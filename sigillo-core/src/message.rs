//! Cifratura e decifratura dei messaggi: testo e file binari (immagini).

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::packet::{Packet, PKESK, SKESK};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, GoodChecksum, MessageLayer, MessageStructure,
    VerificationHelper,
};
use openpgp::parse::{PacketParser, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message, Signer};
use openpgp::types::{DataFormat, SymmetricAlgorithm};
use openpgp::{Cert, Fingerprint, KeyHandle};

/// Cifra byte grezzi (testo o binario, ad es. un'immagine) per uno o più
/// destinatari, con firma opzionale del mittente.
///
/// `filename`, se presente, viene incorporato nel messaggio OpenPGP stesso
/// (campo standard del pacchetto "dati letterali"): chi decifra lo
/// ritrova come nome suggerito per il file, e il contenuto viene marcato
/// come binario invece che testo. `armor` sceglie tra output ASCII
/// armored (`.asc`, testo puro, ~33% più pesante) e binario compatto
/// (`.gpg`).
pub fn encrypt_bytes(
    sender: &Cert,
    recipients: &[Cert],
    data: &[u8],
    filename: Option<&str>,
    sign: bool,
    armor: bool,
) -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    encrypt_to_writer(sender, recipients, filename, sign, armor, &mut sink, |w| {
        w.write_all(data)?;
        Ok(())
    })?;
    Ok(sink)
}

/// Come [`encrypt_bytes`], ma "a flusso": il contenuto non viene
/// passato tutto insieme ma scritto da `write_body` direttamente nel
/// messaggio OpenPGP mentre si cifra, e il risultato va a `out` (tipicamente
/// un file) invece di accumularsi in memoria. È ciò che permette di
/// cifrare un allegato da centinaia di MB senza tenerne in RAM più di
/// qualche kilobyte alla volta.
pub fn encrypt_to_writer<W: Write + Send + Sync>(
    sender: &Cert,
    recipients: &[Cert],
    filename: Option<&str>,
    sign: bool,
    armor: bool,
    out: W,
    write_body: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let p = &StandardPolicy::new();

    let mut recipient_keys = Vec::new();
    for cert in recipients {
        let mut has_encryption_key = false;
        for ka in cert
            .keys()
            .with_policy(p, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            recipient_keys.push(openpgp::serialize::stream::Recipient::from(ka));
            has_encryption_key = true;
        }
        if !has_encryption_key {
            anyhow::bail!(
                "il contatto non ha una chiave di cifratura valida (fingerprint {})",
                cert.fingerprint()
            );
        }
    }
    if recipient_keys.is_empty() {
        anyhow::bail!("nessun destinatario selezionato");
    }

    let message = Message::new(out);
    let message: Message = if armor {
        Armorer::new(message).build()?
    } else {
        message
    };
    let message = Encryptor2::for_recipients(message, recipient_keys).build()?;

    let message = if sign {
        let signing_keypair = sender
            .keys()
            .secret()
            .with_policy(p, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .context("la tua identità non ha una chiave di firma valida")?
            .key()
            .clone()
            .into_keypair()
            .context("impossibile usare la tua chiave per firmare")?;
        Signer::new(message, signing_keypair).build()?
    } else {
        message
    };

    let mut literal = LiteralWriter::new(message);
    literal = if let Some(name) = filename {
        literal.filename(name).context("nome file non valido")?.format(DataFormat::Binary)
    } else {
        literal.format(DataFormat::Unicode)
    };
    let mut message = literal.build()?;
    write_body(&mut message)?;
    message.finalize()?;

    Ok(())
}

/// Cifra `plaintext` per uno o più destinatari, con firma opzionale del
/// mittente. Restituisce sempre il messaggio in formato ASCII armored
/// (.asc): per il testo non è prevista alcuna scelta di formato, a
/// differenza delle immagini (vedi [`encrypt_bytes`]).
pub fn encrypt(sender: &Cert, recipients: &[Cert], plaintext: &str, sign: bool) -> Result<String> {
    let bytes = encrypt_bytes(sender, recipients, plaintext.as_bytes(), None, sign, true)?;
    String::from_utf8(bytes).context("errore interno: output cifrato non valido")
}

/// Esito della verifica della firma di un messaggio decifrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Il messaggio non era firmato.
    Unsigned,
    /// Firma valida, del titolare del fingerprint indicato.
    Verified(Fingerprint),
    /// Il messaggio conteneva una firma, ma non è stato possibile
    /// verificarla (chiave del mittente sconosciuta, o firma non valida).
    Unverifiable,
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub signature: SignatureStatus,
}

/// Come [`DecryptedMessage`], ma per contenuto binario (es. un'immagine):
/// niente conversione a testo, e il nome file originale se il mittente lo
/// aveva incluso (impostato automaticamente da [`encrypt_bytes`]).
#[derive(Debug, Clone)]
pub struct DecryptedBytes {
    pub data: Vec<u8>,
    pub filename: Option<String>,
    pub signature: SignatureStatus,
}

struct Helper<'a> {
    identity: &'a Cert,
    contacts: &'a [Cert],
    found_matching_key: Rc<RefCell<bool>>,
    signature: SignatureStatus,
    /// Condiviso con chi decifra "a flusso", che puo' leggere il nome
    /// file non appena il pacchetto dei dati letterali e' stato visto.
    filename: Rc<RefCell<Option<String>>>,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(self
            .contacts
            .iter()
            .cloned()
            .chain(std::iter::once(self.identity.clone()))
            .collect())
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    match result {
                        Ok(GoodChecksum { ka, .. }) => {
                            self.signature = SignatureStatus::Verified(ka.key().fingerprint());
                        }
                        Err(_) => {
                            if self.signature == SignatureStatus::Unsigned {
                                self.signature = SignatureStatus::Unverifiable;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn inspect(&mut self, pp: &PacketParser) -> Result<()> {
        if let Packet::Literal(lit) = &pp.packet {
            if let Some(name) = lit.filename() {
                *self.filename.borrow_mut() = Some(String::from_utf8_lossy(name).into_owned());
            }
        }
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let p = &StandardPolicy::new();
        let secret_keys: Vec<_> = self
            .identity
            .keys()
            .secret()
            .with_policy(p, None)
            .supported()
            .alive()
            .revoked(false)
            .for_storage_encryption()
            .chain(
                self.identity
                    .keys()
                    .secret()
                    .with_policy(p, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .for_transport_encryption(),
            )
            .collect();

        for pkesk in pkesks {
            for ka in &secret_keys {
                if pkesk.recipient().aliases(ka.key().key_handle()) {
                    *self.found_matching_key.borrow_mut() = true;
                    let mut keypair = ka.key().clone().into_keypair()?;
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                        if decrypt(algo, &session_key) {
                            return Ok(Some(self.identity.fingerprint()));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

fn decrypt_raw(
    identity: &Cert,
    contacts: &[Cert],
    input: &[u8],
) -> Result<(Vec<u8>, Option<String>, SignatureStatus)> {
    let p = &StandardPolicy::new();
    let found_matching_key = Rc::new(RefCell::new(false));

    let helper = Helper {
        identity,
        contacts,
        found_matching_key: found_matching_key.clone(),
        signature: SignatureStatus::Unsigned,
        filename: Rc::new(RefCell::new(None)),
    };

    let mut decryptor = DecryptorBuilder::from_bytes(input)
        .context("il contenuto non è un messaggio OpenPGP valido, o è danneggiato")?
        .with_policy(p, None, helper)
        .map_err(|_| {
            if *found_matching_key.borrow() {
                anyhow::anyhow!(
                    "impossibile decifrare il messaggio: la chiave corrisponde ma il contenuto sembra danneggiato"
                )
            } else {
                anyhow::anyhow!(
                    "questo messaggio non è indirizzato a te: nessuna delle tue chiavi corrisponde"
                )
            }
        })?;

    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut decryptor, &mut data)
        .context("errore durante la lettura del contenuto decifrato")?;

    let helper = decryptor.into_helper();
    let filename = helper.filename.borrow().clone();
    Ok((data, filename, helper.signature))
}

/// Esito di una decifratura "a flusso" (vedi [`decrypt_streaming`]).
pub struct StreamOutcome<T> {
    /// Quello che ha restituito la funzione che ha consumato il flusso.
    pub value: T,
    /// Nome file incorporato nel messaggio, se c'era.
    pub filename: Option<String>,
    pub signature: SignatureStatus,
}

/// Decifra `input` "a flusso": invece di restituire tutto il contenuto in
/// memoria, passa a `consume` un lettore dei byte decifrati, che puo'
/// copiarli direttamente su file. `consume` riceve anche una funzione
/// per leggere il nome file incorporato (disponibile dopo la lettura dei
/// primi byte).
///
/// Quando `consume` ha finito, il resto del flusso viene letto comunque
/// fino in fondo: e' solo alla fine che il messaggio risulta autenticato
/// (controllo di integrita' e firma), quindi un contenuto manomesso o
/// troncato produce un errore e non viene mai dato per buono. Chi chiama
/// deve perciò considerare il risultato valido solo se questa funzione
/// restituisce `Ok`, e scartare qualunque file scritto in `consume`
/// altrimenti.
pub fn decrypt_streaming<R, T, F>(
    identity: &Cert,
    contacts: &[Cert],
    input: R,
    consume: F,
) -> Result<StreamOutcome<T>>
where
    R: std::io::Read + Send + Sync,
    F: FnOnce(&mut dyn std::io::Read, &dyn Fn() -> Option<String>) -> Result<T>,
{
    let p = &StandardPolicy::new();
    let found_matching_key = Rc::new(RefCell::new(false));
    let filename = Rc::new(RefCell::new(None));

    let helper = Helper {
        identity,
        contacts,
        found_matching_key: found_matching_key.clone(),
        signature: SignatureStatus::Unsigned,
        filename: filename.clone(),
    };

    let mut decryptor = DecryptorBuilder::from_reader(input)
        .context("il contenuto non è un messaggio OpenPGP valido, o è danneggiato")?
        .with_policy(p, None, helper)
        .map_err(|_| {
            if *found_matching_key.borrow() {
                anyhow::anyhow!(
                    "impossibile decifrare il messaggio: la chiave corrisponde ma il contenuto sembra danneggiato"
                )
            } else {
                anyhow::anyhow!(
                    "questo messaggio non è indirizzato a te: nessuna delle tue chiavi corrisponde"
                )
            }
        })?;

    let name_reader = {
        let filename = filename.clone();
        move || filename.borrow().clone()
    };
    let value = consume(&mut decryptor, &name_reader)?;

    // Fino in fondo: e' qui che emergono manomissioni e troncamenti.
    std::io::copy(&mut decryptor, &mut std::io::sink())
        .context("errore durante la lettura del contenuto decifrato: il file sembra danneggiato o incompleto")?;

    let helper = decryptor.into_helper();
    let final_name = filename.borrow().clone();
    Ok(StreamOutcome {
        value,
        filename: final_name,
        signature: helper.signature,
    })
}

/// Decifra un contenuto binario (es. un'immagine cifrata), verificando
/// anche l'eventuale firma del mittente. Accetta sia input ASCII
/// armored (.asc) sia binario (.gpg): Sequoia riconosce automaticamente
/// il formato.
pub fn decrypt_bytes(identity: &Cert, contacts: &[Cert], input: &[u8]) -> Result<DecryptedBytes> {
    let (data, filename, signature) = decrypt_raw(identity, contacts, input)?;
    Ok(DecryptedBytes {
        data,
        filename,
        signature,
    })
}

/// Decifra un messaggio di testo ASCII-armored, verificando anche
/// l'eventuale firma del mittente. `contacts` è l'elenco delle chiavi
/// pubbliche note (la rubrica), usato per verificare le firme.
pub fn decrypt(identity: &Cert, contacts: &[Cert], armored: &str) -> Result<DecryptedMessage> {
    let (data, _filename, signature) = decrypt_raw(identity, contacts, armored.as_bytes())?;
    let plaintext =
        String::from_utf8(data).context("il contenuto decifrato non è testo leggibile")?;
    Ok(DecryptedMessage {
        plaintext,
        signature,
    })
}
