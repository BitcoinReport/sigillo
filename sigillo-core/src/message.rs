//! Cifratura e decifratura dei messaggi.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, GoodChecksum, MessageLayer, MessageStructure,
    VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message, Signer};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Cert, Fingerprint, KeyHandle};

/// Cifra `plaintext` per uno o piu destinatari, con firma opzionale del
/// mittente. Restituisce il messaggio in formato ASCII armored (.asc),
/// testo puro leggibile e riconoscibile su qualsiasi client OpenPGP.
pub fn encrypt(
    sender: &Cert,
    recipients: &[Cert],
    plaintext: &str,
    sign: bool,
) -> Result<String> {
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

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;
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
                .context("la tua identita non ha una chiave di firma valida")?
                .key()
                .clone()
                .into_keypair()
                .context("impossibile usare la tua chiave per firmare")?;
            Signer::new(message, signing_keypair).build()?
        } else {
            message
        };

        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(plaintext.as_bytes())?;
        message.finalize()?;
    }

    String::from_utf8(sink).context("errore interno: output cifrato non valido")
}

/// Esito della verifica della firma di un messaggio decifrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Il messaggio non era firmato.
    Unsigned,
    /// Firma valida, del titolare del fingerprint indicato.
    Verified(Fingerprint),
    /// Il messaggio conteneva una firma, ma non e stato possibile
    /// verificarla (chiave del mittente sconosciuta, o firma non valida).
    Unverifiable,
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub signature: SignatureStatus,
}

struct Helper<'a> {
    identity: &'a Cert,
    contacts: &'a [Cert],
    found_matching_key: Rc<RefCell<bool>>,
    signature: SignatureStatus,
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

/// Decifra un messaggio ASCII-armored, verificando anche l'eventuale
/// firma del mittente. `contacts` e l'elenco delle chiavi pubbliche note
/// (la rubrica), usato per verificare le firme.
pub fn decrypt(identity: &Cert, contacts: &[Cert], armored: &str) -> Result<DecryptedMessage> {
    let p = &StandardPolicy::new();
    let found_matching_key = Rc::new(RefCell::new(false));

    let helper = Helper {
        identity,
        contacts,
        found_matching_key: found_matching_key.clone(),
        signature: SignatureStatus::Unsigned,
    };

    let mut decryptor = DecryptorBuilder::from_bytes(armored.as_bytes())
        .context("il testo incollato non e un messaggio OpenPGP valido, o e danneggiato")?
        .with_policy(p, None, helper)
        .map_err(|_| {
            if *found_matching_key.borrow() {
                anyhow::anyhow!(
                    "impossibile decifrare il messaggio: la chiave corrisponde ma il contenuto sembra danneggiato"
                )
            } else {
                anyhow::anyhow!(
                    "questo messaggio non e indirizzato a te: nessuna delle tue chiavi corrisponde"
                )
            }
        })?;

    let mut plaintext = String::new();
    std::io::Read::read_to_string(&mut decryptor, &mut plaintext)
        .context("il contenuto decifrato non e testo leggibile")?;

    let signature = decryptor.into_helper().signature;

    Ok(DecryptedMessage {
        plaintext,
        signature,
    })
}
