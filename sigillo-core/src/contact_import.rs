//! Importare un contatto in rubrica senza incollare a mano la chiave:
//! da fingerprint (la chiave si scarica da un keyserver), da file
//! (.asc, .gpg, .key...) o da testo incollato.
//!
//! Questo modulo non fa rete e non salva nulla: contiene le regole che
//! rendono sicura l'operazione, indipendentemente da come la chiave
//! arriva.
//!
//! - [`normalize_fingerprint`]: accetta il fingerprint in qualunque forma
//!   di scrittura e rifiuta gli identificativi corti (8 o 16 caratteri),
//!   che si possono falsificare.
//! - [`parse_keys`]: legge una o più chiavi da testo o binario e, se in
//!   mezzo c'e' una chiave PRIVATA, la scarta subito senza tenerla.
//! - [`fingerprint_matches`]: dopo un download, il fingerprint della
//!   chiave ricevuta deve essere quello richiesto. Il server non e' mai
//!   una fonte di verita' sull'identita'.
//! - [`summarize`]: nome, email, date e stato (valida, scaduta, revocata)
//!   da mostrare nella schermata di conferma.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::SerializeInto;
use openpgp::types::RevocationStatus;
use openpgp::Cert;

/// Un fingerprint OpenPGP v4 sono 20 byte: 40 caratteri esadecimali.
pub const FINGERPRINT_HEX_LEN: usize = 40;

/// Un file di chiavi pubbliche e' piccolo (qualche KB, al massimo
/// qualche centinaio con molte firme di terzi): oltre questa soglia non
/// e' una chiave, e non vale la pena leggerlo.
pub const MAX_KEY_FILE_BYTES: usize = 5 * 1024 * 1024;

// ---------- Fingerprint ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    Empty,
    /// Meno di 40 caratteri: tipicamente un Key ID da 8 o 16.
    TooShort(usize),
    TooLong(usize),
    NotHex,
}

impl FingerprintError {
    /// Messaggio per l'utente, in italiano semplice.
    pub fn user_message(&self) -> String {
        match self {
            FingerprintError::Empty => "Scrivi o incolla il fingerprint della persona.".to_string(),
            FingerprintError::TooShort(_) => {
                "Serve il fingerprint completo (40 caratteri). Quelli più corti non sono sicuri."
                    .to_string()
            }
            FingerprintError::TooLong(_) => {
                "Il fingerprint è troppo lungo: ne servono esattamente 40 caratteri.".to_string()
            }
            FingerprintError::NotHex => {
                "Il fingerprint può contenere solo cifre da 0 a 9 e lettere da A a F.".to_string()
            }
        }
    }
}

/// Porta un fingerprint scritto in un modo qualsiasi alla forma
/// canonica: 40 caratteri esadecimali maiuscoli, senza spazi.
///
/// Accetta maiuscole/minuscole, spazi (anche a blocchi da 4, anche con
/// doppio spazio a meta'), due punti, e il prefisso `0x`.
pub fn normalize_fingerprint(input: &str) -> std::result::Result<String, FingerprintError> {
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    let cleaned: String = without_prefix
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();

    if cleaned.is_empty() {
        return Err(FingerprintError::Empty);
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(FingerprintError::NotHex);
    }
    match cleaned.len().cmp(&FINGERPRINT_HEX_LEN) {
        std::cmp::Ordering::Less => Err(FingerprintError::TooShort(cleaned.len())),
        std::cmp::Ordering::Greater => Err(FingerprintError::TooLong(cleaned.len())),
        std::cmp::Ordering::Equal => Ok(cleaned.to_ascii_uppercase()),
    }
}

/// Vero se `cert` ha esattamente il fingerprint `expected_plain` (nella
/// forma restituita da [`normalize_fingerprint`]).
pub fn fingerprint_matches(cert: &Cert, expected_plain: &str) -> bool {
    cert.fingerprint().to_hex().eq_ignore_ascii_case(expected_plain)
}

// ---------- Lettura di chiavi da testo o file ----------

#[derive(Debug)]
pub struct ParsedKeys {
    /// Le chiavi PUBBLICHE trovate (vuoto se si e' trovata una privata).
    pub public: Vec<Cert>,
    /// Il contenuto includeva almeno una chiave privata: non si importa
    /// niente e il chiamante deve avvisare l'utente.
    pub found_private: bool,
}

const PUBLIC_BLOCK_MARKER: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PRIVATE_BLOCK_MARKER: &[u8] = b"PRIVATE KEY BLOCK-----";

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Interpreta `data` (armored o binario, anche con piu' chiavi) come
/// chiavi pubbliche di contatti.
///
/// Se il contenuto include una chiave PRIVATA (blocco `PRIVATE KEY
/// BLOCK` o materiale segreto in un file binario), la funzione la
/// scarta subito e lo segnala: una chiave privata non deve mai finire
/// in rubrica, ne' restare in memoria piu' del necessario.
pub fn parse_keys(data: &[u8]) -> Result<ParsedKeys> {
    if data.len() > MAX_KEY_FILE_BYTES {
        bail!("il file è troppo grande per essere una chiave");
    }
    if data.is_empty() {
        bail!("il contenuto è vuoto");
    }

    // Blocco armored privato: non serve nemmeno interpretarlo.
    if !find_all(data, PRIVATE_BLOCK_MARKER).is_empty() {
        return Ok(ParsedKeys {
            public: Vec::new(),
            found_private: true,
        });
    }

    // Piu' blocchi armored uno dopo l'altro: ciascuno si legge da solo.
    let starts = find_all(data, PUBLIC_BLOCK_MARKER);
    let chunks: Vec<&[u8]> = if starts.len() > 1 {
        starts
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                let end = starts.get(i + 1).copied().unwrap_or(data.len());
                &data[s..end]
            })
            .collect()
    } else {
        vec![data]
    };

    let mut public: Vec<Cert> = Vec::new();
    let mut found_private = false;
    for chunk in chunks {
        let parser = match CertParser::from_bytes(chunk) {
            Ok(p) => p,
            Err(_) => continue,
        };
        for item in parser {
            let Ok(cert) = item else { continue };
            if cert.is_tsk() {
                found_private = true;
                continue;
            }
            if !public.iter().any(|c| c.fingerprint() == cert.fingerprint()) {
                public.push(cert);
            }
        }
    }

    if found_private {
        return Ok(ParsedKeys {
            public: Vec::new(),
            found_private: true,
        });
    }
    if public.is_empty() {
        bail!("il testo/file non contiene una chiave pubblica OpenPGP valida");
    }
    Ok(ParsedKeys {
        public,
        found_private: false,
    })
}

/// Come [`parse_keys`], poi cancella `data` dalla memoria: per il
/// contenuto di un file letto da disco, che potrebbe essere una chiave
/// privata scelta per errore.
pub fn parse_keys_and_wipe(mut data: Vec<u8>) -> Result<ParsedKeys> {
    let result = parse_keys(&data);
    data.zeroize();
    result
}

// ---------- Riepilogo di una chiave ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Utilizzabile per cifrare messaggi.
    Valid,
    /// La chiave e' scaduta.
    Expired,
    /// Chi l'ha creata l'ha revocata: non e' piu' sicura.
    Revoked,
    /// Valida ma senza una sottochiave di cifratura utilizzabile: non
    /// si possono cifrare messaggi per questo contatto.
    NoEncryptionKey,
}

#[derive(Debug, Clone)]
pub struct CertSummary {
    /// 40 caratteri esadecimali maiuscoli.
    pub fingerprint_plain: String,
    /// Blocchi da 4 per leggerlo e confrontarlo.
    pub fingerprint_spaced: String,
    pub words: Vec<&'static str>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub created_unix: i64,
    pub expires_unix: Option<i64>,
    pub status: KeyStatus,
}

fn unix(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Raggruppa a blocchi di 4 caratteri: `AA28 F0C4 8857 ...`.
fn blocks_of_four(plain: &str) -> String {
    plain
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Descrive `cert` per la schermata di conferma, valutandola all'istante
/// `now`.
pub fn summarize(cert: &Cert, now: SystemTime) -> CertSummary {
    let p = &StandardPolicy::new();
    let fingerprint_plain = cert.fingerprint().to_hex();
    let words = crate::contacts::fingerprint_to_words(&cert.fingerprint());
    let mut summary = CertSummary {
        fingerprint_spaced: blocks_of_four(&fingerprint_plain),
        fingerprint_plain,
        words,
        name: None,
        email: None,
        created_unix: unix(cert.primary_key().key().creation_time()),
        expires_unix: None,
        status: KeyStatus::NoEncryptionKey,
    };

    let Ok(valid) = cert.with_policy(p, now) else {
        // Nessuna firma di auto-certificazione valida in questo momento.
        return summary;
    };

    summary.expires_unix = valid.primary_key().key_expiration_time().map(unix);

    // Nome ed email dall'identita' principale. Su keys.openpgp.org le
    // identita' compaiono solo se verificate dal proprietario: puo'
    // quindi mancare, e l'utente lo scrive a mano.
    if let Ok(uid) = valid.primary_userid() {
        let userid = uid.userid();
        summary.name = userid
            .name2()
            .ok()
            .flatten()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string);
        summary.email = userid
            .email2()
            .ok()
            .flatten()
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string);
        if summary.name.is_none() && summary.email.is_none() {
            let raw = String::from_utf8_lossy(userid.value()).trim().to_string();
            if !raw.is_empty() {
                summary.name = Some(raw);
            }
        }
    }

    summary.status = if matches!(valid.revocation_status(), RevocationStatus::Revoked(_)) {
        KeyStatus::Revoked
    } else if valid.alive().is_err() {
        KeyStatus::Expired
    } else if valid
        .keys()
        .alive()
        .revoked(false)
        .supported()
        .for_transport_encryption()
        .next()
        .is_none()
    {
        KeyStatus::NoEncryptionKey
    } else {
        KeyStatus::Valid
    };
    summary
}

/// La chiave pubblica di `cert` in formato armored, senza materiale
/// segreto: e' cio' che si salva in rubrica.
pub fn public_armored(cert: &Cert) -> Result<String> {
    let bytes = cert
        .clone()
        .strip_secret_key_material()
        .armored()
        .to_vec()
        .context("impossibile preparare la chiave pubblica")?;
    String::from_utf8(bytes).context("errore interno: chiave non valida")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use std::time::Duration;

    fn make_cert(userid: &str) -> Cert {
        CertBuilder::new()
            .add_userid(userid)
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0
    }

    fn armored(cert: &Cert) -> Vec<u8> {
        cert.armored().to_vec().unwrap()
    }

    // ---------- normalizzazione del fingerprint ----------

    const FPR: &str = "AA28F0C488574E2C540FE63D2CCDD28EC64FA94C";

    #[test]
    fn every_way_of_writing_a_fingerprint_gives_the_same_result() {
        let spellings = [
            "AA28F0C488574E2C540FE63D2CCDD28EC64FA94C",
            "aa28f0c488574e2c540fe63d2ccdd28ec64fa94c",
            "Aa28F0c488574E2c540Fe63D2cCdD28eC64fA94c",
            "AA28 F0C4 8857 4E2C 540F E63D 2CCD D28E C64F A94C",
            "AA28 F0C4 8857 4E2C 540F  E63D 2CCD D28E C64F A94C",
            "aa28 f0c4 8857 4e2c 540f e63d 2ccd d28e c64f a94c",
            "0xAA28F0C488574E2C540FE63D2CCDD28EC64FA94C",
            "0Xaa28f0c488574e2c540fe63d2ccdd28ec64fa94c",
            "0x AA28 F0C4 8857 4E2C 540F E63D 2CCD D28E C64F A94C",
            "  AA28F0C488574E2C540FE63D2CCDD28EC64FA94C\n",
            "AA:28:F0:C4:88:57:4E:2C:54:0F:E6:3D:2C:CD:D2:8E:C6:4F:A9:4C",
        ];
        for s in spellings {
            assert_eq!(normalize_fingerprint(s).as_deref(), Ok(FPR), "{s:?}");
        }
    }

    #[test]
    fn short_key_ids_are_refused_with_a_clear_message() {
        for short in ["C64FA94C", "0xC64FA94C", "2CCDD28EC64FA94C", "2CCD D28E C64F A94C"] {
            let err = normalize_fingerprint(short).unwrap_err();
            assert!(matches!(err, FingerprintError::TooShort(8 | 16)), "{short}: {err:?}");
            assert_eq!(
                err.user_message(),
                "Serve il fingerprint completo (40 caratteri). Quelli più corti non sono sicuri."
            );
        }
        // Qualunque altra lunghezza sotto i 40 e' comunque troppo corta.
        assert!(matches!(
            normalize_fingerprint("AA28F0C4").unwrap_err(),
            FingerprintError::TooShort(8)
        ));
        assert!(matches!(
            normalize_fingerprint(&FPR[..39]).unwrap_err(),
            FingerprintError::TooShort(39)
        ));
    }

    #[test]
    fn malformed_fingerprints_are_refused() {
        assert_eq!(normalize_fingerprint(""), Err(FingerprintError::Empty));
        assert_eq!(normalize_fingerprint("   0x  "), Err(FingerprintError::Empty));
        assert_eq!(
            normalize_fingerprint("ZZ28F0C488574E2C540FE63D2CCDD28EC64FA94C"),
            Err(FingerprintError::NotHex)
        );
        assert_eq!(
            normalize_fingerprint("AA28F0C488574E2C540FE63D2CCDD28EC64FA94C00"),
            Err(FingerprintError::TooLong(42))
        );
        // Non si fa passare un nome o un'email per un fingerprint.
        assert!(normalize_fingerprint("mike@esempio.it").is_err());
        assert!(normalize_fingerprint("AA28F0C488574E2C540FE63D2CCDD28EC64FA94C; DROP").is_err());
    }

    // ---------- lettura di chiavi ----------

    #[test]
    fn a_single_armored_public_key_is_read() {
        let cert = make_cert("Giulia <giulia@esempio.it>");
        let parsed = parse_keys(&armored(&cert)).unwrap();
        assert!(!parsed.found_private);
        assert_eq!(parsed.public.len(), 1);
        assert_eq!(parsed.public[0].fingerprint(), cert.fingerprint());
    }

    #[test]
    fn a_binary_public_key_is_read() {
        // Formato .gpg / .pgp: pacchetti OpenPGP grezzi.
        let cert = make_cert("Giulia <giulia@esempio.it>");
        let parsed = parse_keys(&cert.to_vec().unwrap()).unwrap();
        assert_eq!(parsed.public.len(), 1);
        assert_eq!(parsed.public[0].fingerprint(), cert.fingerprint());
    }

    #[test]
    fn several_keys_are_all_found_in_any_container() {
        let a = make_cert("Anna <anna@esempio.it>");
        let b = make_cert("Bruno <bruno@esempio.it>");
        let c = make_cert("Carla <carla@esempio.it>");

        // Due blocchi armored uno dopo l'altro (come un "cat a.asc b.asc").
        let mut two_blocks = armored(&a);
        two_blocks.extend_from_slice(&armored(&b));
        let parsed = parse_keys(&two_blocks).unwrap();
        assert_eq!(parsed.public.len(), 2);

        // Tre chiavi binarie concatenate (un portachiavi .gpg).
        let mut ring = a.to_vec().unwrap();
        ring.extend_from_slice(&b.to_vec().unwrap());
        ring.extend_from_slice(&c.to_vec().unwrap());
        let parsed = parse_keys(&ring).unwrap();
        let fps: Vec<_> = parsed.public.iter().map(|k| k.fingerprint()).collect();
        assert_eq!(fps, vec![a.fingerprint(), b.fingerprint(), c.fingerprint()]);

        // Testo con del contorno prima, dopo e in mezzo.
        let mut with_text = b"Ecco le chiavi di Anna e Bruno:\n\n".to_vec();
        with_text.extend_from_slice(&armored(&a));
        with_text.extend_from_slice(b"\nE questa e' di Bruno:\n");
        with_text.extend_from_slice(&armored(&b));
        with_text.extend_from_slice(b"\nCiao!\n");
        assert_eq!(parse_keys(&with_text).unwrap().public.len(), 2);
    }

    #[test]
    fn the_same_key_twice_is_listed_once() {
        let a = make_cert("Anna <anna@esempio.it>");
        let mut twice = armored(&a);
        twice.extend_from_slice(&armored(&a));
        assert_eq!(parse_keys(&twice).unwrap().public.len(), 1);
    }

    #[test]
    fn a_private_key_is_never_imported_armored_or_binary() {
        let secret = CertBuilder::new()
            .add_userid("Segreta <s@esempio.it>")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0;

        let armored_tsk = secret.as_tsk().armored().to_vec().unwrap();
        let parsed = parse_keys(&armored_tsk).unwrap();
        assert!(parsed.found_private);
        assert!(parsed.public.is_empty());

        let binary_tsk = secret.as_tsk().to_vec().unwrap();
        let parsed = parse_keys(&binary_tsk).unwrap();
        assert!(parsed.found_private);
        assert!(parsed.public.is_empty());
    }

    #[test]
    fn a_file_mixing_public_and_private_keys_imports_nothing() {
        let public = make_cert("Pubblica <p@esempio.it>");
        let secret = make_cert("Segreta <s@esempio.it>");
        let mut mixed = armored(&public);
        mixed.extend_from_slice(&secret.as_tsk().armored().to_vec().unwrap());
        let parsed = parse_keys(&mixed).unwrap();
        assert!(parsed.found_private);
        assert!(parsed.public.is_empty(), "nessuna chiave va importata se c'e' una privata");

        let mut mixed_binary = public.to_vec().unwrap();
        mixed_binary.extend_from_slice(&secret.as_tsk().to_vec().unwrap());
        let parsed = parse_keys(&mixed_binary).unwrap();
        assert!(parsed.found_private && parsed.public.is_empty());
    }

    #[test]
    fn things_that_are_not_keys_are_refused_cleanly() {
        assert!(parse_keys(b"").is_err());
        assert!(parse_keys(b"ciao, non sono una chiave").is_err());
        assert!(parse_keys(&[0u8; 200]).is_err());
        assert!(parse_keys(&vec![b'a'; MAX_KEY_FILE_BYTES + 1]).is_err());
        // Un messaggio cifrato non e' una chiave.
        let alice = make_cert("Alice <a@esempio.it>");
        let msg = crate::message::encrypt(&alice, &[alice.clone()], "ciao", false).unwrap();
        assert!(parse_keys(msg.as_bytes()).is_err());
        // Un blocco armored troncato / rovinato.
        let mut broken = armored(&alice);
        broken.truncate(broken.len() / 2);
        let _ = parse_keys(&broken); // errore o niente: l'importante e' non andare in panico
    }

    #[test]
    fn wiping_variant_gives_the_same_answer() {
        let cert = make_cert("Giulia <giulia@esempio.it>");
        let parsed = parse_keys_and_wipe(armored(&cert)).unwrap();
        assert_eq!(parsed.public.len(), 1);
    }

    // ---------- riepilogo e stato ----------

    #[test]
    fn a_normal_key_is_valid_with_name_email_and_dates() {
        let cert = make_cert("Giulia Rossi <giulia@esempio.it>");
        let s = summarize(&cert, SystemTime::now());
        assert_eq!(s.status, KeyStatus::Valid);
        assert_eq!(s.name.as_deref(), Some("Giulia Rossi"));
        assert_eq!(s.email.as_deref(), Some("giulia@esempio.it"));
        assert_eq!(s.fingerprint_plain, cert.fingerprint().to_hex());
        assert_eq!(s.fingerprint_plain.len(), 40);
        assert_eq!(s.fingerprint_spaced.split(' ').count(), 10);
        assert!(s.fingerprint_spaced.split(' ').all(|b| b.len() == 4));
        assert_eq!(s.words.len(), 15);
        assert!(s.created_unix > 0);
        assert_eq!(s.expires_unix, None);
    }

    #[test]
    fn a_name_only_or_email_only_identity_is_handled() {
        let name_only = summarize(&make_cert("Io"), SystemTime::now());
        assert_eq!(name_only.name.as_deref(), Some("Io"));
        assert_eq!(name_only.email, None);

        let email_only = summarize(&make_cert("<solo@esempio.it>"), SystemTime::now());
        assert_eq!(email_only.email.as_deref(), Some("solo@esempio.it"));
    }

    #[test]
    fn a_key_without_identities_has_no_name_to_suggest() {
        let (cert, _) = CertBuilder::new().add_transport_encryption_subkey().generate().unwrap();
        let s = summarize(&cert, SystemTime::now());
        assert_eq!(s.name, None);
        assert_eq!(s.email, None);
    }

    #[test]
    fn an_expired_key_is_reported_as_expired() {
        let now = SystemTime::now();
        let (cert, _) = CertBuilder::new()
            .set_creation_time(now - Duration::from_secs(10 * 86_400))
            .set_validity_period(Duration::from_secs(86_400))
            .add_userid("Scaduta <scaduta@esempio.it>")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        let s = summarize(&cert, now);
        assert_eq!(s.status, KeyStatus::Expired);
        assert!(s.expires_unix.is_some());
        assert!(s.expires_unix.unwrap() < unix(now));

        // Creata 10 giorni fa e valida per 1 giorno: a 9 giorni e mezzo fa era ancora valida.
        let before = now - Duration::from_secs(9 * 86_400 + 43_200);
        assert_eq!(summarize(&cert, before).status, KeyStatus::Valid);
    }

    #[test]
    fn a_future_expiry_is_reported_but_the_key_is_valid() {
        let now = SystemTime::now();
        let (cert, _) = CertBuilder::new()
            .set_validity_period(Duration::from_secs(365 * 86_400))
            .add_userid("Presto <presto@esempio.it>")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        let s = summarize(&cert, now);
        assert_eq!(s.status, KeyStatus::Valid);
        assert!(s.expires_unix.unwrap() > unix(now));
    }

    #[test]
    fn a_revoked_key_is_reported_as_revoked() {
        let (cert, revocation) = CertBuilder::new()
            .add_userid("Revocata <revocata@esempio.it>")
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        let cert = cert.insert_packets(revocation).unwrap();
        // Va riconosciuta anche dopo un giro di serializzazione, come
        // quando arriva da un file o da un keyserver.
        let reparsed = parse_keys(&armored(&cert)).unwrap().public.remove(0);
        for c in [&cert, &reparsed] {
            assert_eq!(summarize(c, SystemTime::now()).status, KeyStatus::Revoked);
        }
    }

    #[test]
    fn a_key_that_cannot_encrypt_is_flagged() {
        let (cert, _) = CertBuilder::new().add_userid("Solo firma <f@esempio.it>").generate().unwrap();
        assert_eq!(summarize(&cert, SystemTime::now()).status, KeyStatus::NoEncryptionKey);
    }

    #[test]
    fn sigillo_identities_are_valid_contacts() {
        let id = crate::identity::generate(crate::identity::SeedWordCount::Twelve, "Alice").unwrap();
        let public = id.cert.clone().strip_secret_key_material();
        let s = summarize(&public, SystemTime::now());
        assert_eq!(s.status, KeyStatus::Valid);
        assert_eq!(s.name.as_deref(), Some("Alice"));
    }

    // ---------- fingerprint e armored pubblico ----------

    #[test]
    fn a_different_key_never_matches_the_requested_fingerprint() {
        let wanted = make_cert("Voluta <v@esempio.it>");
        let imposter = make_cert("Impostore <i@esempio.it>");
        let wanted_fpr = wanted.fingerprint().to_hex();
        assert!(fingerprint_matches(&wanted, &wanted_fpr));
        assert!(fingerprint_matches(&wanted, &wanted_fpr.to_lowercase()));
        assert!(!fingerprint_matches(&imposter, &wanted_fpr));
    }

    #[test]
    fn the_saved_form_is_public_only_and_keeps_the_fingerprint() {
        let secret = make_cert("Segreta <s@esempio.it>");
        let saved = public_armored(&secret).unwrap();
        assert!(saved.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(!saved.contains("PRIVATE"));
        let back = crate::contacts::import_public_key(saved.as_bytes()).unwrap();
        assert_eq!(back.fingerprint(), secret.fingerprint());
        assert!(!back.is_tsk());
    }

    // ---------- la chiave reale pubblicata sul sito ----------

    #[test]
    fn the_key_published_on_the_website_imports_correctly() {
        // Fixture: copia di mike-sigillo-contact.asc, il file che il sito
        // offre per "scrivermi messaggi cifrati" (solo chiave pubblica).
        let data = include_bytes!("../tests/fixtures/mike-sigillo-contact.asc");
        let parsed = parse_keys(data).unwrap();
        assert!(!parsed.found_private);
        assert_eq!(parsed.public.len(), 1);

        let cert = &parsed.public[0];
        assert!(fingerprint_matches(cert, "AA28F0C488574E2C540FE63D2CCDD28EC64FA94C"));
        let typed = normalize_fingerprint("AA28 F0C4 8857 4E2C 540F  E63D 2CCD D28E C64F A94C").unwrap();
        assert!(fingerprint_matches(cert, &typed));

        let s = summarize(cert, SystemTime::now());
        assert_eq!(s.status, KeyStatus::Valid, "{s:?}");
        assert_eq!(s.words.len(), 15);
    }
}
