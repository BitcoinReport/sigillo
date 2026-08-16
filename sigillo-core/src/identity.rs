//! Identita Sigillo: seed phrase BIP39 -> chiave OpenPGP Ed25519/X25519.
//!
//! Il materiale segreto delle chiavi OpenPGP non e generato a caso e poi
//! salvato: e derivato in modo interamente deterministico dal seed BIP39,
//! cosi che reinserire la stessa seed phrase su un altro dispositivo
//! rigeneri esattamente la stessa identita (stesso fingerprint, stessa
//! chiave), permettendo di leggere i vecchi messaggi cifrati e di restare
//! riconoscibili ai contatti che avevano gia verificato l'impronta.

use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use sequoia_openpgp as openpgp;
use openpgp::packet::key::{Key4, PrimaryRole, SecretParts, SubordinateRole};
use openpgp::packet::prelude::*;
use openpgp::types::{KeyFlags, SignatureType};
use openpgp::Cert;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Numero di parole della seed phrase (lo standard BIP39 supporta 12, 15,
/// 18, 21 o 24; Sigillo espone solo le due lunghezze piu comuni, in linea
/// con l'ecosistema dei wallet Bitcoin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedWordCount {
    Twelve,
    TwentyFour,
}

impl SeedWordCount {
    fn word_count(self) -> usize {
        match self {
            SeedWordCount::Twelve => 12,
            SeedWordCount::TwentyFour => 24,
        }
    }
}

/// Timestamp fisso usato come data di creazione di ogni chiave OpenPGP
/// generata da Sigillo.
///
/// Il fingerprint OpenPGP v4 e calcolato anche sulla data di creazione
/// della chiave. Per garantire che reinserire la stessa seed phrase su un
/// altro dispositivo rigeneri un fingerprint identico, questa data deve
/// essere sempre la stessa, invece di "adesso". Il valore scelto e il
/// timestamp del blocco Genesis di Bitcoin (2009-01-03T18:15:05Z): non ha
/// alcun significato crittografico, e solo una costante condivisa da tutte
/// le identita Sigillo.
const KEY_CTIME_UNIX: u64 = 1_231_006_505;

fn key_ctime() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(KEY_CTIME_UNIX)
}

/// Un'identita Sigillo: la seed phrase BIP39 e il certificato OpenPGP
/// (comprensivo di materiale segreto) da essa derivato.
pub struct Identity {
    pub mnemonic: Mnemonic,
    pub cert: Cert,
}

impl Identity {
    /// Rappresentazione testuale della seed phrase (parole separate da
    /// spazi), da mostrare all'utente durante il wizard di conferma.
    pub fn seed_phrase(&self) -> String {
        self.mnemonic.words().collect::<Vec<_>>().join(" ")
    }

    /// Le singole parole della seed phrase, utile per la schermata di
    /// conferma dove all'utente vengono chieste solo alcune parole a caso.
    pub fn seed_words(&self) -> Vec<&'static str> {
        self.mnemonic.words().collect()
    }
}

/// Deriva 32 byte di materiale segreto dal seed BIP39 (64 byte) tramite
/// HKDF-SHA256, separando i domini con `info` cosi che la chiave di firma
/// e quella di cifratura non abbiano mai lo stesso valore anche se
/// derivano dallo stesso seed.
fn hkdf_derive_32(seed: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut_slice())
        .expect("32 e' una lunghezza di output valida per HKDF-SHA256");
    okm
}

/// Costruisce il certificato OpenPGP a partire dal seed BIP39 a 64 byte, in
/// modo interamente deterministico: stesso seed => stesso fingerprint,
/// sempre, su qualunque dispositivo.
fn build_cert(seed64: &[u8; 64], display_name: &str) -> Result<Cert> {
    let ed25519_seed = hkdf_derive_32(seed64, b"sigillo/openpgp/ed25519-sign/v1");
    let x25519_seed = hkdf_derive_32(seed64, b"sigillo/openpgp/x25519-encrypt/v1");
    let ctime = key_ctime();

    // 1. Chiave primaria Ed25519: certifica l'identita e firma i messaggi.
    let primary: Key<SecretParts, PrimaryRole> =
        Key4::import_secret_ed25519(ed25519_seed.as_slice(), ctime)
            .context("derivazione della chiave primaria Ed25519 fallita")?
            .into();
    let mut primary_signer = primary
        .clone()
        .into_keypair()
        .context("impossibile usare la chiave primaria per firmare")?;

    let direct_key_sig = SignatureBuilder::new(SignatureType::DirectKey)
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
        .sign_direct_key(&mut primary_signer, primary.parts_as_public())?;

    let cert = Cert::try_from(vec![
        Packet::SecretKey(primary.clone()),
        Packet::from(direct_key_sig),
    ])?;

    let mut acc = Vec::new();

    // 2. User ID: solo un nome scelto dall'utente, nessuna email richiesta.
    let uid = UserID::from(display_name);
    let uid_sig = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_primary_userid(true)?
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
        .sign_userid_binding(&mut primary_signer, primary.parts_as_public(), &uid)?;
    acc.push(Packet::from(uid));
    acc.push(Packet::from(uid_sig));

    // 3. Sottochiave di cifratura X25519 (Cv25519 in OpenPGP). Essendo una
    //    sottochiave di sola cifratura non serve una "back signature":
    //    quelle servono solo per sottochiavi che firmano/certificano.
    let subkey: Key<SecretParts, SubordinateRole> =
        Key4::import_secret_cv25519(x25519_seed.as_slice(), None, None, ctime)
            .context("derivazione della sottochiave X25519 fallita")?
            .into();

    let subkey_sig = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_key_flags(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
        )?
        .sign_subkey_binding(&mut primary_signer, primary.parts_as_public(), &subkey)?;
    acc.push(Packet::from(subkey));
    acc.push(Packet::from(subkey_sig));

    let cert = cert.insert_packets(acc)?;

    Ok(cert)
}

fn from_mnemonic(mnemonic: Mnemonic, display_name: &str) -> Result<Identity> {
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let cert = build_cert(&seed, display_name)?;
    Ok(Identity { mnemonic, cert })
}

/// Genera una nuova identita casuale, con seed phrase inglese BIP39.
pub fn generate(word_count: SeedWordCount, display_name: &str) -> Result<Identity> {
    let mnemonic = Mnemonic::generate_in(Language::English, word_count.word_count())
        .context("generazione della seed phrase fallita")?;
    from_mnemonic(mnemonic, display_name)
}

/// Rigenera un'identita esistente a partire dalla sua seed phrase (12 o 24
/// parole, wordlist inglese standard BIP39). Usata sia per importare
/// l'identita su un nuovo dispositivo, sia per verificarla nel wizard di
/// conferma dopo la generazione.
pub fn import(phrase: &str, display_name: &str) -> Result<Identity> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase).context(
        "seed phrase non valida: controlla di aver scritto correttamente tutte le parole, nell'ordine giusto",
    )?;
    from_mnemonic(mnemonic, display_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_12_and_24_words() {
        let id12 = generate(SeedWordCount::Twelve, "Test").unwrap();
        assert_eq!(id12.seed_words().len(), 12);

        let id24 = generate(SeedWordCount::TwentyFour, "Test").unwrap();
        assert_eq!(id24.seed_words().len(), 24);
    }

    #[test]
    fn reimporting_the_same_phrase_yields_the_same_fingerprint() {
        let original = generate(SeedWordCount::TwentyFour, "Alice").unwrap();
        let phrase = original.seed_phrase();

        // Stesso nome visualizzato: deve rigenerare esattamente la stessa identita.
        let reimported = import(&phrase, "Alice").unwrap();
        assert_eq!(original.cert.fingerprint(), reimported.cert.fingerprint());

        // Un nome visualizzato diverso non deve cambiare il fingerprint:
        // il fingerprint copre solo la chiave primaria, non lo User ID.
        let reimported_other_name = import(&phrase, "Alice (altro dispositivo)").unwrap();
        assert_eq!(original.cert.fingerprint(), reimported_other_name.cert.fingerprint());
    }

    #[test]
    fn different_seed_phrases_yield_different_fingerprints() {
        let a = generate(SeedWordCount::TwentyFour, "Alice").unwrap();
        let b = generate(SeedWordCount::TwentyFour, "Bob").unwrap();
        assert_ne!(a.cert.fingerprint(), b.cert.fingerprint());
    }

    #[test]
    fn cert_has_primary_signing_key_and_encryption_subkey() {
        let id = generate(SeedWordCount::TwentyFour, "Test").unwrap();
        // 1 chiave primaria + 1 sottochiave di cifratura = 2 chiavi totali.
        assert_eq!(id.cert.keys().count(), 2);
        assert_eq!(id.cert.userids().count(), 1);
    }

    #[test]
    fn rejects_garbage_seed_phrase() {
        assert!(import("questa non e una seed phrase valida", "Test").is_err());
    }
}
