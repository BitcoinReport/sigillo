//! Rubrica: import di chiavi pubbliche di contatti e verifica leggibile
//! del fingerprint (invece dell'esadecimale, una sequenza di parole
//! della wordlist inglese BIP39, da confrontare a voce con il contatto).

use anyhow::{Context, Result};
use bip39::Language;

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::Cert;

/// Importa la chiave pubblica di un contatto da un blocco ASCII-armored
/// (.asc), da testo incollato, o dal contenuto grezzo decodificato di un
/// QR code. Sequoia riconosce automaticamente sia il formato armato che
/// quello binario.
pub fn import_public_key(data: &[u8]) -> Result<Cert> {
    let cert = Cert::from_bytes(data)
        .context("il testo/file non contiene una chiave pubblica OpenPGP valida")?;
    if cert.is_tsk() {
        anyhow::bail!(
            "questo file contiene anche una chiave privata: importa solo la chiave pubblica di un contatto, mai la tua chiave privata o quella di qualcun altro"
        );
    }
    Ok(cert)
}

/// Converte un fingerprint OpenPGP in una sequenza di parole leggibili,
/// da confrontare a voce o di persona con il contatto per verificare che
/// nessuno si stia fingendo qualcun altro.
///
/// Non e un meccanismo crittografico: e solo una rappresentazione piu
/// facile da leggere e confrontare rispetto alla stringa esadecimale del
/// fingerprint. Riusa la wordlist inglese di BIP39, gia inclusa
/// nell'applicazione per le seed phrase.
pub fn fingerprint_to_words(fingerprint: &openpgp::Fingerprint) -> Vec<&'static str> {
    let bytes = fingerprint.as_bytes();
    let wordlist = Language::English.word_list();

    let mut words = Vec::new();
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;

    for &byte in bytes {
        acc = (acc << 8) | byte as u32;
        acc_bits += 8;
        while acc_bits >= 11 {
            acc_bits -= 11;
            let index = ((acc >> acc_bits) & 0x7FF) as usize;
            words.push(wordlist[index]);
        }
    }
    if acc_bits > 0 {
        let index = ((acc << (11 - acc_bits)) & 0x7FF) as usize;
        words.push(wordlist[index]);
    }

    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    #[test]
    fn import_rejects_non_openpgp_data() {
        assert!(import_public_key(b"questo non e affatto una chiave").is_err());
    }

    #[test]
    fn import_rejects_private_key_material() {
        let id = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let armored_tsk =
            openpgp::serialize::SerializeInto::to_vec(&id.cert.as_tsk().armored()).unwrap();
        assert!(import_public_key(&armored_tsk).is_err());
    }

    #[test]
    fn import_accepts_public_key_export() {
        let id = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let armored_pub =
            openpgp::serialize::SerializeInto::to_vec(&id.cert.armored()).unwrap();
        let imported = import_public_key(&armored_pub).unwrap();
        assert_eq!(imported.fingerprint(), id.cert.fingerprint());
    }

    #[test]
    fn fingerprint_words_are_deterministic_and_stable_length() {
        let id = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let words_a = fingerprint_to_words(&id.cert.fingerprint());
        let words_b = fingerprint_to_words(&id.cert.fingerprint());
        assert_eq!(words_a, words_b);
        // Fingerprint v4 = 20 byte = 160 bit => 15 parole da 11 bit (con padding finale).
        assert_eq!(words_a.len(), 15);
    }
}
