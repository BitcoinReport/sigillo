//! Rubrica: import di chiavi pubbliche di contatti e verifica leggibile
//! del fingerprint (invece dell'esadecimale, una sequenza di parole
//! della wordlist inglese BIP39, da confrontare a voce con il contatto).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bip39::Language;
use serde::{Deserialize, Serialize};

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
/// Non è un meccanismo crittografico: è solo una rappresentazione più
/// facile da leggere e confrontare rispetto alla stringa esadecimale del
/// fingerprint. Riusa la wordlist inglese di BIP39, già inclusa
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

/// Un contatto salvato in rubrica, così come persiste su disco.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedContact {
    pub name: String,
    pub public_key_armored: String,
}

/// Carica la rubrica salvata su disco. Se non è mai stato salvato nulla
/// (nessun file ancora), restituisce una rubrica vuota invece di un
/// errore: è lo stato normale al primo avvio.
pub fn load_address_book(path: &Path) -> Result<Vec<SavedContact>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path).context("impossibile leggere la rubrica salvata")?;
    serde_json::from_str(&data).context("il file della rubrica è danneggiato")
}

/// Salva l'intera rubrica su disco, sovrascrivendo il file precedente.
///
/// A differenza della chiave privata dell'utente (`storage.rs`), le
/// chiavi pubbliche dei contatti non sono materiale segreto: non serve
/// cifrarle, ma vanno comunque scritte in modo da sopravvivere ai
/// riavvii dell'app.
pub fn save_address_book(path: &Path, contacts: &[SavedContact]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("impossibile creare la cartella dati dell'app")?;
    }
    let data = serde_json::to_string_pretty(contacts)
        .context("errore interno nella serializzazione della rubrica")?;

    // File temporaneo + rename atomico, come per il vault dell'identità:
    // un crash a meta scrittura non deve lasciare una rubrica troncata.
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, data).context("impossibile scrivere la rubrica")?;
    fs::rename(&tmp_path, path).context("impossibile salvare la rubrica")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    #[test]
    fn import_rejects_non_openpgp_data() {
        assert!(import_public_key(b"questo non e' affatto una chiave").is_err());
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

    #[test]
    fn address_book_is_empty_when_no_file_exists_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        let book = load_address_book(&path).unwrap();
        assert!(book.is_empty());
    }

    #[test]
    fn address_book_save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");

        let contacts = vec![SavedContact {
            name: "Giulia".to_string(),
            public_key_armored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----".to_string(),
        }];
        save_address_book(&path, &contacts).unwrap();

        let loaded = load_address_book(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Giulia");
        assert_eq!(loaded[0].public_key_armored, contacts[0].public_key_armored);
    }

    #[test]
    fn address_book_accumulates_contacts_across_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");

        let mut book = load_address_book(&path).unwrap();
        book.push(SavedContact {
            name: "Giulia".to_string(),
            public_key_armored: "chiave-di-giulia".to_string(),
        });
        save_address_book(&path, &book).unwrap();

        let mut book = load_address_book(&path).unwrap();
        book.push(SavedContact {
            name: "Marco".to_string(),
            public_key_armored: "chiave-di-marco".to_string(),
        });
        save_address_book(&path, &book).unwrap();

        let final_book = load_address_book(&path).unwrap();
        assert_eq!(final_book.len(), 2);
        assert_eq!(final_book[0].name, "Giulia");
        assert_eq!(final_book[1].name, "Marco");
    }

    #[test]
    fn corrupted_address_book_file_is_reported_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        fs::write(&path, b"non sono json valido").unwrap();
        assert!(load_address_book(&path).is_err());
    }
}
