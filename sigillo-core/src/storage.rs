//! Salvataggio cifrato a riposo dell'identità sul dispositivo.
//!
//! Il file salvato su disco non contiene mai la seed phrase (o la chiave
//! privata) in chiaro: è sempre cifrato con una chiave derivata dalla
//! passphrase locale scelta dall'utente, tramite Argon2id (resistente ad
//! attacchi a forza bruta) + AES-256-GCM (cifratura autenticata: un file
//! manomesso o una passphrase sbagliata vengono rilevati, non decifrati
//! per errore).
//!
//! Questa passphrase locale è diversa dalla seed phrase: sblocca solo
//! l'identità già salvata su *questo* dispositivo, non permette di
//! rigenerarla altrove (per quello serve la seed phrase).

use std::fs;
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SGL1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// Argon2id, parametri in linea con le raccomandazioni OWASP per uso
// interattivo (circa 19 MiB di memoria, giusto per rendere costoso un
// attacco a forza bruta senza rendere fastidiosa l'attesa di sblocco).
const ARGON2_M_COST: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Vero se esiste già un'identità salvata su questo dispositivo in `path`.
pub fn vault_exists(path: &Path) -> bool {
    path.is_file()
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow::anyhow!("parametri Argon2 non validi: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("derivazione della chiave fallita: {e}"))?;
    Ok(key)
}

fn encode_payload(display_name: &str, seed_phrase: &str) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::new());
    let name_bytes = display_name.as_bytes();
    let phrase_bytes = seed_phrase.as_bytes();

    payload.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(name_bytes);
    payload.extend_from_slice(&(phrase_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(phrase_bytes);
    payload
}

fn decode_payload(payload: &[u8]) -> Result<(String, String)> {
    if payload.len() < 2 {
        bail!("file dell'identità corrotto");
    }
    let name_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    let name_start = 2;
    let name_end = name_start + name_len;
    if payload.len() < name_end + 2 {
        bail!("file dell'identità corrotto");
    }
    let display_name = String::from_utf8(payload[name_start..name_end].to_vec())
        .context("file dell'identità corrotto (nome non valido)")?;

    let phrase_len_start = name_end;
    let phrase_len =
        u16::from_le_bytes([payload[phrase_len_start], payload[phrase_len_start + 1]]) as usize;
    let phrase_start = phrase_len_start + 2;
    let phrase_end = phrase_start + phrase_len;
    if payload.len() != phrase_end {
        bail!("file dell'identità corrotto");
    }
    let seed_phrase = String::from_utf8(payload[phrase_start..phrase_end].to_vec())
        .context("file dell'identità corrotto (seed phrase non valida)")?;

    Ok((display_name, seed_phrase))
}

/// Cifra e salva l'identità (nome visualizzato + seed phrase) in `path`,
/// protetta dalla `passphrase` locale scelta dall'utente. Sovrascrive un
/// eventuale file precedente.
pub fn save_identity(
    path: &Path,
    passphrase: &str,
    display_name: &str,
    seed_phrase: &str,
) -> Result<()> {
    if passphrase.is_empty() {
        bail!("la passphrase non può essere vuota");
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("impossibile creare la cartella dati dell'app")?;
    }

    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = encode_payload(display_name, seed_phrase);
    let ciphertext = cipher
        .encrypt(nonce, payload.as_slice())
        .map_err(|_| anyhow::anyhow!("cifratura dell'identità fallita"))?;

    let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + 12 + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    // File temporaneo + rename atomico, così un crash a meta scrittura non
    // lascia un vault troncato/corrotto al posto di quello precedente.
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp_path).context("impossibile scrivere il file dell'identità")?;
        f.write_all(&out)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path).context("impossibile salvare il file dell'identità")?;

    Ok(())
}

/// Decifra l'identità salvata in `path` con la `passphrase` fornita.
/// Restituisce `(nome_visualizzato, seed_phrase)`.
pub fn load_identity(path: &Path, passphrase: &str) -> Result<(String, String)> {
    let data = fs::read(path).context("nessuna identità salvata su questo dispositivo")?;

    if data.len() < 4 || &data[0..4] != MAGIC {
        bail!("il file dell'identità non è valido o è di una versione non supportata");
    }
    let mut offset = 4;

    let salt_len = *data.get(offset).context("file dell'identità corrotto")? as usize;
    offset += 1;
    if data.len() < offset + salt_len + 12 + NONCE_LEN {
        bail!("file dell'identità corrotto");
    }
    let salt = &data[offset..offset + salt_len];
    offset += salt_len;

    let m_cost = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let t_cost = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let p_cost = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let nonce_bytes = &data[offset..offset + NONCE_LEN];
    offset += NONCE_LEN;

    let ciphertext = &data[offset..];

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("parametri Argon2 non validi nel file: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("derivazione della chiave fallita: {e}"))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("passphrase errata"))?;

    decode_payload(&payload)
}

/// Cancella in modo sicuro l'identità salvata su questo dispositivo:
/// sovrascrive il file con zeri prima di rimuoverlo, così anche un
/// recupero grezzo dal disco non ritroverebbe la seed phrase cifrata.
/// Dopo questa chiamata `vault_exists` torna a restituire `false`.
pub fn remove_identity(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; metadata.len() as usize];
            let _ = f.write_all(&zeros);
            let _ = f.sync_all();
        }
    }

    fs::remove_file(path).context("impossibile rimuovere il file dell'identità")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        save_identity(&path, "passphrase-di-prova", "Alice", "parola1 parola2 parola3").unwrap();
        assert!(vault_exists(&path));

        let (name, phrase) = load_identity(&path, "passphrase-di-prova").unwrap();
        assert_eq!(name, "Alice");
        assert_eq!(phrase, "parola1 parola2 parola3");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        save_identity(&path, "passphrase-corretta", "Alice", "seed phrase segreta").unwrap();
        let err = load_identity(&path, "passphrase-sbagliata").unwrap_err();
        assert!(err.to_string().contains("passphrase errata"));
    }

    #[test]
    fn plaintext_seed_phrase_never_touches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");
        let seed_phrase = "abbandonare abbaglio abbastanza zibetto zoccolo zoppo";

        save_identity(&path, "una passphrase robusta", "Bob", seed_phrase).unwrap();

        let raw = fs::read(&path).unwrap();
        // Nessuna delle parole della seed phrase deve comparire in chiaro
        // da nessuna parte nel file salvato su disco.
        for word in seed_phrase.split_whitespace() {
            assert!(
                !raw.windows(word.len()).any(|w| w == word.as_bytes()),
                "la parola '{word}' è presente in chiaro nel file salvato"
            );
        }
    }

    #[test]
    fn remove_identity_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        save_identity(&path, "passphrase", "Alice", "seed phrase").unwrap();
        assert!(vault_exists(&path));

        remove_identity(&path).unwrap();
        assert!(!vault_exists(&path));
    }

    #[test]
    fn vault_exists_is_false_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");
        assert!(!vault_exists(&path));
    }

    #[test]
    fn corrupted_file_is_reported_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");
        fs::write(&path, b"non sono un vault Sigillo").unwrap();

        let err = load_identity(&path, "qualunque").unwrap_err();
        assert!(err.to_string().contains("non è valido"));
    }
}
