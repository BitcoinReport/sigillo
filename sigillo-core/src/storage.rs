//! Salvataggio cifrato a riposo delle identità sul dispositivo.
//!
//! Il file salvato su disco non contiene mai una seed phrase o una chiave
//! privata in chiaro: è sempre cifrato con una chiave derivata dalla
//! passphrase locale scelta dall'utente, tramite Argon2id (resistente ad
//! attacchi a forza bruta) + AES-256-GCM (cifratura autenticata: un file
//! manomesso o una passphrase sbagliata vengono rilevati, non decifrati
//! per errore).
//!
//! Questa passphrase locale è diversa dalla seed phrase (o dalla eventuale
//! passphrase originale di una chiave importata): sblocca solo le identità
//! già salvate su *questo* dispositivo.
//!
//! Dalla versione con supporto multi-account, il vault può contenere più
//! identità contemporaneamente, sbloccate tutte con un'unica passphrase di
//! dispositivo (per non costringere l'utente a ricordarne una diversa per
//! ciascuna), ma cifrate ciascuna separatamente: ogni voce ha il proprio
//! nonce e la propria autenticazione AEAD, così un problema su una voce
//! non intacca le altre. Il formato precedente (una sola identità) resta
//! leggibile: viene riconosciuto dal suo marcatore e caricato come un
//! vault con un'unica voce.

use std::fs;
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC_V1: &[u8; 4] = b"SGL1";
const MAGIC_V2: &[u8; 4] = b"SGL2";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// Argon2id. Questi parametri proteggono l'unico segreto a riposo sul
// dispositivo (la seed phrase / chiave privata nel vault): teniamo la
// memoria a 64 MiB, ben oltre il minimo OWASP di ~19 MiB, perché il
// costo in più allo sblocco è di pochi centesimi di secondo mentre
// quello di un attacco a forza bruta offline su un file rubato sale
// in modo sensibile.
//
// I parametri vengono scritti dentro il file del vault e riletti da lì
// allo sblocco (vedi save_vault / load_vault_v*): un vault salvato con
// valori precedenti continua quindi a sbloccarsi con quei valori, e
// passa a questi nuovi solo alla prima riscrittura (es. aggiunta o
// rimozione di un'identità).
const ARGON2_M_COST: u32 = 65_536;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Da dove viene il materiale segreto di un'identità nel vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrySource {
    /// Identità generata o reimportata da Sigillo tramite seed phrase BIP39.
    Seed(String),
    /// Identità importata da una chiave OpenPGP generata altrove (GPG
    /// Suite, Kleopatra, terminale...): il testo è la chiave privata
    /// completa in formato ASCII armored, con il materiale segreto già
    /// in chiaro (l'eventuale passphrase originale della chiave serve
    /// solo al momento dell'import, non per le letture successive).
    ImportedTsk(String),
}

/// Una identità così come persiste nel vault: un nome scelto
/// dall'utente per riconoscerla nell'interfaccia, più il materiale da
/// cui ricostruirla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    pub alias: String,
    pub source: EntrySource,
}

/// Vero se su questo dispositivo esiste già un vault (uno o più
/// identità) in `path`.
pub fn vault_exists(path: &Path) -> bool {
    path.is_file()
}

fn derive_key(passphrase: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("parametri Argon2 non validi: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("derivazione della chiave fallita: {e}"))?;
    Ok(key)
}

// ---------- Codifica di una singola voce (prima della cifratura) ----------

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    Ok(read_bytes(data, pos, 1)?[0])
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read_bytes(data, pos, 2)?.try_into().unwrap()))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_bytes(data, pos, 4)?.try_into().unwrap()))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(len).context("file dell'identità corrotto")?;
    let slice = data.get(*pos..end).context("file dell'identità corrotto")?;
    *pos = end;
    Ok(slice)
}

fn encode_entry(entry: &VaultEntry) -> Vec<u8> {
    let alias_bytes = entry.alias.as_bytes();
    let (kind, secret): (u8, &str) = match &entry.source {
        EntrySource::Seed(phrase) => (0, phrase.as_str()),
        EntrySource::ImportedTsk(armored) => (1, armored.as_str()),
    };
    let secret_bytes = secret.as_bytes();

    let mut out = Vec::with_capacity(2 + alias_bytes.len() + 1 + 4 + secret_bytes.len());
    out.extend_from_slice(&(alias_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(alias_bytes);
    out.push(kind);
    out.extend_from_slice(&(secret_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(secret_bytes);
    out
}

fn decode_entry(data: &[u8]) -> Result<VaultEntry> {
    let mut pos = 0;
    let alias_len = read_u16(data, &mut pos)? as usize;
    let alias = String::from_utf8(read_bytes(data, &mut pos, alias_len)?.to_vec())
        .context("file dell'identità corrotto (alias non valido)")?;
    let kind = read_u8(data, &mut pos)?;
    let secret_len = read_u32(data, &mut pos)? as usize;
    let secret = String::from_utf8(read_bytes(data, &mut pos, secret_len)?.to_vec())
        .context("file dell'identità corrotto (materiale non valido)")?;

    let source = match kind {
        0 => EntrySource::Seed(secret),
        1 => EntrySource::ImportedTsk(secret),
        _ => bail!("file dell'identità corrotto (tipo di identità sconosciuto)"),
    };
    Ok(VaultEntry { alias, source })
}

// ---------- Formato V2 (multi-identità) ----------

/// Cifra e salva tutte le `entries` in `path`, protette dalla
/// `passphrase` locale scelta dall'utente. Sovrascrive un eventuale
/// vault precedente (in qualunque formato fosse). Ogni voce viene
/// cifrata separatamente (nonce e autenticazione propri), pur
/// derivando tutte dalla stessa passphrase.
pub fn save_vault(path: &Path, passphrase: &str, entries: &[VaultEntry]) -> Result<()> {
    if passphrase.is_empty() {
        bail!("la passphrase non può essere vuota");
    }
    if entries.is_empty() {
        bail!("il vault deve contenere almeno un'identità");
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("impossibile creare la cartella dati dell'app")?;
    }

    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_V2);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());

    for entry in entries {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = encode_entry(entry);
        let ciphertext = cipher
            .encrypt(nonce, payload.as_slice())
            .map_err(|_| anyhow::anyhow!("cifratura di un'identità fallita"))?;

        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&ciphertext);
    }

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

fn load_vault_v2(data: &[u8], passphrase: &str) -> Result<Vec<VaultEntry>> {
    let mut pos = 4; // magic gia' controllato dal chiamante

    let salt_len = read_u8(data, &mut pos)? as usize;
    let salt = read_bytes(data, &mut pos, salt_len)?;
    let m_cost = read_u32(data, &mut pos)?;
    let t_cost = read_u32(data, &mut pos)?;
    let p_cost = read_u32(data, &mut pos)?;
    let entry_count = read_u16(data, &mut pos)? as usize;

    let key = derive_key(passphrase, salt, m_cost, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let nonce_bytes = read_bytes(data, &mut pos, NONCE_LEN)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext_len = read_u32(data, &mut pos)? as usize;
        let ciphertext = read_bytes(data, &mut pos, ciphertext_len)?;

        let payload = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("passphrase errata"))?;
        entries.push(decode_entry(&payload)?);
    }

    Ok(entries)
}

// ---------- Formato V1 (retrocompatibilità: una sola identità) ----------

fn decode_payload_v1(payload: &[u8]) -> Result<(String, String)> {
    let mut pos = 0;
    let name_len = read_u16(payload, &mut pos)? as usize;
    let display_name = String::from_utf8(read_bytes(payload, &mut pos, name_len)?.to_vec())
        .context("file dell'identità corrotto (nome non valido)")?;
    let phrase_len = read_u16(payload, &mut pos)? as usize;
    let seed_phrase = String::from_utf8(read_bytes(payload, &mut pos, phrase_len)?.to_vec())
        .context("file dell'identità corrotto (seed phrase non valida)")?;
    Ok((display_name, seed_phrase))
}

fn load_vault_v1(data: &[u8], passphrase: &str) -> Result<Vec<VaultEntry>> {
    let mut pos = 4; // magic gia' controllato dal chiamante

    let salt_len = read_u8(data, &mut pos)? as usize;
    let salt = read_bytes(data, &mut pos, salt_len)?;
    let m_cost = read_u32(data, &mut pos)?;
    let t_cost = read_u32(data, &mut pos)?;
    let p_cost = read_u32(data, &mut pos)?;
    let nonce_bytes = read_bytes(data, &mut pos, NONCE_LEN)?;
    let ciphertext = &data[pos..];

    let key = derive_key(passphrase, salt, m_cost, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("passphrase errata"))?;
    let (display_name, seed_phrase) = decode_payload_v1(&payload)?;

    Ok(vec![VaultEntry {
        alias: display_name,
        source: EntrySource::Seed(seed_phrase),
    }])
}

/// Decifra tutte le identità salvate in `path` con la `passphrase`
/// fornita, riconoscendo automaticamente sia il formato attuale
/// (multi-identità) sia quello precedente (una sola identità, ancora
/// perfettamente leggibile). Il risultato ha sempre almeno una voce.
pub fn load_vault(path: &Path, passphrase: &str) -> Result<Vec<VaultEntry>> {
    let data = fs::read(path).context("nessuna identità salvata su questo dispositivo")?;
    if data.len() < 4 {
        bail!("il file dell'identità non è valido o è di una versione non supportata");
    }
    let magic: &[u8; 4] = data[0..4].try_into().unwrap();
    match magic {
        m if m == MAGIC_V1 => load_vault_v1(&data, passphrase),
        m if m == MAGIC_V2 => load_vault_v2(&data, passphrase),
        _ => bail!("il file dell'identità non è valido o è di una versione non supportata"),
    }
}

/// Cancella in modo sicuro il vault salvato su questo dispositivo (tutte
/// le identità che contiene): sovrascrive il file con zeri prima di
/// rimuoverlo, così anche un recupero grezzo dal disco non ritroverebbe
/// il materiale segreto cifrato. Dopo questa chiamata `vault_exists`
/// torna a restituire `false`.
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

    fn seed_entry(alias: &str, phrase: &str) -> VaultEntry {
        VaultEntry {
            alias: alias.to_string(),
            source: EntrySource::Seed(phrase.to_string()),
        }
    }

    #[test]
    fn save_then_load_round_trip_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        save_vault(&path, "passphrase-di-prova", &[seed_entry("Alice", "parola1 parola2 parola3")]).unwrap();
        assert!(vault_exists(&path));

        let entries = load_vault(&path, "passphrase-di-prova").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "Alice");
        assert_eq!(entries[0].source, EntrySource::Seed("parola1 parola2 parola3".to_string()));
    }

    #[test]
    fn save_then_load_round_trip_multiple_entries_mixed_sources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        let entries = vec![
            seed_entry("Alice personale", "una due tre"),
            VaultEntry {
                alias: "Alice lavoro (importata)".to_string(),
                source: EntrySource::ImportedTsk(
                    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake\n-----END PGP PRIVATE KEY BLOCK-----"
                        .to_string(),
                ),
            },
        ];
        save_vault(&path, "passphrase-dispositivo", &entries).unwrap();

        let loaded = load_vault(&path, "passphrase-dispositivo").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], entries[0]);
        assert_eq!(loaded[1], entries[1]);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        save_vault(&path, "passphrase-corretta", &[seed_entry("Alice", "seed phrase segreta")]).unwrap();
        let err = load_vault(&path, "passphrase-sbagliata").unwrap_err();
        assert!(err.to_string().contains("passphrase errata"));
    }

    #[test]
    fn plaintext_seed_phrase_never_touches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");
        let seed_phrase = "abbandonare abbaglio abbastanza zibetto zoccolo zoppo";

        save_vault(&path, "una passphrase robusta", &[seed_entry("Bob", seed_phrase)]).unwrap();

        let raw = fs::read(&path).unwrap();
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

        save_vault(&path, "passphrase", &[seed_entry("Alice", "seed phrase")]).unwrap();
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

        let err = load_vault(&path, "qualunque").unwrap_err();
        assert!(err.to_string().contains("non è valido"));
    }

    #[test]
    fn a_vault_saved_before_multi_account_support_is_still_readable() {
        // Ricostruisce a mano un vault nel formato V1 (una sola identità,
        // come lo scriveva l'app prima del supporto multi-account) e
        // verifica che load_vault lo riconosca e lo legga correttamente,
        // senza che l'utente perda l'accesso alla propria identità dopo
        // un aggiornamento dell'app.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");

        let passphrase = "passphrase-prima-del-multi-account";
        let display_name = "Alice";
        let seed_phrase = "parola1 parola2 parola3";

        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let key = derive_key(passphrase, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut payload = Vec::new();
        let name_bytes = display_name.as_bytes();
        let phrase_bytes = seed_phrase.as_bytes();
        payload.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(name_bytes);
        payload.extend_from_slice(&(phrase_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(phrase_bytes);
        let ciphertext = cipher.encrypt(nonce, payload.as_slice()).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_V1);
        out.push(SALT_LEN as u8);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
        out.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
        out.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        fs::write(&path, &out).unwrap();

        let entries = load_vault(&path, passphrase).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "Alice");
        assert_eq!(entries[0].source, EntrySource::Seed("parola1 parola2 parola3".to_string()));
    }

    #[test]
    fn a_vault_saved_with_older_argon2_parameters_still_unlocks() {
        // I parametri Argon2 sono salvati nel file e riletti da lì: se in
        // una versione futura alziamo ARGON2_M_COST, un vault scritto con
        // il valore precedente deve continuare a sbloccarsi (nessuno
        // resta fuori dalla propria identità dopo un aggiornamento).
        // Qui ricostruiamo a mano un vault V2 con m_cost = 19_456 (il
        // valore storico) e verifichiamo che load_vault lo apra.
        const OLD_M_COST: u32 = 19_456;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.sigillo");
        let passphrase = "passphrase-di-un-vault-vecchio";

        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt, OLD_M_COST, ARGON2_T_COST, ARGON2_P_COST).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

        let entry = VaultEntry {
            alias: "Bea".to_string(),
            source: EntrySource::Seed("una due tre quattro".to_string()),
        };

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), encode_entry(&entry).as_slice())
            .unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_V2);
        out.push(SALT_LEN as u8);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&OLD_M_COST.to_le_bytes());
        out.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
        out.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // una voce
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&ciphertext);
        fs::write(&path, &out).unwrap();

        let entries = load_vault(&path, passphrase).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "Bea");
        assert_eq!(
            entries[0].source,
            EntrySource::Seed("una due tre quattro".to_string())
        );
    }
}
