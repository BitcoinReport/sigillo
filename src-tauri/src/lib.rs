use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use sigillo_core::{contacts, identity, keyinfo, message, storage};

const VAULT_FILE_NAME: &str = "identity.sigillo";
const CONTACTS_FILE_NAME: &str = "contacts.json";
const MIN_PASSPHRASE_LEN: usize = 8;

#[derive(Default)]
struct AppState {
    identity: Mutex<Option<identity::Identity>>,
    display_name: Mutex<Option<String>>,
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("impossibile trovare la cartella dati dell'app: {e}"))?;
    Ok(dir.join(VAULT_FILE_NAME))
}

fn contacts_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("impossibile trovare la cartella dati dell'app: {e}"))?;
    Ok(dir.join(CONTACTS_FILE_NAME))
}

#[derive(Serialize)]
struct IdentityView {
    display_name: String,
    seed_phrase: String,
    seed_words: Vec<String>,
    fingerprint_hex: String,
    fingerprint_words: Vec<String>,
    public_key_armored: String,
}

fn identity_view(id: &identity::Identity, display_name: &str) -> Result<IdentityView, String> {
    let public_key_armored = String::from_utf8(
        sequoia_openpgp::serialize::SerializeInto::to_vec(&id.cert.armored())
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(IdentityView {
        display_name: display_name.to_string(),
        seed_phrase: id.seed_phrase(),
        seed_words: id.seed_words().into_iter().map(str::to_string).collect(),
        fingerprint_hex: id.cert.fingerprint().to_spaced_hex(),
        fingerprint_words: contacts::fingerprint_to_words(&id.cert.fingerprint())
            .into_iter()
            .map(str::to_string)
            .collect(),
        public_key_armored,
    })
}

fn set_current_identity(state: &State<AppState>, id: identity::Identity, display_name: &str) {
    *state.identity.lock().unwrap() = Some(id);
    *state.display_name.lock().unwrap() = Some(display_name.to_string());
}

/// Vero se su questo dispositivo esiste gia un'identita salvata: decide se
/// l'app deve mostrare il wizard di generazione/import (primo avvio) o la
/// schermata di sblocco con la sola passphrase (avvii successivi).
#[tauri::command]
fn identity_exists_on_disk(app: AppHandle) -> Result<bool, String> {
    Ok(storage::vault_exists(&vault_path(&app)?))
}

#[tauri::command]
fn generate_identity(
    state: State<AppState>,
    word_count: u8,
    display_name: String,
) -> Result<IdentityView, String> {
    let words = match word_count {
        12 => identity::SeedWordCount::Twelve,
        24 => identity::SeedWordCount::TwentyFour,
        _ => return Err("il numero di parole deve essere 12 o 24".into()),
    };

    let name = if display_name.trim().is_empty() {
        "Io"
    } else {
        display_name.trim()
    };

    let id = identity::generate(words, name).map_err(|e| e.to_string())?;
    let view = identity_view(&id, name)?;
    set_current_identity(&state, id, name);
    Ok(view)
}

#[tauri::command]
fn import_identity(
    state: State<AppState>,
    phrase: String,
    display_name: String,
) -> Result<IdentityView, String> {
    let name = if display_name.trim().is_empty() {
        "Io"
    } else {
        display_name.trim()
    };

    let id = identity::import(&phrase, name).map_err(|e| e.to_string())?;
    let view = identity_view(&id, name)?;
    set_current_identity(&state, id, name);
    Ok(view)
}

/// Ricontrolla che le parole indicate della seed phrase corrispondano a
/// quelle mostrate, come nel wizard di conferma dei wallet Bitcoin.
#[tauri::command]
fn confirm_seed_words(
    state: State<AppState>,
    positions_and_words: Vec<(u32, String)>,
) -> Result<bool, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard.as_ref().ok_or("nessuna identita generata")?;
    let words = id.seed_words();

    for (position, word) in positions_and_words {
        let expected = words
            .get(position as usize)
            .ok_or("posizione fuori range")?;
        if !expected.eq_ignore_ascii_case(word.trim()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Salva su disco, cifrata con `passphrase`, l'identita attualmente in
/// memoria (generata o importata in questa sessione). Da chiamare come
/// ultimo passo del wizard di primo avvio.
#[tauri::command]
fn save_identity_to_disk(
    app: AppHandle,
    state: State<AppState>,
    passphrase: String,
) -> Result<(), String> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "la passphrase deve avere almeno {MIN_PASSPHRASE_LEN} caratteri"
        ));
    }

    let guard = state.identity.lock().unwrap();
    let id = guard.as_ref().ok_or("nessuna identita da salvare")?;
    let name_guard = state.display_name.lock().unwrap();
    let display_name = name_guard.as_deref().unwrap_or("Io");

    let path = vault_path(&app)?;
    storage::save_identity(&path, &passphrase, display_name, &id.seed_phrase())
        .map_err(|e| e.to_string())
}

/// Sblocca, con la sola passphrase locale (non la seed phrase), l'identita
/// gia salvata su questo dispositivo.
#[tauri::command]
fn unlock_identity(
    app: AppHandle,
    state: State<AppState>,
    passphrase: String,
) -> Result<IdentityView, String> {
    let path = vault_path(&app)?;
    let (display_name, seed_phrase) =
        storage::load_identity(&path, &passphrase).map_err(|e| e.to_string())?;

    let id = identity::import(&seed_phrase, &display_name).map_err(|e| e.to_string())?;
    let view = identity_view(&id, &display_name)?;
    set_current_identity(&state, id, &display_name);
    Ok(view)
}

/// Rimuove in modo sicuro l'identita salvata su questo dispositivo, e con
/// essa la rubrica: dopo questa chiamata il prossimo avvio torna a
/// mostrare il wizard di generazione/import, come al primo avvio, con una
/// rubrica di nuovo vuota.
#[tauri::command]
fn remove_identity_from_disk(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let path = vault_path(&app)?;
    storage::remove_identity(&path).map_err(|e| e.to_string())?;
    // La rubrica potrebbe non esistere ancora (nessun contatto mai
    // aggiunto): non e un errore, e il caso normale.
    let _ = std::fs::remove_file(contacts_path(&app)?);
    *state.identity.lock().unwrap() = None;
    *state.display_name.lock().unwrap() = None;
    Ok(())
}

#[derive(Serialize)]
struct ContactView {
    name: String,
    key: String,
    fingerprint_hex: String,
    fingerprint_words: Vec<String>,
}

fn contact_view(name: String, armored_public_key: String) -> Result<ContactView, String> {
    let cert =
        contacts::import_public_key(armored_public_key.as_bytes()).map_err(|e| e.to_string())?;
    Ok(ContactView {
        name,
        key: armored_public_key,
        fingerprint_hex: cert.fingerprint().to_spaced_hex(),
        fingerprint_words: contacts::fingerprint_to_words(&cert.fingerprint())
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
}

/// Carica la rubrica salvata su questo dispositivo (vuota se non e mai
/// stato aggiunto nessun contatto). Da chiamare quando l'identita viene
/// sbloccata/creata, cosi la rubrica non riparte vuota ad ogni avvio.
#[tauri::command]
fn load_contacts(app: AppHandle) -> Result<Vec<ContactView>, String> {
    let path = contacts_path(&app)?;
    let saved = contacts::load_address_book(&path).map_err(|e| e.to_string())?;
    saved
        .into_iter()
        .map(|c| contact_view(c.name, c.public_key_armored))
        .collect()
}

/// Aggiunge un contatto alla rubrica e lo salva subito su disco (le
/// chiavi pubbliche dei contatti non sono materiale segreto come la
/// chiave privata dell'utente, ma vanno comunque persistite: senza
/// questo la rubrica si svuoterebbe ad ogni riavvio).
#[tauri::command]
fn add_contact(
    app: AppHandle,
    name: String,
    armored_public_key: String,
) -> Result<ContactView, String> {
    // Valida la chiave prima di scrivere qualunque cosa su disco.
    let view = contact_view(name.clone(), armored_public_key.clone())?;

    let path = contacts_path(&app)?;
    let mut book = contacts::load_address_book(&path).map_err(|e| e.to_string())?;
    book.push(contacts::SavedContact {
        name,
        public_key_armored: armored_public_key,
    });
    contacts::save_address_book(&path, &book).map_err(|e| e.to_string())?;

    Ok(view)
}

#[derive(Serialize)]
struct KeyDetailView {
    label: String,
    algorithm: String,
    created_unix: i64,
    expires_unix: Option<i64>,
}

impl From<keyinfo::KeyDetail> for KeyDetailView {
    fn from(d: keyinfo::KeyDetail) -> Self {
        KeyDetailView {
            label: d.label,
            algorithm: d.algorithm,
            created_unix: d.created_unix,
            expires_unix: d.expires_unix,
        }
    }
}

/// Dettagli tecnici (algoritmo, date) della propria identita, per la
/// sezione "avanzate".
#[tauri::command]
fn my_technical_details(state: State<AppState>) -> Result<Vec<KeyDetailView>, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard.as_ref().ok_or("genera o importa prima la tua identita")?;
    keyinfo::technical_details(&id.cert)
        .map(|details| details.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

/// Dettagli tecnici (algoritmo, date) della chiave pubblica di un
/// contatto, per la sezione "avanzate".
#[tauri::command]
fn contact_technical_details(armored_public_key: String) -> Result<Vec<KeyDetailView>, String> {
    let cert =
        contacts::import_public_key(armored_public_key.as_bytes()).map_err(|e| e.to_string())?;
    keyinfo::technical_details(&cert)
        .map(|details| details.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

/// Esporta la chiave privata come file classico cifrato con password
/// (l'alternativa "meno consigliata" alla seed phrase).
#[tauri::command]
fn export_private_key_file(state: State<AppState>, password: String) -> Result<String, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard.as_ref().ok_or("genera o importa prima la tua identita")?;
    identity::export_private_key_file(&id.cert, &password).map_err(|e| e.to_string())
}

#[tauri::command]
fn encrypt_message(
    state: State<AppState>,
    recipients_armored: Vec<String>,
    plaintext: String,
    sign: bool,
) -> Result<String, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard
        .as_ref()
        .ok_or("genera o importa prima la tua identita")?;

    let recipients: Vec<sequoia_openpgp::Cert> = recipients_armored
        .iter()
        .map(|armored| contacts::import_public_key(armored.as_bytes()))
        .collect::<anyhow::Result<_>>()
        .map_err(|e| e.to_string())?;

    message::encrypt(&id.cert, &recipients, &plaintext, sign).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct DecryptView {
    plaintext: String,
    signature_status: String,
    signer_fingerprint: Option<String>,
}

#[tauri::command]
fn decrypt_message(
    state: State<AppState>,
    contacts_armored: Vec<String>,
    ciphertext: String,
) -> Result<DecryptView, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard
        .as_ref()
        .ok_or("genera o importa prima la tua identita")?;

    let contacts_certs: Vec<sequoia_openpgp::Cert> = contacts_armored
        .iter()
        .map(|armored| contacts::import_public_key(armored.as_bytes()))
        .collect::<anyhow::Result<_>>()
        .map_err(|e| e.to_string())?;

    let decrypted =
        message::decrypt(&id.cert, &contacts_certs, &ciphertext).map_err(|e| e.to_string())?;

    let (signature_status, signer_fingerprint) = match decrypted.signature {
        message::SignatureStatus::Unsigned => ("non_firmato".to_string(), None),
        message::SignatureStatus::Verified(fp) => {
            ("verificata".to_string(), Some(fp.to_spaced_hex()))
        }
        message::SignatureStatus::Unverifiable => ("non_verificabile".to_string(), None),
    };

    Ok(DecryptView {
        plaintext: decrypted.plaintext,
        signature_status,
        signer_fingerprint,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            identity_exists_on_disk,
            generate_identity,
            import_identity,
            confirm_seed_words,
            save_identity_to_disk,
            unlock_identity,
            remove_identity_from_disk,
            load_contacts,
            add_contact,
            my_technical_details,
            contact_technical_details,
            export_private_key_file,
            encrypt_message,
            decrypt_message,
        ])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di Sigillo");
}
