use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

use sigillo_core::{contacts, identity, message};

#[derive(Default)]
struct AppState {
    identity: Mutex<Option<identity::Identity>>,
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
    *state.identity.lock().unwrap() = Some(id);
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
    *state.identity.lock().unwrap() = Some(id);
    Ok(view)
}

/// Ricontrolla che le parole indicate della seed phrase corrispondano a
/// quelle mostrate, come nel wizard di conferma dei wallet Bitcoin.
#[tauri::command]
fn confirm_seed_words(state: State<AppState>, positions_and_words: Vec<(u32, String)>) -> Result<bool, String> {
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

#[derive(Serialize)]
struct ContactFingerprint {
    fingerprint_hex: String,
    fingerprint_words: Vec<String>,
}

#[tauri::command]
fn contact_fingerprint_words(armored_public_key: String) -> Result<ContactFingerprint, String> {
    let cert =
        contacts::import_public_key(armored_public_key.as_bytes()).map_err(|e| e.to_string())?;
    Ok(ContactFingerprint {
        fingerprint_hex: cert.fingerprint().to_spaced_hex(),
        fingerprint_words: contacts::fingerprint_to_words(&cert.fingerprint())
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
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
            generate_identity,
            import_identity,
            confirm_seed_words,
            contact_fingerprint_words,
            encrypt_message,
            decrypt_message,
        ])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di Sigillo");
}
