use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use sigillo_core::{contacts, identity, keyinfo, message, settings, storage};

const VAULT_FILE_NAME: &str = "identity.sigillo";
const CONTACTS_FILE_NAME: &str = "contacts.json";
const SETTINGS_FILE_NAME: &str = "settings.json";
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

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("impossibile trovare la cartella dati dell'app: {e}"))?;
    Ok(dir.join(SETTINGS_FILE_NAME))
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

/// Vero se su questo dispositivo esiste già un'identità salvata: decide se
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
    let id = guard.as_ref().ok_or("nessuna identità generata")?;
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

/// Salva su disco, cifrata con `passphrase`, l'identità attualmente in
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
    let id = guard.as_ref().ok_or("nessuna identità da salvare")?;
    let name_guard = state.display_name.lock().unwrap();
    let display_name = name_guard.as_deref().unwrap_or("Io");

    let path = vault_path(&app)?;
    storage::save_identity(&path, &passphrase, display_name, &id.seed_phrase())
        .map_err(|e| e.to_string())
}

/// Sblocca, con la sola passphrase locale (non la seed phrase), l'identità
/// già salvata su questo dispositivo.
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

/// Rimuove in modo sicuro l'identità salvata su questo dispositivo, e con
/// essa la rubrica: dopo questa chiamata il prossimo avvio torna a
/// mostrare il wizard di generazione/import, come al primo avvio, con una
/// rubrica di nuovo vuota.
#[tauri::command]
fn remove_identity_from_disk(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let path = vault_path(&app)?;
    storage::remove_identity(&path).map_err(|e| e.to_string())?;
    // La rubrica potrebbe non esistere ancora (nessun contatto mai
    // aggiunto): non è un errore, è il caso normale.
    let _ = std::fs::remove_file(contacts_path(&app)?);
    *state.identity.lock().unwrap() = None;
    *state.display_name.lock().unwrap() = None;
    Ok(())
}

fn image_format_to_str(format: settings::ImageFormat) -> &'static str {
    match format {
        settings::ImageFormat::Asc => "asc",
        settings::ImageFormat::Gpg => "gpg",
    }
}

/// Formato di cifratura scelto per le immagini ("asc" o "gpg"). Il testo
/// non ha questa scelta: è sempre ASCII armored.
#[tauri::command]
fn get_image_format(app: AppHandle) -> Result<String, String> {
    let format =
        settings::load_image_format(&settings_path(&app)?).map_err(|e| e.to_string())?;
    Ok(image_format_to_str(format).to_string())
}

#[tauri::command]
fn set_image_format(app: AppHandle, format: String) -> Result<(), String> {
    let format = match format.as_str() {
        "asc" => settings::ImageFormat::Asc,
        "gpg" => settings::ImageFormat::Gpg,
        _ => return Err("formato non valido: deve essere \"asc\" o \"gpg\"".to_string()),
    };
    settings::save_image_format(&settings_path(&app)?, format).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct ContactView {
    name: String,
    key: String,
    fingerprint_hex: String,
    fingerprint_words: Vec<String>,
    photo_base64: Option<String>,
    photo_mime: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    notes: Option<String>,
}

fn contact_view(saved: &contacts::SavedContact) -> Result<ContactView, String> {
    let cert = contacts::import_public_key(saved.public_key_armored.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(ContactView {
        name: saved.name.clone(),
        key: saved.public_key_armored.clone(),
        fingerprint_hex: cert.fingerprint().to_spaced_hex(),
        fingerprint_words: contacts::fingerprint_to_words(&cert.fingerprint())
            .into_iter()
            .map(str::to_string)
            .collect(),
        photo_base64: saved.photo_base64.clone(),
        photo_mime: saved.photo_mime.clone(),
        email: saved.email.clone(),
        phone: saved.phone.clone(),
        notes: saved.notes.clone(),
    })
}

/// Trasforma una stringa facoltativa arrivata dal modulo in `None` se
/// vuota (o solo spazi): il frontend invia sempre una stringa per i
/// campi facoltativi non compilati, invece di ometterli.
fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// Carica la rubrica salvata su questo dispositivo (vuota se non è mai
/// stato aggiunto nessun contatto). Da chiamare quando l'identità viene
/// sbloccata/creata, così la rubrica non riparte vuota ad ogni avvio.
#[tauri::command]
fn load_contacts(app: AppHandle) -> Result<Vec<ContactView>, String> {
    let path = contacts_path(&app)?;
    let saved = contacts::load_address_book(&path).map_err(|e| e.to_string())?;
    saved.iter().map(contact_view).collect()
}

/// Aggiunge un contatto alla rubrica e lo salva subito su disco (le
/// chiavi pubbliche dei contatti non sono materiale segreto come la
/// chiave privata dell'utente, ma vanno comunque persistite: senza
/// questo la rubrica si svuoterebbe ad ogni riavvio). Foto, email,
/// telefono e note si aggiungono in un secondo momento dalla scheda
/// dettaglio del contatto (vedi `update_contact`).
#[tauri::command]
fn add_contact(
    app: AppHandle,
    name: String,
    armored_public_key: String,
) -> Result<ContactView, String> {
    // Valida la chiave prima di scrivere qualunque cosa su disco.
    contacts::import_public_key(armored_public_key.as_bytes()).map_err(|e| e.to_string())?;

    let path = contacts_path(&app)?;
    let mut book = contacts::load_address_book(&path).map_err(|e| e.to_string())?;
    let entry = contacts::SavedContact {
        name,
        public_key_armored: armored_public_key,
        ..Default::default()
    };
    book.push(entry.clone());
    contacts::save_address_book(&path, &book).map_err(|e| e.to_string())?;

    contact_view(&entry)
}

/// Aggiorna nome, foto e dettagli facoltativi (email, telefono, note)
/// di un contatto già in rubrica, individuato dalla sua chiave pubblica
/// (unica e immutabile, a differenza del nome che qui si può cambiare).
#[tauri::command]
fn update_contact(
    app: AppHandle,
    public_key_armored: String,
    name: String,
    email: Option<String>,
    phone: Option<String>,
    notes: Option<String>,
    photo_base64: Option<String>,
    photo_mime: Option<String>,
) -> Result<ContactView, String> {
    let path = contacts_path(&app)?;
    let mut book = contacts::load_address_book(&path).map_err(|e| e.to_string())?;
    let entry = book
        .iter_mut()
        .find(|c| c.public_key_armored == public_key_armored)
        .ok_or("contatto non trovato in rubrica")?;

    entry.name = name;
    entry.email = normalize_optional(email);
    entry.phone = normalize_optional(phone);
    entry.notes = normalize_optional(notes);
    entry.photo_base64 = photo_base64;
    entry.photo_mime = photo_mime;
    let updated = entry.clone();

    contacts::save_address_book(&path, &book).map_err(|e| e.to_string())?;

    contact_view(&updated)
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

/// Dettagli tecnici (algoritmo, date) della propria identità, per la
/// sezione "avanzate".
#[tauri::command]
fn my_technical_details(state: State<AppState>) -> Result<Vec<KeyDetailView>, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard.as_ref().ok_or("genera o importa prima la tua identità")?;
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
    let id = guard.as_ref().ok_or("genera o importa prima la tua identità")?;
    identity::export_private_key_file(&id.cert, &password).map_err(|e| e.to_string())
}

fn recipients_from_armored(recipients_armored: &[String]) -> Result<Vec<sequoia_openpgp::Cert>, String> {
    recipients_armored
        .iter()
        .map(|armored| contacts::import_public_key(armored.as_bytes()))
        .collect::<anyhow::Result<_>>()
        .map_err(|e| e.to_string())
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
        .ok_or("genera o importa prima la tua identità")?;
    let recipients = recipients_from_armored(&recipients_armored)?;
    message::encrypt(&id.cert, &recipients, &plaintext, sign).map_err(|e| e.to_string())
}

/// Cifra un'immagine (o un altro file) leggendolo da `source_path` e
/// scrivendo il risultato cifrato direttamente in `output_path`, senza
/// far transitare i byte del file per il frontend: per un'immagine di
/// alcuni MB è più veloce e non appesantisce l'interfaccia. Il nome
/// originale del file viene incorporato nel messaggio OpenPGP, cosi chi
/// decifra lo ritrova come nome suggerito. Il formato (.asc armato o
/// .gpg binario) segue l'impostazione salvata in Avanzate.
#[tauri::command]
fn encrypt_image(
    app: AppHandle,
    state: State<AppState>,
    recipients_armored: Vec<String>,
    source_path: String,
    output_path: String,
    sign: bool,
) -> Result<(), String> {
    let guard = state.identity.lock().unwrap();
    let id = guard
        .as_ref()
        .ok_or("genera o importa prima la tua identità")?;
    let recipients = recipients_from_armored(&recipients_armored)?;

    let data = std::fs::read(&source_path)
        .map_err(|e| format!("impossibile leggere il file immagine: {e}"))?;
    let filename = std::path::Path::new(&source_path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned());

    let format =
        settings::load_image_format(&settings_path(&app)?).map_err(|e| e.to_string())?;
    let armor = format == settings::ImageFormat::Asc;

    let ciphertext = message::encrypt_bytes(
        &id.cert,
        &recipients,
        &data,
        filename.as_deref(),
        sign,
        armor,
    )
    .map_err(|e| e.to_string())?;

    std::fs::write(&output_path, &ciphertext)
        .map_err(|e| format!("impossibile salvare il file cifrato: {e}"))?;

    Ok(())
}

/// Cifra insieme, in un unico file, un testo e un'immagine: il
/// destinatario aprendo e decifrando quel singolo file ritrova entrambi,
/// come un messaggio con didascalia e foto. I due contenuti vengono
/// prima impacchettati con [`sigillo_core::composite::encode`] in
/// un'unica sequenza di byte, poi cifrati normalmente: il motore
/// crittografico non deve sapere che dentro ci sono due cose diverse.
#[tauri::command]
fn encrypt_combined(
    app: AppHandle,
    state: State<AppState>,
    recipients_armored: Vec<String>,
    plaintext: String,
    source_path: String,
    output_path: String,
    sign: bool,
) -> Result<(), String> {
    let guard = state.identity.lock().unwrap();
    let id = guard
        .as_ref()
        .ok_or("genera o importa prima la tua identità")?;
    let recipients = recipients_from_armored(&recipients_armored)?;

    let image_data = std::fs::read(&source_path)
        .map_err(|e| format!("impossibile leggere il file immagine: {e}"))?;
    let image_filename = std::path::Path::new(&source_path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned());
    let image_mime =
        detect_media_mime(&image_data).ok_or("formato immagine o video non riconosciuto")?;

    let format =
        settings::load_image_format(&settings_path(&app)?).map_err(|e| e.to_string())?;
    let armor = format == settings::ImageFormat::Asc;

    let combined = sigillo_core::composite::encode(
        &plaintext,
        image_filename.as_deref(),
        image_mime,
        &image_data,
    );

    let ciphertext = message::encrypt_bytes(&id.cert, &recipients, &combined, None, sign, armor)
        .map_err(|e| e.to_string())?;

    std::fs::write(&output_path, &ciphertext)
        .map_err(|e| format!("impossibile salvare il file cifrato: {e}"))?;

    Ok(())
}

/// Riconosce se `data` è un'immagine o un video nei formati comuni
/// guardando i primi byte (che non cambiano cifrando/decifrando), non
/// l'estensione del file: funziona anche se il mittente ha usato un
/// altro programma OpenPGP che non imposta il nome file.
fn detect_media_mime(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if data.len() > 12 && &data[4..8] == b"ftyp" {
        let brand = &data[8..12];
        if matches!(
            brand,
            b"heic" | b"heix" | b"hevc" | b"heim" | b"heis" | b"hevm" | b"hevs" | b"mif1" | b"msf1"
        ) {
            return Some("image/heic");
        }
        if brand == b"qt  " {
            return Some("video/quicktime");
        }
        // Le varianti piu' comuni del brand MP4 (ISO Base Media / MPEG-4).
        if matches!(
            brand,
            b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1" | b"M4V " | b"M4A " | b"3gp4" | b"3gp5"
        ) {
            return Some("video/mp4");
        }
    }
    // Alcuni file .mov piu' vecchi non hanno un box "ftyp" iniziale:
    // iniziano direttamente con uno dei box QuickTime piu' comuni.
    if data.len() > 8 && matches!(&data[4..8], b"moov" | b"mdat" | b"free" | b"wide") {
        return Some("video/quicktime");
    }
    None
}

/// Sopra questa soglia, un'immagine o un video decifrati non vengono
/// incorporati come base64 nella risposta (appesantirebbe inutilmente
/// il trasferimento verso l'interfaccia e il consumo di memoria): si
/// scrivono invece su un file temporaneo, che l'utente puo' salvare
/// altrove o aprire con il lettore predefinito del sistema.
const LARGE_MEDIA_BYTES: usize = 60 * 1024 * 1024;

fn sanitize_filename_component(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn write_temp_media_file(data: &[u8], filename: Option<&str>) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("sigillo-anteprime");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("impossibile creare la cartella temporanea: {e}"))?;

    let base_name = filename
        .map(sanitize_filename_component)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "file-decifrato".to_string());

    let unique_prefix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("{}-{}-{}", std::process::id(), unique_prefix, base_name));

    std::fs::write(&path, data).map_err(|e| format!("impossibile salvare l'anteprima: {e}"))?;
    Ok(path)
}

/// Rimuove eventuali file temporanei di anteprima rimasti da una
/// sessione precedente (es. l'utente ha chiuso l'app senza salvare o
/// aprire un video decifrato): sicuro da fare ad ogni avvio, perche'
/// ogni decifratura crea sempre un file con un nome nuovo.
fn cleanup_stale_temp_previews() {
    let dir = std::env::temp_dir().join("sigillo-anteprime");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Prepara i campi "media" della risposta di decifratura: sotto soglia
/// il contenuto viene incorporato come base64 (comportamento invariato
/// per immagini e video di dimensione normale), sopra soglia viene
/// scritto su file temporaneo. Ritorna (base64, mime, percorso_temp).
fn media_view_fields(
    data: &[u8],
    mime: &str,
    filename: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    if data.len() > LARGE_MEDIA_BYTES {
        if let Ok(path) = write_temp_media_file(data, filename) {
            return (None, Some(mime.to_string()), Some(path.to_string_lossy().into_owned()));
        }
        // Se per qualche motivo non si riesce a scrivere il file
        // temporaneo, ripiega sul base64 invece di far fallire tutto.
    }
    (
        Some(base64::engine::general_purpose::STANDARD.encode(data)),
        Some(mime.to_string()),
        None,
    )
}

#[derive(Serialize)]
struct DecryptView {
    /// "testo", "immagine", "video", "combinato" (testo + immagine/video)
    /// o "file" (contenuto binario non riconosciuto).
    kind: String,
    plaintext: Option<String>,
    image_data_base64: Option<String>,
    image_mime: Option<String>,
    /// Presente solo per immagini/video sopra `LARGE_MEDIA_BYTES`: al
    /// posto di `image_data_base64`, il percorso di un file temporaneo
    /// gia' scritto su disco.
    media_temp_path: Option<String>,
    filename: Option<String>,
    signature_status: String,
    signer_fingerprint: Option<String>,
}

fn build_decrypt_view(
    data: Vec<u8>,
    filename: Option<String>,
    signature: message::SignatureStatus,
) -> DecryptView {
    let (signature_status, signer_fingerprint) = match signature {
        message::SignatureStatus::Unsigned => ("non_firmato".to_string(), None),
        message::SignatureStatus::Verified(fp) => {
            ("verificata".to_string(), Some(fp.to_spaced_hex()))
        }
        message::SignatureStatus::Unverifiable => ("non_verificabile".to_string(), None),
    };

    // Va controllato prima degli altri due casi: un pacchetto combinato
    // non ha i byte magici di un'immagine/video puro, ma per puro caso
    // i suoi byte potrebbero comunque risultare UTF-8 valido, finendo
    // scambiati per testo semplice se non lo si riconosce per primo.
    if sigillo_core::composite::is_combined(&data) {
        if let Ok(combined) = sigillo_core::composite::decode(&data) {
            let (image_data_base64, image_mime, media_temp_path) = media_view_fields(
                &combined.image_data,
                &combined.image_mime,
                combined.image_filename.as_deref(),
            );
            return DecryptView {
                kind: "combinato".to_string(),
                plaintext: Some(combined.text),
                image_data_base64,
                image_mime,
                media_temp_path,
                filename: combined.image_filename,
                signature_status,
                signer_fingerprint,
            };
        }
        // Pacchetto marcato come combinato ma illeggibile: ripiega sul
        // trattarlo come gli altri casi, invece di far fallire tutto.
    }

    if let Some(mime) = detect_media_mime(&data) {
        let kind = if mime.starts_with("video/") { "video" } else { "immagine" };
        let (image_data_base64, image_mime, media_temp_path) =
            media_view_fields(&data, mime, filename.as_deref());
        return DecryptView {
            kind: kind.to_string(),
            plaintext: None,
            image_data_base64,
            image_mime,
            media_temp_path,
            filename,
            signature_status,
            signer_fingerprint,
        };
    }

    if let Ok(text) = String::from_utf8(data.clone()) {
        return DecryptView {
            kind: "testo".to_string(),
            plaintext: Some(text),
            image_data_base64: None,
            image_mime: None,
            media_temp_path: None,
            filename,
            signature_status,
            signer_fingerprint,
        };
    }

    DecryptView {
        kind: "file".to_string(),
        plaintext: None,
        image_data_base64: Some(base64::engine::general_purpose::STANDARD.encode(&data)),
        image_mime: None,
        media_temp_path: None,
        filename,
        signature_status,
        signer_fingerprint,
    }
}

/// Copia un file temporaneo di anteprima (vedi `media_view_fields`)
/// nella destinazione scelta dall'utente, e prova a ripulire il
/// temporaneo dopo: usato dal pulsante "Salva..." quando la
/// decifratura di un'immagine/video di grandi dimensioni non ha
/// incorporato i byte nella risposta.
#[tauri::command]
fn save_temp_media(temp_path: String, dest_path: String) -> Result<(), String> {
    std::fs::copy(&temp_path, &dest_path)
        .map_err(|e| format!("impossibile salvare il file: {e}"))?;
    let _ = std::fs::remove_file(&temp_path);
    Ok(())
}

/// Decifra un contenuto incollato come testo (funziona sia per un
/// messaggio di testo sia per un'immagine cifrata in formato .asc: in
/// entrambi i casi l'input è testo ASCII armored). Il tipo di contenuto
/// reale (testo/immagine/file) è determinato dopo la decifratura.
#[tauri::command]
fn decrypt_message(
    state: State<AppState>,
    contacts_armored: Vec<String>,
    ciphertext: String,
) -> Result<DecryptView, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard
        .as_ref()
        .ok_or("genera o importa prima la tua identità")?;
    let contacts_certs = recipients_from_armored(&contacts_armored)?;

    let decrypted = message::decrypt_bytes(&id.cert, &contacts_certs, ciphertext.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(build_decrypt_view(
        decrypted.data,
        decrypted.filename,
        decrypted.signature,
    ))
}

/// Come [`decrypt_message`], ma leggendo l'input da un file su disco
/// invece che da testo incollato: serve per i file .gpg (binari, non
/// incollabili in una casella di testo).
#[tauri::command]
fn decrypt_file(
    state: State<AppState>,
    contacts_armored: Vec<String>,
    path: String,
) -> Result<DecryptView, String> {
    let guard = state.identity.lock().unwrap();
    let id = guard
        .as_ref()
        .ok_or("genera o importa prima la tua identità")?;
    let contacts_certs = recipients_from_armored(&contacts_armored)?;

    let input = std::fs::read(&path).map_err(|e| format!("impossibile leggere il file: {e}"))?;
    let decrypted =
        message::decrypt_bytes(&id.cert, &contacts_certs, &input).map_err(|e| e.to_string())?;

    Ok(build_decrypt_view(
        decrypted.data,
        decrypted.filename,
        decrypted.signature,
    ))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    cleanup_stale_temp_previews();

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
            update_contact,
            my_technical_details,
            contact_technical_details,
            export_private_key_file,
            get_image_format,
            set_image_format,
            encrypt_message,
            encrypt_image,
            encrypt_combined,
            decrypt_message,
            decrypt_file,
            save_temp_media,
        ])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di Sigillo");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mp4_via_ftyp_isom_brand() {
        let mut data = vec![0u8; 4];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(b"isom");
        data.extend_from_slice(&[0u8; 20]);
        assert_eq!(detect_media_mime(&data), Some("video/mp4"));
    }

    #[test]
    fn detects_mov_via_ftyp_qt_brand() {
        let mut data = vec![0u8; 4];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(b"qt  ");
        data.extend_from_slice(&[0u8; 20]);
        assert_eq!(detect_media_mime(&data), Some("video/quicktime"));
    }

    #[test]
    fn detects_older_mov_without_ftyp_box() {
        let mut data = vec![0u8; 4];
        data.extend_from_slice(b"moov");
        data.extend_from_slice(&[0u8; 20]);
        assert_eq!(detect_media_mime(&data), Some("video/quicktime"));
    }

    #[test]
    fn still_detects_images_unaffected_by_video_support() {
        assert_eq!(
            detect_media_mime(&[0xFF, 0xD8, 0xFF, 0, 0]),
            Some("image/jpeg")
        );
    }

    #[test]
    fn plain_text_is_not_detected_as_media() {
        assert_eq!(detect_media_mime(b"ciao, sono testo normale"), None);
    }

    #[test]
    fn small_media_is_embedded_as_base64_not_temp_file() {
        let (b64, mime, temp) = media_view_fields(&[1, 2, 3, 4], "image/png", Some("foto.png"));
        assert!(b64.is_some());
        assert_eq!(mime.as_deref(), Some("image/png"));
        assert!(temp.is_none());
    }

    #[test]
    fn large_media_is_written_to_a_temp_file_not_base64() {
        let data = vec![0xABu8; LARGE_MEDIA_BYTES + 1];
        let (b64, mime, temp) = media_view_fields(&data, "video/mp4", Some("clip.mp4"));
        assert!(b64.is_none());
        assert_eq!(mime.as_deref(), Some("video/mp4"));
        let path = temp.expect("doveva scrivere un file temporaneo");
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, data);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn temp_filename_has_no_directory_traversal_from_embedded_filename() {
        let path = write_temp_media_file(&[1, 2, 3], Some("../../etc/passwd")).unwrap();
        assert!(!path.to_string_lossy().contains(".."));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_temp_media_copies_and_cleans_up_the_source() {
        let dir = std::env::temp_dir().join("sigillo-test-save-temp-media");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("sorgente.bin");
        let dest = dir.join("destinazione.bin");
        std::fs::write(&src, b"contenuto di prova").unwrap();

        save_temp_media(
            src.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        )
        .unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"contenuto di prova");
        assert!(!src.exists(), "il file temporaneo va ripulito dopo la copia");

        std::fs::remove_dir_all(&dir).ok();
    }
}
