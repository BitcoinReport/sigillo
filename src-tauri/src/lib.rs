mod attachments;

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Context;
use serde::Serialize;
use sequoia_openpgp::Cert;
use tauri::{AppHandle, Manager, State};

use sigillo_core::{contacts, identity, keyinfo, message, settings, storage};

const VAULT_FILE_NAME: &str = "identity.sigillo";
const CONTACTS_FILE_NAME: &str = "contacts.json";
const SETTINGS_FILE_NAME: &str = "settings.json";
const MIN_PASSPHRASE_LEN: usize = 8;

/// Una delle identità dell'utente, sbloccate e pronte all'uso in questa
/// sessione: il nome/alias scelto in Sigillo (distinto dallo User ID
/// dentro il certificato OpenPGP, specialmente per una chiave importata)
/// più l'identità vera e propria.
struct LoadedIdentity {
    alias: String,
    identity: identity::Identity,
}

/// Sigillo supporta più identità sullo stesso dispositivo, tutte
/// protette da un'unica passphrase locale (per non costringere
/// l'utente a ricordarne una diversa per ciascuna), ma cifrate
/// ciascuna separatamente nel vault (vedi `storage::save_vault`).
#[derive(Default)]
struct AppState {
    /// Tutte le identità sbloccate in questa sessione (dal vault, con
    /// `unlock_identity`).
    identities: Mutex<Vec<LoadedIdentity>>,
    /// Quale, fra `identities`, è quella attiva di default (mostrata in
    /// "La mia identità", usata per firmare se lo Scrivi non ne indica
    /// una diversa esplicitamente).
    active_index: Mutex<Option<usize>>,
    /// Un'identità appena generata o importata, in attesa che l'utente
    /// completi il wizard (conferma seed phrase se presente, poi
    /// passphrase del dispositivo) prima di essere aggiunta al vault.
    pending: Mutex<Option<LoadedIdentity>>,
}

/// L'identità "attiva" di default: quella mostrata in "La mia identità"
/// e usata per firmare quando lo Scrivi non ne specifica una diversa.
fn active_identity(state: &State<AppState>) -> Result<(String, identity::Identity), String> {
    let identities = state.identities.lock().unwrap();
    let idx = state
        .active_index
        .lock()
        .unwrap()
        .ok_or("genera o importa prima la tua identità")?;
    identities
        .get(idx)
        .map(|li| (li.alias.clone(), clone_identity(&li.identity)))
        .ok_or_else(|| "genera o importa prima la tua identità".to_string())
}

/// L'identità scelta da un selettore esplicito (es. il menu "Firma
/// come..." in Scrivi), oppure quella attiva se non ne è stata indicata
/// una specifica.
fn identity_by_index_or_active(
    state: &State<AppState>,
    index: Option<usize>,
) -> Result<identity::Identity, String> {
    match index {
        Some(idx) => {
            let identities = state.identities.lock().unwrap();
            identities
                .get(idx)
                .map(|li| clone_identity(&li.identity))
                .ok_or_else(|| "identità non valida".to_string())
        }
        None => active_identity(state).map(|(_, id)| id),
    }
}

/// `identity::Identity` non implementa `Clone` (contiene materiale
/// segreto: meglio non renderlo clonabile per distrazione in giro per
/// il codice), ma qui serve poter usare un'identità senza tenere il
/// lock del Mutex per tutta la durata di un'operazione di
/// cifratura/decifratura potenzialmente lunga. La clonazione è
/// esplicita e locale a questo modulo.
fn clone_identity(id: &identity::Identity) -> identity::Identity {
    identity::Identity {
        mnemonic: id.mnemonic.clone(),
        cert: id.cert.clone(),
    }
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
    /// Nome/alias scelto per questa identità (per una generata da
    /// Sigillo coincide con lo User ID della chiave; per una importata è
    /// un'etichetta separata, solo per l'interfaccia di Sigillo).
    display_name: String,
    /// `None` per un'identità importata da una chiave esterna: non ha
    /// una seed phrase Sigillo.
    seed_phrase: Option<String>,
    seed_words: Vec<String>,
    fingerprint_hex: String,
    fingerprint_words: Vec<String>,
    public_key_armored: String,
    is_imported: bool,
}

fn identity_view(id: &identity::Identity, alias: &str) -> Result<IdentityView, String> {
    let public_key_armored = String::from_utf8(
        sequoia_openpgp::serialize::SerializeInto::to_vec(&id.cert.armored())
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(IdentityView {
        display_name: alias.to_string(),
        seed_phrase: id.seed_phrase(),
        seed_words: id
            .seed_words()
            .map(|words| words.into_iter().map(str::to_string).collect())
            .unwrap_or_default(),
        fingerprint_hex: id.cert.fingerprint().to_spaced_hex(),
        fingerprint_words: contacts::fingerprint_to_words(&id.cert.fingerprint())
            .into_iter()
            .map(str::to_string)
            .collect(),
        public_key_armored,
        is_imported: id.mnemonic.is_none(),
    })
}

/// Vero se su questo dispositivo esiste già un vault salvato (una o più
/// identità): decide se l'app deve mostrare il wizard di
/// generazione/import (primo avvio) o la schermata di sblocco con la
/// sola passphrase (avvii successivi).
#[tauri::command]
fn identity_exists_on_disk(app: AppHandle) -> Result<bool, String> {
    Ok(storage::vault_exists(&vault_path(&app)?))
}

/// Versione dell'app (sincronizzata con il tag della release da parte
/// del flusso di pubblicazione automatico): mostrata in Avanzate per
/// poter verificare a colpo d'occhio quale versione è davvero
/// installata, invece di doverlo dedurre da comportamenti/messaggi.
#[tauri::command]
fn app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
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
    *state.pending.lock().unwrap() = Some(LoadedIdentity {
        alias: name.to_string(),
        identity: id,
    });
    Ok(view)
}

/// Reimporta un'identità Sigillo esistente dalla sua seed phrase (per
/// portarla su un nuovo dispositivo, o per il passo di verifica subito
/// dopo averla generata).
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
    *state.pending.lock().unwrap() = Some(LoadedIdentity {
        alias: name.to_string(),
        identity: id,
    });
    Ok(view)
}

/// Importa una chiave privata OpenPGP generata altrove (GPG Suite,
/// Kleopatra, un terminale con GnuPG...): `armored_tsk` è il contenuto
/// del file .asc con la chiave privata completa, `key_passphrase` la sua
/// eventuale passphrase originale (solo per sbloccarla ora: da qui in
/// poi la protegge il vault di Sigillo), `alias` il nome scelto per
/// riconoscerla nell'interfaccia di Sigillo.
#[tauri::command]
fn import_identity_external(
    state: State<AppState>,
    armored_tsk: String,
    key_passphrase: Option<String>,
    alias: String,
) -> Result<IdentityView, String> {
    let alias = if alias.trim().is_empty() {
        "Chiave importata"
    } else {
        alias.trim()
    };
    let passphrase = key_passphrase.as_deref().filter(|p| !p.is_empty());

    let id = identity::import_external(armored_tsk.as_bytes(), passphrase)
        .map_err(|e| e.to_string())?;
    let view = identity_view(&id, alias)?;
    *state.pending.lock().unwrap() = Some(LoadedIdentity {
        alias: alias.to_string(),
        identity: id,
    });
    Ok(view)
}

/// Ricontrolla che le parole indicate della seed phrase corrispondano a
/// quelle mostrate, come nel wizard di conferma dei wallet Bitcoin. Non
/// si applica a un'identità importata da chiave esterna (non ha una
/// seed phrase da confermare: il wizard salta questo passo).
#[tauri::command]
fn confirm_seed_words(
    state: State<AppState>,
    positions_and_words: Vec<(u32, String)>,
) -> Result<bool, String> {
    let guard = state.pending.lock().unwrap();
    let pending = guard.as_ref().ok_or("nessuna identità generata")?;
    let words = pending
        .identity
        .seed_words()
        .ok_or("questa identità non ha una seed phrase da confermare")?;

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

/// Serializza il certificato (con materiale segreto) come TSK ASCII
/// armored, senza protezione da password: usato solo per la
/// persistenza interna nel vault di Sigillo, che lo protegge già da
/// solo con la passphrase del dispositivo.
fn serialize_tsk_armored(cert: &Cert) -> Result<String, String> {
    let armored =
        sequoia_openpgp::serialize::SerializeInto::to_vec(&cert.clone().as_tsk().armored())
            .map_err(|e| e.to_string())?;
    String::from_utf8(armored).map_err(|e| e.to_string())
}

/// Salva su disco, cifrata con `passphrase`, l'identità attualmente in
/// sospeso (generata o importata in questa sessione, non ancora nel
/// vault). Se sul dispositivo esiste già un vault, `passphrase` deve
/// essere quella corrente: la nuova identità si aggiunge alle altre,
/// non le sostituisce. Se è la primissima identità, `passphrase`
/// diventa la passphrase del dispositivo da questo momento in poi.
/// Restituisce l'elenco aggiornato di tutte le identità sul dispositivo.
#[tauri::command]
fn save_identity_to_disk(
    app: AppHandle,
    state: State<AppState>,
    passphrase: String,
) -> Result<Vec<IdentityView>, String> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "la passphrase deve avere almeno {MIN_PASSPHRASE_LEN} caratteri"
        ));
    }

    let pending = state
        .pending
        .lock()
        .unwrap()
        .take()
        .ok_or("nessuna identità da salvare")?;

    let path = vault_path(&app)?;
    let mut entries = if storage::vault_exists(&path) {
        storage::load_vault(&path, &passphrase).map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };

    let source = match pending.identity.seed_phrase() {
        Some(phrase) => storage::EntrySource::Seed(phrase),
        None => storage::EntrySource::ImportedTsk(serialize_tsk_armored(&pending.identity.cert)?),
    };
    entries.push(storage::VaultEntry {
        alias: pending.alias.clone(),
        source,
    });

    storage::save_vault(&path, &passphrase, &entries).map_err(|e| e.to_string())?;

    let mut identities = state.identities.lock().unwrap();
    identities.push(pending);
    *state.active_index.lock().unwrap() = Some(identities.len() - 1);

    identities
        .iter()
        .map(|li| identity_view(&li.identity, &li.alias))
        .collect()
}

/// Ricostruisce le identità (cert + eventuale mnemonic) a partire dalle
/// voci del vault già decifrate: usata sia da `unlock_identity` sia da
/// `save_identity_to_disk` per restituire una vista aggiornata di tutte
/// le identità senza dover tenere in memoria due rappresentazioni
/// diverse dello stesso dato.
fn identities_from_entries(entries: &[storage::VaultEntry]) -> Result<Vec<identity::Identity>, String> {
    entries
        .iter()
        .map(|entry| match &entry.source {
            storage::EntrySource::Seed(phrase) => {
                identity::import(phrase, &entry.alias).map_err(|e| e.to_string())
            }
            storage::EntrySource::ImportedTsk(armored) => {
                // Nel vault il materiale segreto e' gia' in chiaro
                // (protetto dal vault stesso): non serve piu' la
                // passphrase originale della chiave, fornita una sola
                // volta al momento dell'import.
                identity::import_external(armored.as_bytes(), None).map_err(|e| e.to_string())
            }
        })
        .collect()
}

/// Sblocca, con la sola passphrase locale del dispositivo (non le seed
/// phrase né le eventuali passphrase originali delle chiavi importate),
/// tutte le identità salvate su questo dispositivo.
#[tauri::command]
fn unlock_identity(
    app: AppHandle,
    state: State<AppState>,
    passphrase: String,
) -> Result<Vec<IdentityView>, String> {
    let path = vault_path(&app)?;
    let entries = storage::load_vault(&path, &passphrase).map_err(|e| e.to_string())?;
    let identities = identities_from_entries(&entries)?;

    let views = entries
        .iter()
        .zip(&identities)
        .map(|(entry, id)| identity_view(id, &entry.alias))
        .collect::<Result<Vec<_>, _>>()?;

    let loaded: Vec<LoadedIdentity> = entries
        .into_iter()
        .zip(identities)
        .map(|(entry, identity)| LoadedIdentity {
            alias: entry.alias,
            identity,
        })
        .collect();

    *state.identities.lock().unwrap() = loaded;
    *state.active_index.lock().unwrap() = Some(0);

    Ok(views)
}

/// Cambia quale identità è "attiva" (mostrata in "La mia identità",
/// usata per firmare quando Scrivi non ne indica una diversa).
#[tauri::command]
fn set_active_identity(state: State<AppState>, index: usize) -> Result<(), String> {
    let identities = state.identities.lock().unwrap();
    if index >= identities.len() {
        return Err("identità non valida".to_string());
    }
    *state.active_index.lock().unwrap() = Some(index);
    Ok(())
}

/// Rimuove in modo sicuro l'intero vault salvato su questo dispositivo
/// (tutte le identità), e con esso la rubrica: dopo questa chiamata il
/// prossimo avvio torna a mostrare il wizard di generazione/import,
/// come al primo avvio, con una rubrica di nuovo vuota.
#[tauri::command]
fn remove_identity_from_disk(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let path = vault_path(&app)?;
    storage::remove_identity(&path).map_err(|e| e.to_string())?;
    // La rubrica potrebbe non esistere ancora (nessun contatto mai
    // aggiunto): non è un errore, è il caso normale.
    let _ = std::fs::remove_file(contacts_path(&app)?);
    state.identities.lock().unwrap().clear();
    *state.active_index.lock().unwrap() = None;
    *state.pending.lock().unwrap() = None;
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

/// Tutte le preferenze rilevanti per il frontend in un'unica risposta:
/// evita un giro a parte per ciascuna (formato immagini escluso, che ha
/// già i suoi comandi dedicati usati anche prima di questa funzione).
#[derive(Serialize)]
struct AppSettingsView {
    experimental_features_enabled: bool,
    tor_enabled: bool,
    tor_socks_host: String,
    tor_socks_port: u16,
    timelock_custom_endpoint: Option<String>,
}

impl From<settings::Settings> for AppSettingsView {
    fn from(s: settings::Settings) -> Self {
        AppSettingsView {
            experimental_features_enabled: s.experimental_features_enabled,
            tor_enabled: s.tor_enabled,
            tor_socks_host: s.tor_socks_host,
            tor_socks_port: s.tor_socks_port,
            timelock_custom_endpoint: s.timelock_custom_endpoint,
        }
    }
}

#[tauri::command]
fn get_app_settings(app: AppHandle) -> Result<AppSettingsView, String> {
    settings::load_settings(&settings_path(&app)?)
        .map(Into::into)
        .map_err(|e| e.to_string())
}

/// "Funzioni sperimentali" (Avanzate): finché disattivato, il resto
/// dell'interfaccia legata al time-lock non deve comparire da nessuna
/// parte, non solo essere disabilitata — è il frontend a occuparsene
/// non renderizzando quella UI quando questo flag è spento.
#[tauri::command]
fn set_experimental_features_enabled(app: AppHandle, enabled: bool) -> Result<(), String> {
    let path = settings_path(&app)?;
    let mut current = settings::load_settings(&path).map_err(|e| e.to_string())?;
    current.experimental_features_enabled = enabled;
    settings::save_settings(&path, &current).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_tor_settings(
    app: AppHandle,
    enabled: bool,
    socks_host: String,
    socks_port: u16,
    custom_endpoint: Option<String>,
) -> Result<(), String> {
    let path = settings_path(&app)?;
    let mut current = settings::load_settings(&path).map_err(|e| e.to_string())?;
    current.tor_enabled = enabled;
    if !socks_host.trim().is_empty() {
        current.tor_socks_host = socks_host.trim().to_string();
    }
    current.tor_socks_port = socks_port;
    current.timelock_custom_endpoint = custom_endpoint.filter(|e| !e.trim().is_empty());
    settings::save_settings(&path, &current).map_err(|e| e.to_string())
}

// ---------- Time-lock (funzione sperimentale) ----------

const DEFAULT_TIMELOCK_ENDPOINT: &str = "https://mempool.space/api/blocks/tip/height";

// Una richiesta diretta (senza Tor) è normalmente rapida: 20 secondi
// sono già ampiamente sufficienti anche con una rete lenta.
const CLEARNET_HTTP_TIMEOUT_SECS: u64 = 20;

// La costruzione di un circuito Tor è per natura variabile: nei test
// di questa funzione, la stessa identica richiesta verso lo stesso
// demone ha impiegato a volte pochi secondi e a volte oltre un minuto.
// Margini generosi per non scambiare per un errore quello che è solo
// un circuito lento a formarsi (l'utente può comunque ritentare).
const TOR_CONNECT_TIMEOUT_SECS: u64 = 90;
const TOR_TOTAL_TIMEOUT_SECS: u64 = 120;

/// Interroga `endpoint` (che deve rispondere con l'altezza blocco come
/// numero semplice, come fa l'API pubblica di mempool.space) e
/// restituisce l'altezza corrente. Se `use_tor` è attivo, la richiesta
/// passa da un proxy SOCKS5 locale (un demone Tor già in esecuzione,
/// non incorporato in Sigillo: per questo l'inizializzazione qui è solo
/// la creazione di un client HTTP configurato, non l'avvio di un client
/// Tor vero e proprio, che semplicemente non esiste dentro l'app).
fn fetch_block_height(
    endpoint: &str,
    use_tor: bool,
    tor_socks_host: &str,
    tor_socks_port: u16,
) -> Result<u32, String> {
    let (connect_timeout, total_timeout) = if use_tor {
        (
            std::time::Duration::from_secs(TOR_CONNECT_TIMEOUT_SECS),
            std::time::Duration::from_secs(TOR_TOTAL_TIMEOUT_SECS),
        )
    } else {
        let t = std::time::Duration::from_secs(CLEARNET_HTTP_TIMEOUT_SECS);
        (t, t)
    };
    fetch_block_height_with_timeouts(
        endpoint,
        use_tor,
        tor_socks_host,
        tor_socks_port,
        connect_timeout,
        total_timeout,
    )
}

/// Nucleo di `fetch_block_height` con i timeout esposti come parametri,
/// per poter essere testato con valori brevi invece di dover aspettare
/// i timeout (generosi apposta) usati in produzione.
fn fetch_block_height_with_timeouts(
    endpoint: &str,
    use_tor: bool,
    tor_socks_host: &str,
    tor_socks_port: u16,
    connect_timeout: std::time::Duration,
    total_timeout: std::time::Duration,
) -> Result<u32, String> {
    // Log su stderr (visibile lanciando l'app da terminale, non
    // incorporato in nessuna UI): pensato per poter diagnosticare un
    // problema di connessione futuro senza dover indovinare quali
    // valori sono stati effettivamente usati per la richiesta. Non
    // c'e' alcuna cache in questa funzione: host, porta e client HTTP
    // sono sempre ricostruiti da zero a ogni chiamata, con i valori
    // ricevuti come parametro in quel preciso momento.
    eprintln!(
        "[sigillo/timelock] verifica altezza blocco: endpoint={endpoint} use_tor={use_tor} tor_socks={tor_socks_host}:{tor_socks_port} connect_timeout={connect_timeout:?} total_timeout={total_timeout:?}"
    );

    let mut builder = reqwest::blocking::Client::builder().timeout(total_timeout);

    if use_tor {
        // "socks5h" (non "socks5"): la risoluzione del nome host avviene
        // dal lato del proxy, indispensabile per un indirizzo .onion,
        // che non esiste nel DNS normale.
        let proxy_url = format!("socks5h://{tor_socks_host}:{tor_socks_port}");
        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| format!("configurazione del proxy Tor non valida: {e}"))?;
        builder = builder.proxy(proxy).connect_timeout(connect_timeout);
    }

    let client = builder
        .build()
        .map_err(|e| format!("impossibile inizializzare il client di rete: {e}"))?;

    let response = client.get(endpoint).send().map_err(|e| {
        // {:?} (Debug) su un reqwest::Error espone anche la catena di
        // errori sottostante (io::Error, motivo hyper...), utile in
        // log/diagnosi anche quando il messaggio mostrato all'utente
        // (via {}, Display) resta un riassunto piu' leggibile.
        eprintln!(
            "[sigillo/timelock] richiesta fallita verso {endpoint} (tor={use_tor}, proxy={tor_socks_host}:{tor_socks_port}): {e:?}"
        );
        describe_block_height_request_error(&e, endpoint, use_tor, tor_socks_host, tor_socks_port)
    })?;

    let text = response
        .error_for_status()
        .map_err(|e| format!("l'endpoint ha risposto con un errore: {e}"))?
        .text()
        .map_err(|e| format!("impossibile leggere la risposta dell'endpoint: {e}"))?;

    text.trim()
        .parse::<u32>()
        .map_err(|_| format!("risposta dell'endpoint non valida (attesa l'altezza blocco, un numero): \"{}\"", text.trim()))
}

/// Traduce un errore di rete in un messaggio che distingue i casi più
/// comuni (nessun servizio in ascolto sulla porta indicata, timeout...)
/// invece di limitarsi a un messaggio generico: soprattutto per Tor,
/// dove le cause tipiche (demone non avviato, porta sbagliata, circuito
/// lento a formarsi) richiedono reazioni diverse da parte dell'utente.
fn describe_block_height_request_error(
    err: &reqwest::Error,
    endpoint: &str,
    use_tor: bool,
    tor_socks_host: &str,
    tor_socks_port: u16,
) -> String {
    if !use_tor {
        return format!("impossibile raggiungere {endpoint}: {err}");
    }

    // L'ordine conta: un timeout durante la fase di connessione può
    // soddisfare anche is_connect() (e' comunque fallito "durante la
    // connessione"), ma il messaggio piu' utile in quel caso e' quello
    // sul timeout, non quello che suggerisce "nessun servizio in
    // ascolto" (che varrebbe solo per un rifiuto immediato, senza
    // alcuna attesa).
    if err.is_timeout() {
        format!(
            "il proxy Tor su {tor_socks_host}:{tor_socks_port} non ha risposto in tempo: se il client Tor è stato avviato da poco, il circuito potrebbe impiegare più tempo del solito a formarsi la prima volta. Riprova tra qualche istante."
        )
    } else if err.is_connect() {
        format!(
            "impossibile connettersi al proxy Tor su {tor_socks_host}:{tor_socks_port}: verifica che un client Tor (demone standalone, Tor Browser...) sia davvero in ascolto su quella porta. Dettagli: {err}"
        )
    } else {
        format!("impossibile raggiungere {endpoint} tramite Tor ({tor_socks_host}:{tor_socks_port}): {err}")
    }
}

fn effective_endpoint(custom: Option<&str>) -> String {
    custom
        .filter(|e| !e.trim().is_empty())
        .unwrap_or(DEFAULT_TIMELOCK_ENDPOINT)
        .to_string()
}

fn should_use_tor(endpoint: &str, local_tor_enabled: bool) -> bool {
    endpoint.contains(".onion") || local_tor_enabled
}

/// L'endpoint di verifica altezza blocco che compare *dentro* un
/// messaggio con blocco temporale è scelto da chi ha scritto il
/// messaggio, non da chi lo apre. Prima di contattarlo lo restringiamo,
/// così che aprire un messaggio non possa diventare:
///
/// - un "tracking pixel": una richiesta in chiaro rivelerebbe al
///   mittente IP e orario esatto di apertura → ammettiamo solo `https`
///   (con un'eccezione per gli indirizzi `.onion`, dove è il trasporto
///   Tor a fornire cifratura e anonimato e i servizi onion sono spesso
///   solo-`http`);
/// - un SSRF verso la rete interna del destinatario → l'host deve essere
///   un nome di dominio, mai un indirizzo IP scritto per esteso (blocca
///   `127.0.0.1`, `169.254.169.254`, `10.x`, `192.168.x`, `[::1]`, ...),
///   e non deve essere `localhost`.
///
/// L'endpoint predefinito (mempool.space) e quello eventualmente salvato
/// dall'utente in Avanzate non passano di qui: quelli li ha scelti
/// l'utente in prima persona.
fn validate_sender_supplied_endpoint(raw: &str) -> Result<(), String> {
    let generic = || {
        "l'indirizzo di verifica indicato nel messaggio non è ammesso \
         (serve un URL https verso un nome di dominio)"
            .to_string()
    };

    let url = reqwest::Url::parse(raw).map_err(|_| generic())?;

    let host = url.host_str().ok_or_else(generic)?;
    // host_str() restituisce l'IPv6 fra parentesi quadre: vanno tolte
    // prima di provare a interpretarlo come indirizzo IP.
    let host_bare = host.trim_start_matches('[').trim_end_matches(']');
    let host_lower = host_bare.to_ascii_lowercase();

    let is_onion = host_lower == "onion" || host_lower.ends_with(".onion");

    match url.scheme() {
        "https" => {}
        "http" if is_onion => {}
        _ => return Err(generic()),
    }

    if host_bare.parse::<std::net::IpAddr>().is_ok() {
        return Err(
            "l'indirizzo di verifica indicato nel messaggio punta a un IP diretto, non consentito"
                .to_string(),
        );
    }

    if host_lower == "localhost" || host_lower.ends_with(".localhost") {
        return Err(
            "l'indirizzo di verifica indicato nel messaggio punta a 'localhost', non consentito"
                .to_string(),
        );
    }

    Ok(())
}

/// Controlla l'altezza blocco corrente: usato sia per mostrare un
/// riferimento mentre si sceglie l'altezza target in Scrivi, sia
/// internamente per verificare se un messaggio bloccato si può ormai
/// decifrare.
#[tauri::command]
fn check_block_height(app: AppHandle, custom_endpoint: Option<String>) -> Result<u32, String> {
    let settings = settings::load_settings(&settings_path(&app)?).map_err(|e| e.to_string())?;
    let endpoint = effective_endpoint(custom_endpoint.as_deref());
    let use_tor = should_use_tor(&endpoint, settings.tor_enabled);
    fetch_block_height(&endpoint, use_tor, &settings.tor_socks_host, settings.tor_socks_port)
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
    let (_, id) = active_identity(&state)?;
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
    let (_, id) = active_identity(&state)?;
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
    sender_index: Option<usize>,
) -> Result<String, String> {
    let id = identity_by_index_or_active(&state, sender_index)?;
    let recipients = recipients_from_armored(&recipients_armored)?;
    message::encrypt(&id.cert, &recipients, &plaintext, sign).map_err(|e| e.to_string())
}

// ---------- Allegati: cifratura ----------

/// Esegue un lavoro pesante (cifratura/decifratura di un file, copie) su
/// un thread dedicato invece che sul thread principale dell'app: la
/// finestra resta reattiva anche con allegati da centinaia di MB. Va
/// fatto con `spawn_blocking` (e non con un semplice comando "async")
/// perche' la verifica dell'altezza blocco usa un client HTTP bloccante,
/// che non puo' girare dentro un task asincrono.
async fn run_blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|e| format!("errore interno: {e}"))?
}

fn attachment_store(app: &AppHandle) -> Result<attachments::AttachmentStore, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("impossibile trovare la cartella privata dell'app: {e}"))?;
    Ok(attachments::AttachmentStore::new(dir.join("anteprime")))
}

/// Un file scelto per essere allegato, gia' descritto con le stesse
/// regole usate in "Scrivi" (nome sanificato, tipo, dimensione).
struct SourceFile {
    path: PathBuf,
    info: attachments::AttachmentInfo,
}

fn open_source_file(path: &str) -> Result<SourceFile, String> {
    let path = PathBuf::from(path);
    let info = attachments::describe_source_file(&path).map_err(|e| format!("{e:#}"))?;
    Ok(SourceFile { path, info })
}

/// Scrive su `output_path` un messaggio cifrato il cui contenuto e'
/// `prefix` seguito (se c'e') dal file `file`, copiato a pezzi: in
/// memoria non ce n'e' mai piu' di qualche kilobyte alla volta, quindi
/// vale per un PDF come per un video da centinaia di MB. Si scrive in
/// un file provvisorio e lo si rinomina solo a cifratura riuscita: un
/// errore (disco pieno, file cambiato nel frattempo) non lascia mai un
/// file cifrato a meta' al posto di quello scelto dall'utente.
fn encrypt_payload_to_file(
    sender: &Cert,
    recipients: &[Cert],
    sign: bool,
    armor: bool,
    output_path: &str,
    literal_name: Option<&str>,
    prefix: &[u8],
    file: Option<&SourceFile>,
) -> Result<(), String> {
    use std::io::{BufReader, BufWriter, Write};

    let partial = format!("{output_path}.parte");
    let result = (|| -> anyhow::Result<()> {
        let mut out = BufWriter::new(
            std::fs::File::create(&partial).context("impossibile creare il file cifrato")?,
        );
        message::encrypt_to_writer(sender, recipients, literal_name, sign, armor, &mut out, |w| {
            w.write_all(prefix)?;
            if let Some(file) = file {
                let mut src = BufReader::new(
                    std::fs::File::open(&file.path).context("impossibile leggere il file da allegare")?,
                );
                let copied = std::io::copy(&mut src, w)?;
                if copied != file.info.size {
                    anyhow::bail!("il file e' cambiato mentre veniva cifrato: riprova");
                }
            }
            Ok(())
        })?;
        out.flush().context("impossibile salvare il file cifrato")?;
        out.into_inner()
            .map_err(|e| anyhow::anyhow!("impossibile salvare il file cifrato: {e}"))?
            .sync_all()
            .context("impossibile salvare il file cifrato")?;
        std::fs::rename(&partial, output_path).context("impossibile salvare il file cifrato")?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = std::fs::remove_file(&partial);
        return Err(format!("{e:#}"));
    }
    Ok(())
}

fn armor_setting(app: &AppHandle) -> Result<bool, String> {
    let format = settings::load_image_format(&settings_path(app)?).map_err(|e| e.to_string())?;
    Ok(format == settings::ImageFormat::Asc)
}

/// Cosa sapere di un file prima di allegarlo: nome (sanificato), tipo,
/// dimensione, se e' un programma. Le stesse regole usate poi per
/// cifrarlo; il contenuto non passa per l'interfaccia.
#[tauri::command]
async fn attachment_info(path: String) -> Result<attachments::AttachmentInfo, String> {
    run_blocking(move || {
        attachments::describe_source_file(std::path::Path::new(&path)).map_err(|e| format!("{e:#}"))
    })
    .await
}

/// Cifra un file qualsiasi (immagine, video, PDF, documento...) leggendolo
/// da `source_path` e scrivendo il risultato direttamente in
/// `output_path`, senza far transitare i byte del file per il frontend.
/// Il nome originale viaggia nel campo standard "nome file" del messaggio
/// OpenPGP: chi decifra con Sigillo (o con un altro programma OpenPGP)
/// ritrova il file con il suo nome. Il formato (.asc armato o .gpg
/// binario) segue l'impostazione salvata in Avanzate.
#[tauri::command]
async fn encrypt_attachment(
    app: AppHandle,
    recipients_armored: Vec<String>,
    source_path: String,
    output_path: String,
    sign: bool,
    sender_index: Option<usize>,
) -> Result<(), String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let id = identity_by_index_or_active(&state, sender_index)?;
        let recipients = recipients_from_armored(&recipients_armored)?;
        let file = open_source_file(&source_path)?;
        let armor = armor_setting(&app)?;
        encrypt_payload_to_file(
            &id.cert,
            &recipients,
            sign,
            armor,
            &output_path,
            Some(&file.info.name),
            &[],
            Some(&file),
        )
    })
    .await
}

/// Cifra insieme, in un unico file, un testo e un allegato: il
/// destinatario aprendo e decifrando quel singolo file ritrova entrambi,
/// come un messaggio con didascalia e foto (o con un PDF). I due
/// contenuti vengono impacchettati con [`sigillo_core::composite`] e poi
/// cifrati normalmente: il motore crittografico non deve sapere che
/// dentro ci sono due cose diverse.
#[tauri::command]
async fn encrypt_combined(
    app: AppHandle,
    recipients_armored: Vec<String>,
    plaintext: String,
    source_path: String,
    output_path: String,
    sign: bool,
    sender_index: Option<usize>,
) -> Result<(), String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let id = identity_by_index_or_active(&state, sender_index)?;
        let recipients = recipients_from_armored(&recipients_armored)?;
        let file = open_source_file(&source_path)?;
        let armor = armor_setting(&app)?;

        let header = sigillo_core::composite::encode_header(
            &plaintext,
            Some(&file.info.name),
            &file.info.mime,
            file.info.size,
        )
        .map_err(|e| e.to_string())?;

        encrypt_payload_to_file(&id.cert, &recipients, sign, armor, &output_path, None, &header, Some(&file))
    })
    .await
}

/// Cifra un messaggio (testo, e/o un allegato) con un blocco temporale
/// applicativo: testo e allegato vengono impacchettati esattamente come
/// in [`encrypt_combined`], poi avvolti da [`sigillo_core::timelock`] con
/// l'altezza blocco target e l'endpoint di verifica scelto (che finisce
/// nei metadati del messaggio, cosi' anche chi lo riceve verifica con lo
/// stesso endpoint), infine cifrati normalmente: il vincolo e'
/// applicativo (lo fa rispettare l'interfaccia di Sigillo), non
/// crittografico — chi ha la chiave privata giusta puo' comunque
/// decifrare il pacchetto OpenPGP in ogni momento, e' solo il contenuto a
/// restare "nascosto" dall'app finche' l'altezza non e' raggiunta.
#[tauri::command]
async fn encrypt_timelocked(
    app: AppHandle,
    recipients_armored: Vec<String>,
    plaintext: String,
    source_path: Option<String>,
    output_path: String,
    sign: bool,
    sender_index: Option<usize>,
    target_height: u32,
    custom_endpoint: Option<String>,
) -> Result<(), String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let id = identity_by_index_or_active(&state, sender_index)?;
        let recipients = recipients_from_armored(&recipients_armored)?;
        let file = source_path.as_deref().map(open_source_file).transpose()?;
        let armor = armor_setting(&app)?;

        // Contenuto interno: un pacchetto combinato se c'e' un allegato,
        // altrimenti il solo testo.
        let (inner_prefix, inner_len) = match &file {
            Some(file) => {
                let header = sigillo_core::composite::encode_header(
                    &plaintext,
                    Some(&file.info.name),
                    &file.info.mime,
                    file.info.size,
                )
                .map_err(|e| e.to_string())?;
                let total = header.len() as u64 + file.info.size;
                (header, total)
            }
            None => {
                let bytes = plaintext.into_bytes();
                let total = bytes.len() as u64;
                (bytes, total)
            }
        };

        let endpoint = custom_endpoint.filter(|e| !e.trim().is_empty());
        let mut prefix =
            sigillo_core::timelock::encode_header(target_height, endpoint.as_deref(), inner_len)
                .map_err(|e| e.to_string())?;
        prefix.extend_from_slice(&inner_prefix);

        encrypt_payload_to_file(&id.cert, &recipients, sign, armor, &output_path, None, &prefix, file.as_ref())
    })
    .await
}

// ---------- Allegati: decifratura ----------

#[derive(Serialize)]
struct DecryptView {
    /// "testo", "allegato" (solo un file), "combinato" (testo + file) o
    /// "bloccato_nel_tempo" (funzione sperimentale, altezza target non
    /// ancora raggiunta).
    kind: String,
    plaintext: Option<String>,
    /// Il file decifrato, su disco nella cartella privata dell'app: al
    /// frontend arrivano solo percorso e metadati, mai i byte.
    attachment: Option<attachments::AttachmentView>,
    signature_status: String,
    signer_fingerprint: Option<String>,
    /// Solo per un messaggio con blocco temporale (bloccato o appena
    /// sbloccato): l'altezza target.
    target_height: Option<u32>,
    /// Solo per un messaggio con blocco temporale: l'altezza corrente,
    /// se la verifica e' riuscita.
    current_height: Option<u32>,
    /// Solo per "bloccato_nel_tempo": presente se la verifica
    /// dell'altezza corrente e' fallita (rete assente, endpoint non
    /// raggiungibile...), invece di current_height.
    height_check_error: Option<String>,
}

fn decrypt_view_from(outcome: message::StreamOutcome<attachments::Processed>) -> DecryptView {
    let (signature_status, signer_fingerprint) = match outcome.signature {
        message::SignatureStatus::Unsigned => ("non_firmato".to_string(), None),
        message::SignatureStatus::Verified(fp) => {
            ("verificata".to_string(), Some(fp.to_spaced_hex()))
        }
        message::SignatureStatus::Unverifiable => ("non_verificabile".to_string(), None),
    };
    let processed = outcome.value;
    DecryptView {
        kind: processed.kind.to_string(),
        plaintext: processed.plaintext,
        attachment: processed.attachment,
        signature_status,
        signer_fingerprint,
        target_height: processed.target_height,
        current_height: processed.current_height,
        height_check_error: processed.height_check_error,
    }
}

type CipherInput<'a> = Box<dyn std::io::Read + Send + Sync + 'a>;

/// Da dove viene il messaggio cifrato: testo incollato, o un file su disco
/// (che si legge a pezzi, senza caricarlo in memoria).
enum CipherSource<'a> {
    Text(&'a str),
    File(&'a str),
}

fn open_cipher_input<'a>(source: &CipherSource<'a>) -> Result<CipherInput<'a>, String> {
    match source {
        CipherSource::Text(text) => Ok(Box::new(std::io::Cursor::new(text.as_bytes()))),
        CipherSource::File(path) => std::fs::File::open(path)
            .map(|f| Box::new(f) as CipherInput<'a>)
            .map_err(|e| format!("impossibile leggere il file: {e}")),
    }
}

/// Prova a decifrare con ciascuna delle identita' disponibili sul
/// dispositivo, non solo quella attiva: un messaggio in arrivo potrebbe
/// essere indirizzato a una qualsiasi delle identita' dell'utente,
/// non necessariamente quella scelta l'ultima volta in "La mia identita'".
/// Separata da `decrypt_to_view` per poterla testare senza costruire il
/// runtime di Tauri: prova `certs` uno per uno, nell'ordine dato, finche'
/// uno non riesce. `open_input` produce un lettore nuovo per ogni
/// tentativo; `rollback` si chiama dopo un tentativo fallito (per
/// buttare via quello che `consume` aveva eventualmente scritto).
fn decrypt_streaming_with_any_cert<'a, T>(
    certs: &[Cert],
    contacts_certs: &[Cert],
    open_input: &dyn Fn() -> Result<CipherInput<'a>, String>,
    consume: &mut dyn FnMut(&mut dyn std::io::Read, &dyn Fn() -> Option<String>) -> anyhow::Result<T>,
    rollback: &mut dyn FnMut(),
) -> Result<message::StreamOutcome<T>, String> {
    if certs.is_empty() {
        return Err("genera o importa prima la tua identità".to_string());
    }

    // Fra piu' errori si preferisce quello che dice qualcosa di utile
    // sul messaggio (es. "danneggiato") a "non e' indirizzato a te".
    let mut best_err: Option<String> = None;
    for cert in certs {
        let input = open_input()?;
        let attempt = message::decrypt_streaming(
            cert,
            contacts_certs,
            input,
            |plain: &mut dyn std::io::Read, name: &dyn Fn() -> Option<String>| consume(plain, name),
        );
        match attempt {
            Ok(outcome) => return Ok(outcome),
            Err(e) => {
                rollback();
                let msg = format!("{e:#}");
                let is_mismatch = msg.contains("non è indirizzato a te");
                if best_err.is_none() || !is_mismatch {
                    best_err = Some(msg);
                }
            }
        }
    }
    Err(best_err.unwrap_or_else(|| "impossibile decifrare il messaggio".to_string()))
}

/// Decifra `source` e lo traduce in quello che vede l'utente. Un
/// allegato viene scritto su file (mai passato come stringa all'interfaccia);
/// se alla fine il messaggio non risulta autentico (troncato, manomesso)
/// i file scritti vengono rimossi e il risultato e' un errore.
fn decrypt_to_view(
    app: &AppHandle,
    state: &State<AppState>,
    contacts_armored: &[String],
    source: CipherSource,
) -> Result<DecryptView, String> {
    let contacts_certs = recipients_from_armored(contacts_armored)?;
    // Si copiano i certificati fuori dal lucchetto: la decifratura (e
    // l'eventuale verifica di rete del blocco temporale) non deve tenere
    // bloccate le altre operazioni.
    let certs: Vec<Cert> = {
        let identities = state.identities.lock().unwrap();
        identities.iter().map(|li| li.identity.cert.clone()).collect()
    };
    let settings = settings::load_settings(&settings_path(app)?).map_err(|e| e.to_string())?;

    let store = attachment_store(app)?;
    let session = attachments::Session::new(&store);
    let fetch_height = |endpoint: &str, use_tor: bool| {
        fetch_block_height(endpoint, use_tor, &settings.tor_socks_host, settings.tor_socks_port)
    };

    let outcome = decrypt_streaming_with_any_cert(
        &certs,
        &contacts_certs,
        &|| open_cipher_input(&source),
        &mut |plain, name| attachments::process_plaintext(plain, name, &settings, &session, &fetch_height),
        &mut || session.rollback(),
    )?;
    session.commit();
    Ok(decrypt_view_from(outcome))
}

/// Decifra un contenuto incollato come testo (funziona sia per un
/// messaggio di testo sia per un file cifrato in formato .asc: in
/// entrambi i casi l'input e' testo ASCII armored). Il tipo di contenuto
/// reale (testo/allegato) e' determinato dopo la decifratura.
#[tauri::command]
async fn decrypt_message(
    app: AppHandle,
    contacts_armored: Vec<String>,
    ciphertext: String,
) -> Result<DecryptView, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        decrypt_to_view(&app, &state, &contacts_armored, CipherSource::Text(&ciphertext))
    })
    .await
}

/// Come [`decrypt_message`], ma leggendo l'input da un file su disco
/// invece che da testo incollato: serve per i file .gpg (binari, non
/// incollabili in una casella di testo) e per i messaggi grandi, che
/// cosi' non transitano per l'interfaccia.
#[tauri::command]
async fn decrypt_file(
    app: AppHandle,
    contacts_armored: Vec<String>,
    path: String,
) -> Result<DecryptView, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        decrypt_to_view(&app, &state, &contacts_armored, CipherSource::File(&path))
    })
    .await
}

/// Copia un allegato decifrato nella destinazione scelta dall'utente.
/// Rifiuta qualunque origine che non sia nella cartella privata dell'app.
#[tauri::command]
async fn save_decrypted_attachment(
    app: AppHandle,
    temp_path: String,
    dest_path: String,
) -> Result<(), String> {
    run_blocking(move || {
        let store = attachment_store(&app)?;
        attachments::copy_to_destination(
            &store,
            std::path::Path::new(&temp_path),
            std::path::Path::new(&dest_path),
        )
        .map_err(|e| format!("{e:#}"))
    })
    .await
}

/// Apre un allegato decifrato con il programma predefinito del sistema.
/// Per i programmi e gli script (`.exe`, `.sh`, `.apk`...) serve
/// `confirmed = true`, cioe' che l'utente abbia visto l'avviso; non si
/// apre mai nulla in automatico. Su Android/iOS il plugin usa il
/// meccanismo nativo di apertura.
#[tauri::command]
fn open_decrypted_attachment(app: AppHandle, path: String, confirmed: bool) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    let store = attachment_store(&app)?;
    attachments::check_open_allowed(&store, std::path::Path::new(&path), confirmed)
        .map_err(|e| format!("{e:#}"))?;
    app.opener().open_path(path, None::<&str>).map_err(|_| {
        "Non riesco ad aprire il file: forse sul tuo dispositivo non c'è un programma adatto. \
         Puoi comunque salvarlo e aprirlo da dove preferisci."
            .to_string()
    })
}

/// Elimina un allegato decifrato dalla cartella privata (quando si lascia
/// la schermata, o dopo averlo salvato). Un percorso che non e' un
/// allegato di Sigillo viene rifiutato.
#[tauri::command]
fn discard_decrypted_attachment(app: AppHandle, path: String) -> Result<(), String> {
    let store = attachment_store(&app)?;
    store
        .discard(std::path::Path::new(&path))
        .map_err(|e| format!("{e:#}"))
}

/// Su Linux la webview è WebKitGTK, che per riprodurre un video (anteprima
/// di un .mp4/.mov decifrato) si appoggia a GStreamer. Su diverse GPU più
/// datate il percorso di decodifica video *hardware* via VA-API è rotto a
/// livello di driver — sul chip Intel Haswell di prova, per esempio, il
/// driver i965 fallisce un'asserzione interna sul sottocampionamento e
/// l'allocatore dmabuf VA segnala "driver bug" — e questo può far
/// terminare l'intero processo della webview: la finestra diventa bianca
/// e non arriva nessun errore gestibile a livello applicativo (è il
/// sintomo esatto segnalato su Linux Mint e su CubeOS/Qubes).
///
/// Per evitarlo forziamo la decodifica video *software*: demotiamo a
/// `NONE` gli elementi decoder/post-process VA-API di GStreamer, così la
/// scelta ricade sempre sul decoder software (`avdec_h264` e simili). Non
/// tocchiamo il resto dell'accelerazione (compositing, WebGL, immagini):
/// per i video brevi tipici di un messaggio il costo della decodifica
/// software è trascurabile, e in cambio non si crasha su configurazioni
/// Linux che non possiamo testare una per una. Chi sa di avere una
/// VA-API funzionante può annullare questa scelta impostando da sé la
/// variabile `GST_PLUGIN_FEATURE_RANK` prima di avviare Sigillo.
#[cfg(target_os = "linux")]
fn force_software_video_decoding() {
    if std::env::var_os("GST_PLUGIN_FEATURE_RANK").is_some() {
        // L'utente (o l'ambiente) l'ha già impostata: non la sovrascriviamo.
        return;
    }
    std::env::set_var(
        "GST_PLUGIN_FEATURE_RANK",
        "vah264dec:NONE,vah265dec:NONE,vah264lpdec:NONE,vah265lpdec:NONE,\
         vavp8dec:NONE,vavp9dec:NONE,vaav1dec:NONE,vampeg2dec:NONE,vapostproc:NONE,\
         vaapih264dec:NONE,vaapih265dec:NONE,vaapivp8dec:NONE,vaapivp9dec:NONE,\
         vaapiav1dec:NONE,vaapimpeg2dec:NONE,vaapipostproc:NONE,vaapidecodebin:NONE",
    );
    eprintln!(
        "[sigillo] Linux: decodifica video hardware (VA-API) disattivata nella webview, \
         si userà la decodifica software (imposta GST_PLUGIN_FEATURE_RANK per annullare)"
    );
}

#[cfg(not(target_os = "linux"))]
fn force_software_video_decoding() {}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Va fatto prima che WebKitGTK/GStreamer vengano inizializzati (cioè
    // prima di costruire la webview): a quel punto la variabile è già nel
    // processo e viene letta durante la scansione del registry di GStreamer.
    force_software_video_decoding();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .setup(|app| {
            // Eventuali allegati decifrati rimasti da una sessione
            // interrotta (chiusura forzata, crash, spegnimento).
            if let Ok(store) = attachment_store(app.handle()) {
                store.purge();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            identity_exists_on_disk,
            app_version,
            generate_identity,
            import_identity,
            import_identity_external,
            confirm_seed_words,
            save_identity_to_disk,
            unlock_identity,
            set_active_identity,
            remove_identity_from_disk,
            load_contacts,
            add_contact,
            update_contact,
            my_technical_details,
            contact_technical_details,
            export_private_key_file,
            get_image_format,
            set_image_format,
            get_app_settings,
            set_experimental_features_enabled,
            set_tor_settings,
            check_block_height,
            encrypt_message,
            attachment_info,
            encrypt_attachment,
            encrypt_combined,
            encrypt_timelocked,
            decrypt_message,
            decrypt_file,
            save_decrypted_attachment,
            open_decrypted_attachment,
            discard_decrypted_attachment,
        ])
        .build(tauri::generate_context!())
        .expect("errore durante l'avvio di Sigillo")
        .run(|app, event| {
            // Alla chiusura dell'app nessun allegato decifrato (in chiaro)
            // deve restare sul disco.
            if let tauri::RunEvent::Exit = event {
                if let Ok(store) = attachment_store(app) {
                    store.purge();
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Decifratura con piu' identita' ----------

    fn text_consumer() -> impl FnMut(&mut dyn std::io::Read, &dyn Fn() -> Option<String>) -> anyhow::Result<String> {
        |plain, _name| {
            let mut out = String::new();
            std::io::Read::read_to_string(plain, &mut out)?;
            Ok(out)
        }
    }

    fn text_input<'a>(armored: &'a str) -> impl Fn() -> Result<CipherInput<'a>, String> + 'a {
        move || Ok(Box::new(std::io::Cursor::new(armored.as_bytes())) as CipherInput<'a>)
    }

    #[test]
    fn decrypt_tries_every_identity_until_one_matches() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let carol = identity::generate(identity::SeedWordCount::Twelve, "Carol").unwrap();

        // Il mittente cifra per Carol, che sul dispositivo e' la TERZA
        // identita' (non quella "attiva"/prima in elenco): deve comunque
        // riuscire a decifrare, provando le identita' una per una.
        let ciphertext =
            message::encrypt(&alice.cert, &[carol.cert.clone()], "solo per Carol", false).unwrap();

        let certs = vec![alice.cert.clone(), bob.cert.clone(), carol.cert.clone()];
        let mut rollbacks = 0;
        let outcome = decrypt_streaming_with_any_cert(
            &certs,
            &[],
            &text_input(&ciphertext),
            &mut text_consumer(),
            &mut || rollbacks += 1,
        )
        .unwrap();
        assert_eq!(outcome.value, "solo per Carol");
        assert_eq!(rollbacks, 2, "le due identita' sbagliate vanno scartate");
    }

    #[test]
    fn decrypt_fails_clearly_when_no_identity_matches() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let mallory = identity::generate(identity::SeedWordCount::Twelve, "Mallory").unwrap();

        let ciphertext =
            message::encrypt(&alice.cert, &[bob.cert.clone()], "solo per Bob", false).unwrap();

        // Sul dispositivo c'e' solo Mallory: nessuna identita' corrisponde.
        let err = match decrypt_streaming_with_any_cert(
            &[mallory.cert.clone()],
            &[],
            &text_input(&ciphertext),
            &mut text_consumer(),
            &mut || {},
        ) {
            Ok(_) => panic!("doveva fallire"),
            Err(e) => e,
        };
        assert!(err.contains("non è indirizzato a te"), "{err}");
    }

    #[test]
    fn decrypt_reports_missing_identity_when_none_loaded() {
        let err = match decrypt_streaming_with_any_cert(
            &[],
            &[],
            &text_input("qualunque cosa"),
            &mut text_consumer(),
            &mut || {},
        ) {
            Ok(_) => panic!("doveva fallire"),
            Err(e) => e,
        };
        assert!(err.contains("genera o importa"));
    }

    #[test]
    fn a_damaged_message_is_not_reported_as_addressed_to_someone_else() {
        // Con piu' identita', l'errore utile ("danneggiato") non deve
        // essere coperto da quello generico delle identita' sbagliate.
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let carol = identity::generate(identity::SeedWordCount::Twelve, "Carol").unwrap();
        let mut sink = Vec::new();
        message::encrypt_to_writer(&alice.cert, &[bob.cert.clone()], Some("x.bin"), false, false, &mut sink, |w| {
            std::io::Write::write_all(w, &vec![7u8; 50_000])?;
            Ok(())
        })
        .unwrap();
        let mid = sink.len() / 2;
        sink[mid] ^= 1;

        let certs = vec![bob.cert.clone(), carol.cert.clone()];
        let err = match decrypt_streaming_with_any_cert(
            &certs,
            &[],
            &|| Ok(Box::new(std::io::Cursor::new(sink.clone())) as CipherInput<'_>),
            &mut |plain, _| {
                let mut v = Vec::new();
                std::io::Read::read_to_end(plain, &mut v)?;
                Ok(v)
            },
            &mut || {},
        ) {
            Ok(_) => panic!("un messaggio manomesso non deve decifrarsi"),
            Err(e) => e,
        };
        assert!(!err.contains("non è indirizzato a te"), "{err}");
    }

    // ---------- Allegati generici: cifratura -> decifratura, di punta a punta ----------
    //
    // Gli stessi passaggi dei comandi (encrypt_payload_to_file,
    // decrypt_streaming_with_any_cert, process_plaintext), con file veri su
    // disco e cifratura vera, meno il solo collante di Tauri (AppHandle,
    // impostazioni, finestra).

    fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    fn write_source(dir: &std::path::Path, name: &str, content: &[u8]) -> SourceFile {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        open_source_file(path.to_str().unwrap()).unwrap()
    }

    /// Cifra `file` (+ `text`) per `recipient` come fa il comando
    /// corrispondente, e restituisce il percorso del file cifrato.
    fn encrypt_like_the_commands(
        dir: &std::path::Path,
        sender: &identity::Identity,
        recipient: &identity::Identity,
        text: Option<&str>,
        file: &SourceFile,
        sign: bool,
        armor: bool,
        timelock_height: Option<u32>,
    ) -> PathBuf {
        let output = dir.join(format!("{}.cifrato", file.info.name));
        let recipients = [recipient.cert.clone()];
        let out = output.to_str().unwrap();

        let (prefix, literal_name) = match (text, timelock_height) {
            // Solo allegato: nome nel pacchetto OpenPGP, nessun contenitore.
            (None, None) => (Vec::new(), Some(file.info.name.as_str())),
            (Some(text), None) => (
                sigillo_core::composite::encode_header(text, Some(&file.info.name), &file.info.mime, file.info.size).unwrap(),
                None,
            ),
            (text, Some(height)) => {
                let inner = sigillo_core::composite::encode_header(
                    text.unwrap_or(""),
                    Some(&file.info.name),
                    &file.info.mime,
                    file.info.size,
                )
                .unwrap();
                let mut prefix = sigillo_core::timelock::encode_header(height, None, inner.len() as u64 + file.info.size).unwrap();
                prefix.extend_from_slice(&inner);
                (prefix, None)
            }
        };
        encrypt_payload_to_file(&sender.cert, &recipients, sign, armor, out, literal_name, &prefix, Some(file)).unwrap();
        assert!(!std::path::Path::new(&format!("{out}.parte")).exists(), "il file provvisorio non deve restare");
        output
    }

    fn decrypt_like_the_commands(
        store: &attachments::AttachmentStore,
        recipient: &identity::Identity,
        contacts: &[Cert],
        cipher_path: &std::path::Path,
        experimental: bool,
        fetch: &dyn Fn(&str, bool) -> Result<u32, String>,
    ) -> Result<message::StreamOutcome<attachments::Processed>, String> {
        let mut settings = settings::Settings::default();
        settings.experimental_features_enabled = experimental;
        let session = attachments::Session::new(store);
        let path = cipher_path.to_str().unwrap().to_string();
        let source = CipherSource::File(&path);
        let outcome = decrypt_streaming_with_any_cert(
            &[recipient.cert.clone()],
            contacts,
            &|| open_cipher_input(&source),
            &mut |plain, name| attachments::process_plaintext(plain, name, &settings, &session, fetch),
            &mut || session.rollback(),
        )?;
        session.commit();
        Ok(outcome)
    }

    fn no_network(_: &str, _: bool) -> Result<u32, String> {
        panic!("nessuna verifica di rete attesa")
    }

    #[test]
    fn every_kind_of_file_round_trips_with_name_size_and_bytes_intact() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = attachments::AttachmentStore::new(dir.path().join("cache").join("anteprime"));

        let zip = |n| [b"PK\x03\x04".to_vec(), pseudo_random_bytes(n, n as u64)].concat();
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("relazione piccola.pdf", [b"%PDF-1.7\n".to_vec(), pseudo_random_bytes(20_000, 1)].concat(), "pdf"),
            ("relazione grande.pdf", [b"%PDF-1.7\n".to_vec(), pseudo_random_bytes(6_000_000, 2)].concat(), "pdf"),
            ("lettera.docx", zip(150_000), "documento"),
            ("bilancio.xlsx", zip(90_000), "foglio"),
            ("slide.pptx", zip(300_000), "presentazione"),
            ("lettera.odt", zip(40_000), "documento"),
            ("note.txt", "prima riga\nseconda riga, è accentata\n".as_bytes().to_vec(), "testo"),
            ("tabella.csv", "a;b;c\n1;2;3\n".as_bytes().to_vec(), "foglio"),
            ("archivio.zip", zip(700_000), "archivio"),
            ("canzone.mp3", [b"ID3\x03".to_vec(), pseudo_random_bytes(500_000, 3)].concat(), "audio"),
            ("dati.xyz", pseudo_random_bytes(5_000, 4), "generico"),
            ("senza_estensione", pseudo_random_bytes(300, 5), "generico"),
            ("vuoto.bin", Vec::new(), "generico"),
        ];

        for (name, content, category) in &cases {
            let file = write_source(dir.path(), name, content);
            for (text, sign, armor) in [(None, false, true), (None, true, false), (Some("Con un messaggio"), false, true), (Some("Firmato"), true, false)] {
                let cipher = encrypt_like_the_commands(dir.path(), &alice, &bob, text, &file, sign, armor, None);
                let alice_public = alice.cert.clone().strip_secret_key_material();
                let outcome = decrypt_like_the_commands(&store, &bob, &[alice_public], &cipher, false, &no_network).unwrap();

                let processed = outcome.value;
                let att = processed.attachment.unwrap_or_else(|| panic!("{name}: nessun allegato"));
                assert_eq!(att.name, *name, "{name}: nome originale");
                assert_eq!(att.size, content.len() as u64, "{name}: dimensione");
                assert_eq!(att.category, *category, "{name}: tipo");
                assert_eq!(std::fs::read(&att.path).unwrap(), *content, "{name}: contenuto");
                match text {
                    None => assert_eq!(processed.kind, "allegato", "{name}"),
                    Some(t) => {
                        assert_eq!(processed.kind, "combinato", "{name}");
                        assert_eq!(processed.plaintext.as_deref(), Some(t));
                    }
                }
                assert_eq!(
                    matches!(outcome.signature, message::SignatureStatus::Verified(_)),
                    sign,
                    "{name}: firma"
                );
            }
        }
    }

    #[test]
    fn an_attachment_only_message_is_a_plain_openpgp_file_with_its_name() {
        // Interoperabilita': un file allegato da solo si decifra anche con
        // un altro programma OpenPGP e ritorna il file originale (qui lo
        // simuliamo con la decifratura "tutta in memoria" di Sigillo).
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let content = [b"%PDF-1.7\n".to_vec(), pseudo_random_bytes(10_000, 9)].concat();
        let file = write_source(dir.path(), "contratto.pdf", &content);
        let cipher = encrypt_like_the_commands(dir.path(), &alice, &bob, None, &file, false, true, None);

        let decrypted = message::decrypt_bytes(&bob.cert, &[], &std::fs::read(cipher).unwrap()).unwrap();
        assert_eq!(decrypted.data, content, "nessun contenitore Sigillo attorno al file");
        assert_eq!(decrypted.filename.as_deref(), Some("contratto.pdf"));
    }

    #[test]
    fn a_hostile_name_inside_an_encrypted_message_cannot_escape_the_private_folder() {
        // Un mittente malevolo costruisce un messaggio vero, cifrato per
        // noi, con un nome file ostile nel contenitore e nel pacchetto.
        let mallory = identity::generate(identity::SeedWordCount::Twelve, "Mallory").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = attachments::AttachmentStore::new(dir.path().join("cache").join("anteprime"));

        for hostile in ["../../fuga.txt", "..\\..\\fuga.txt", "/etc/passwd", "a/../../b.exe", "nul\0.pdf", "\u{202E}fdp.exe"] {
            for in_container in [true, false] {
                let body = [b"%PDF-1.7\n".to_vec(), vec![1; 100]].concat();
                let mut cipher = Vec::new();
                message::encrypt_to_writer(
                    &mallory.cert,
                    &[bob.cert.clone()],
                    if in_container { None } else { Some(hostile) },
                    false,
                    false,
                    &mut cipher,
                    |w| {
                        if in_container {
                            w.write_all(&sigillo_core::composite::encode("", Some(hostile), "application/pdf", &body).unwrap())?;
                        } else {
                            w.write_all(&body)?;
                        }
                        Ok(())
                    },
                )
                .or_else(|e| if in_container { Err(e) } else { Ok(()) })
                .unwrap();
                if cipher.is_empty() {
                    continue; // il nome ostile non e' nemmeno ammesso nel pacchetto OpenPGP
                }
                let path = dir.path().join("ostile.gpg");
                std::fs::write(&path, &cipher).unwrap();
                let outcome = decrypt_like_the_commands(&store, &bob, &[], &path, false, &no_network).unwrap();
                let att = outcome.value.attachment.unwrap();
                assert!(store.owns(std::path::Path::new(&att.path)), "{hostile:?}: file fuori dalla cartella privata");
                assert!(!att.name.contains('/') && !att.name.contains('\\') && !att.name.contains(".."), "{hostile:?} -> {:?}", att.name);
            }
        }
        // Fuori dalla cartella privata non e' comparso nulla.
        let siblings: Vec<_> = std::fs::read_dir(dir.path().join("cache")).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(siblings, vec![std::ffi::OsString::from("anteprime")]);
        assert!(!dir.path().join("fuga.txt").exists());
    }

    #[test]
    fn messages_made_by_the_previous_versions_still_decrypt() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = attachments::AttachmentStore::new(dir.path().join("anteprime"));
        let jpeg = [vec![0xFF, 0xD8, 0xFF, 0xE0], pseudo_random_bytes(3000, 7)].concat();
        let mut mp4 = vec![0u8; 4];
        mp4.extend_from_slice(b"ftypisom\0\0\0\0");
        mp4.extend_from_slice(&pseudo_random_bytes(4000, 8));

        // Cosa produceva v0.5: testo puro, immagine sola (nome nel pacchetto),
        // video solo, testo + immagine (contenitore), testo + video.
        let old_messages: Vec<(Vec<u8>, Option<&str>, &str, Option<&str>)> = vec![
            ("testo di una volta".as_bytes().to_vec(), None, "testo", Some("testo di una volta")),
            (jpeg.clone(), Some("foto.jpg"), "allegato", None),
            (mp4.clone(), Some("clip.mp4"), "allegato", None),
            (sigillo_core::composite::encode("guarda", Some("foto.jpg"), "image/jpeg", &jpeg).unwrap(), None, "combinato", Some("guarda")),
            (sigillo_core::composite::encode("e un video", Some("clip.mov"), "video/quicktime", &mp4).unwrap(), None, "combinato", Some("e un video")),
        ];
        for (index, (plain, name, kind, text)) in old_messages.iter().enumerate() {
            for armor in [true, false] {
                let bytes = message::encrypt_bytes(&alice.cert, &[bob.cert.clone()], plain, *name, false, armor).unwrap();
                let path = dir.path().join(format!("vecchio-{index}-{armor}"));
                std::fs::write(&path, bytes).unwrap();
                let outcome = decrypt_like_the_commands(&store, &bob, &[], &path, false, &no_network).unwrap();
                assert_eq!(outcome.value.kind, *kind, "messaggio {index}");
                assert_eq!(outcome.value.plaintext.as_deref(), *text, "messaggio {index}");
                if let Some(att) = &outcome.value.attachment {
                    let content = if index == 1 || index == 3 { &jpeg } else { &mp4 };
                    assert_eq!(&std::fs::read(&att.path).unwrap(), content, "messaggio {index}");
                }
            }
        }
    }

    #[test]
    fn a_tampered_or_truncated_message_never_leaves_decrypted_files_behind() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = attachments::AttachmentStore::new(dir.path().join("anteprime"));
        let file = write_source(dir.path(), "segreto.pdf", &[b"%PDF-1.7\n".to_vec(), pseudo_random_bytes(400_000, 3)].concat());
        let cipher = encrypt_like_the_commands(dir.path(), &alice, &bob, Some("testo"), &file, false, false, None);
        let good = std::fs::read(&cipher).unwrap();

        let mut tampered = good.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        let truncated = good[..good.len() / 2].to_vec();

        for (label, bytes) in [("manomesso", tampered), ("troncato", truncated)] {
            let path = dir.path().join(format!("{label}.gpg"));
            std::fs::write(&path, bytes).unwrap();
            assert!(
                decrypt_like_the_commands(&store, &bob, &[], &path, false, &no_network).is_err(),
                "{label}: non deve risultare valido"
            );
            let left = std::fs::read_dir(store.root()).map(|d| d.count()).unwrap_or(0);
            assert_eq!(left, 0, "{label}: nessun file decifrato deve restare");
        }
    }

    #[test]
    fn a_timelocked_attachment_stays_off_the_disk_until_the_height_is_reached() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = attachments::AttachmentStore::new(dir.path().join("anteprime"));
        let content = [b"%PDF-1.7\n".to_vec(), pseudo_random_bytes(50_000, 1)].concat();
        let file = write_source(dir.path(), "piano.pdf", &content);
        let cipher = encrypt_like_the_commands(dir.path(), &alice, &bob, Some("apri dopo"), &file, false, true, Some(900_000));

        // Altezza non raggiunta: nessun contenuto, niente su disco.
        let locked = decrypt_like_the_commands(&store, &bob, &[], &cipher, true, &|_, _| Ok(899_999)).unwrap().value;
        assert_eq!(locked.kind, "bloccato_nel_tempo");
        assert_eq!((locked.target_height, locked.current_height), (Some(900_000), Some(899_999)));
        assert!(locked.attachment.is_none() && locked.plaintext.is_none());
        assert!(!store.root().exists());

        // Funzioni sperimentali spente: nessuna richiesta di rete (no_network
        // fa fallire il test se parte), il contenuto resta un dato opaco.
        let opaque = decrypt_like_the_commands(&store, &bob, &[], &cipher, false, &no_network).unwrap().value;
        assert_ne!(opaque.kind, "bloccato_nel_tempo");

        // Altezza raggiunta: compaiono testo e allegato, identico all'originale.
        let unlocked = decrypt_like_the_commands(&store, &bob, &[], &cipher, true, &|_, _| Ok(900_000)).unwrap().value;
        assert_eq!(unlocked.kind, "combinato");
        assert_eq!(unlocked.plaintext.as_deref(), Some("apri dopo"));
        let att = unlocked.attachment.unwrap();
        assert_eq!(att.name, "piano.pdf");
        assert_eq!(std::fs::read(att.path).unwrap(), content);
    }

    #[test]
    fn a_vanished_source_file_does_not_leave_a_half_written_encrypted_file() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = write_source(dir.path(), "sparisce.pdf", b"%PDF-1.7 corpo");
        std::fs::remove_file(&file.path).unwrap();

        let output = dir.path().join("risultato.asc");
        let err = encrypt_payload_to_file(
            &alice.cert,
            &[bob.cert.clone()],
            false,
            true,
            output.to_str().unwrap(),
            Some("sparisce.pdf"),
            &[],
            Some(&file),
        )
        .unwrap_err();
        assert!(!err.is_empty());
        assert!(!output.exists(), "il file di destinazione non va creato");
        assert!(!dir.path().join("risultato.asc.parte").exists(), "il provvisorio va rimosso");
    }

    #[test]
    fn encrypting_over_an_existing_file_replaces_it_only_on_success() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("esistente.asc");
        std::fs::write(&output, b"versione precedente").unwrap();

        // Un tentativo che fallisce (file mancante) lascia intatto il vecchio.
        let missing = SourceFile {
            path: dir.path().join("non-esiste.pdf"),
            info: attachments::AttachmentInfo {
                name: "non-esiste.pdf".into(),
                size: 10,
                mime: "application/pdf".into(),
                category: "pdf".into(),
                dangerous: false,
                too_large: false,
            },
        };
        assert!(encrypt_payload_to_file(&alice.cert, &[bob.cert.clone()], false, true, output.to_str().unwrap(), Some("x.pdf"), &[], Some(&missing)).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"versione precedente");
    }

    // ---------- Time-lock ----------

    #[test]
    fn effective_endpoint_falls_back_to_default_when_no_custom_one() {
        assert_eq!(effective_endpoint(None), DEFAULT_TIMELOCK_ENDPOINT);
        assert_eq!(effective_endpoint(Some("   ")), DEFAULT_TIMELOCK_ENDPOINT);
        assert_eq!(effective_endpoint(Some("https://mio-nodo.esempio/altezza")), "https://mio-nodo.esempio/altezza");
    }

    #[test]
    fn should_use_tor_is_false_by_default_for_a_normal_endpoint() {
        // Requisito chiave: col toggle Tor spento e un endpoint normale,
        // non deve mai risultare necessario un client Tor.
        assert!(!should_use_tor(DEFAULT_TIMELOCK_ENDPOINT, false));
    }

    #[test]
    fn should_use_tor_is_true_when_the_local_toggle_is_on() {
        assert!(should_use_tor(DEFAULT_TIMELOCK_ENDPOINT, true));
    }

    #[test]
    fn should_use_tor_is_forced_true_for_an_onion_endpoint_even_if_toggle_is_off() {
        assert!(should_use_tor("http://esempio1234.onion/altezza", false));
    }

    /// Avvia un piccolo server HTTP locale (nessuna libreria esterna,
    /// solo std) che risponde una volta con `body`, per testare il
    /// parsing di fetch_block_height senza toccare la rete reale.
    fn spawn_test_http_server(body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/")
    }

    #[test]
    fn fetch_block_height_parses_a_plain_number_response() {
        let endpoint = spawn_test_http_server("912345");
        let height = fetch_block_height(&endpoint, false, "127.0.0.1", 9050).unwrap();
        assert_eq!(height, 912_345);
    }

    #[test]
    fn fetch_block_height_trims_surrounding_whitespace() {
        let endpoint = spawn_test_http_server("  912345\n");
        let height = fetch_block_height(&endpoint, false, "127.0.0.1", 9050).unwrap();
        assert_eq!(height, 912_345);
    }

    #[test]
    fn fetch_block_height_reports_non_numeric_response_clearly() {
        let endpoint = spawn_test_http_server("<html>non e' un numero</html>");
        let err = fetch_block_height(&endpoint, false, "127.0.0.1", 9050).unwrap_err();
        assert!(err.contains("non valida"));
    }

    #[test]
    fn fetch_block_height_reports_unreachable_endpoint_clearly() {
        // Nessun server in ascolto su questa porta: deve fallire con un
        // messaggio comprensibile, non andare in panico.
        let err = fetch_block_height("http://127.0.0.1:1/", false, "127.0.0.1", 9050).unwrap_err();
        assert!(err.contains("impossibile raggiungere"));
    }

    // Regressione: il bug segnalato era un timeout troppo aggressivo
    // (20s totali) per un demone Tor "a freddo" (es. la porta standalone
    // 9050 di `brew services start tor`, senza circuiti gia' pronti),
    // mentre un Tor Browser gia' aperto (9150) ha circuiti pronti e
    // maschera il problema rispondendo piu' in fretta. I timeout ora
    // sono nettamente piu' generosi per il percorso Tor.
    #[test]
    fn tor_timeouts_are_generous_enough_for_a_cold_circuit() {
        // Osservato empiricamente (vedi commento sulle costanti): la
        // stessa richiesta, verso lo stesso demone, puo' impiegare da
        // pochi secondi a oltre un minuto a seconda del momento.
        assert!(
            TOR_CONNECT_TIMEOUT_SECS >= 75,
            "il timeout di connessione per Tor e' di nuovo troppo aggressivo per un circuito a freddo"
        );
        assert!(
            TOR_TOTAL_TIMEOUT_SECS >= 100,
            "il timeout totale per Tor e' di nuovo troppo aggressivo per un circuito a freddo"
        );
    }

    // Solo Unix: verso una porta di loopback chiusa, Unix risponde con un
    // rifiuto immediato (ECONNREFUSED -> reqwest is_connect()), mentre
    // Windows lascia scadere il connect_timeout e lo classifica come
    // TimedOut (is_timeout()). Su Windows quello scenario non è più un
    // "rifiuto" distinguibile da un timeout, quindi il test non si applica.
    #[cfg(unix)]
    #[test]
    fn fetch_block_height_reports_connect_refused_through_tor_distinctly() {
        // Nessun proxy in ascolto su questa porta: deve dire chiaramente
        // di verificare che un client Tor sia davvero in ascolto,
        // non un messaggio generico o "timeout".
        let err = fetch_block_height_with_timeouts(
            DEFAULT_TIMELOCK_ENDPOINT,
            true,
            "127.0.0.1",
            1,
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(err.contains("impossibile connettersi al proxy Tor"));
    }

    #[test]
    #[ignore = "richiede un vero demone Tor standalone in ascolto su 127.0.0.1:9050 (es. `brew services start tor`), non adatto alla CI: esegui con `cargo test -- --ignored`"]
    fn fetch_block_height_works_against_a_real_standalone_tor_daemon_on_9050() {
        // Riproduce esattamente lo scenario segnalato: un demone Tor
        // standalone (non Tor Browser) sulla sua porta di default 9050,
        // verso il vero endpoint pubblico di produzione.
        let height = fetch_block_height(DEFAULT_TIMELOCK_ENDPOINT, true, "127.0.0.1", 9050)
            .expect("la richiesta verso mempool.space tramite Tor (porta 9050) deve riuscire");
        assert!(height > 900_000, "altezza blocco implausibile: {height}");
    }

    #[test]
    fn fetch_block_height_reports_slow_tor_circuit_as_timeout_not_connect_refused() {
        // Un "proxy" che accetta la connessione TCP ma non risponde mai
        // simula un circuito Tor lento a formarsi: il messaggio deve
        // parlare di timeout/circuito lento, non di "nessun servizio in
        // ascolto" (che varrebbe solo per un rifiuto immediato).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(std::time::Duration::from_secs(5));
                drop(stream);
            }
        });

        let err = fetch_block_height_with_timeouts(
            DEFAULT_TIMELOCK_ENDPOINT,
            true,
            "127.0.0.1",
            addr.port(),
            std::time::Duration::from_millis(300),
            std::time::Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(
            err.contains("non ha risposto in tempo"),
            "messaggio inatteso per un circuito lento: {err}"
        );
    }

    // ---------- Time-lock: privacy / SSRF alla decifratura ----------

    // I test del comportamento a funzioni sperimentali spente / con endpoint
    // non ammessi, e dell'interpretazione dei contenuti decifrati, sono in
    // `attachments.rs`: li' la verifica dell'altezza blocco e' iniettata e
    // un test fallisce se parte una richiesta di rete che non doveva partire.

    #[test]
    fn validate_sender_supplied_endpoint_accepts_only_safe_public_https() {
        // Ammessi: https verso un nome di dominio, e http SOLO per .onion.
        assert!(
            validate_sender_supplied_endpoint("https://mempool.space/api/blocks/tip/height").is_ok()
        );
        assert!(
            validate_sender_supplied_endpoint("https://mempool.mio-nodo.example/altezza").is_ok()
        );
        assert!(validate_sender_supplied_endpoint(
            "http://mempoolhqx4vs3tuk7mba5xpwmb2fzezvqm3vza3nnf5tz43yzysfid.onion/api/blocks/tip/height"
        )
        .is_ok());

        // In chiaro verso un host non-onion: rivelerebbe l'apertura.
        assert!(validate_sender_supplied_endpoint("http://mempool.space/altezza").is_err());
        // IP letterali (SSRF verso rete interna / metadati cloud / loopback).
        assert!(validate_sender_supplied_endpoint("https://127.0.0.1/altezza").is_err());
        assert!(validate_sender_supplied_endpoint("https://[::1]/altezza").is_err());
        assert!(
            validate_sender_supplied_endpoint("https://169.254.169.254/latest/meta-data/").is_err()
        );
        assert!(validate_sender_supplied_endpoint("https://10.0.0.5:8332/altezza").is_err());
        // localhost per nome.
        assert!(validate_sender_supplied_endpoint("https://localhost/altezza").is_err());
        assert!(validate_sender_supplied_endpoint("https://api.localhost/altezza").is_err());
        // Schemi non http(s) e input non-URL.
        assert!(validate_sender_supplied_endpoint("ftp://mempool.space/altezza").is_err());
        assert!(validate_sender_supplied_endpoint("file:///etc/passwd").is_err());
        assert!(validate_sender_supplied_endpoint("non è un url").is_err());
    }
}
