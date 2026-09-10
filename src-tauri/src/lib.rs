use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
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
    sender_index: Option<usize>,
) -> Result<(), String> {
    let id = identity_by_index_or_active(&state, sender_index)?;
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
    sender_index: Option<usize>,
) -> Result<(), String> {
    let id = identity_by_index_or_active(&state, sender_index)?;
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

/// Cifra un messaggio (testo, e/o un'immagine o video) con un blocco
/// temporale applicativo: il testo e l'eventuale allegato vengono prima
/// impacchettati esattamente come in [`encrypt_combined`], poi avvolti
/// da [`sigillo_core::timelock::encode`] con l'altezza blocco target e
/// l'endpoint di verifica scelto (che finisce nei metadati del
/// messaggio, cosi' anche chi lo riceve verifica con lo stesso
/// endpoint), infine cifrati normalmente: il vincolo e' applicativo
/// (lo fa rispettare l'interfaccia di Sigillo), non crittografico — chi
/// ha la chiave privata giusta puo' comunque decifrare il pacchetto
/// OpenPGP in ogni momento, e' solo il contenuto a restare "nascosto"
/// dall'app finche' l'altezza non e' raggiunta.
#[tauri::command]
fn encrypt_timelocked(
    app: AppHandle,
    state: State<AppState>,
    recipients_armored: Vec<String>,
    plaintext: String,
    source_path: Option<String>,
    output_path: String,
    sign: bool,
    sender_index: Option<usize>,
    target_height: u32,
    custom_endpoint: Option<String>,
) -> Result<(), String> {
    let id = identity_by_index_or_active(&state, sender_index)?;
    let recipients = recipients_from_armored(&recipients_armored)?;

    let inner: Vec<u8> = match &source_path {
        Some(source_path) => {
            let media_data = std::fs::read(source_path)
                .map_err(|e| format!("impossibile leggere il file: {e}"))?;
            let media_filename = std::path::Path::new(source_path)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned());
            let media_mime =
                detect_media_mime(&media_data).ok_or("formato immagine o video non riconosciuto")?;
            sigillo_core::composite::encode(&plaintext, media_filename.as_deref(), media_mime, &media_data)
        }
        None => plaintext.into_bytes(),
    };

    let endpoint = custom_endpoint.filter(|e| !e.trim().is_empty());
    let locked = sigillo_core::timelock::encode(target_height, endpoint.as_deref(), &inner);

    let format = settings::load_image_format(&settings_path(&app)?).map_err(|e| e.to_string())?;
    let armor = format == settings::ImageFormat::Asc;

    let ciphertext = message::encrypt_bytes(&id.cert, &recipients, &locked, None, sign, armor)
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
    // GIF (sia la variante storica "87a" sia "89a", quella con
    // animazione): la mostra un normale tag <img>, che anima da solo.
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
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
    /// "testo", "immagine", "video", "combinato" (testo + immagine/video),
    /// "bloccato_nel_tempo" (funzione sperimentale, altezza target non
    /// ancora raggiunta) o "file" (contenuto binario non riconosciuto).
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
    /// Solo per un messaggio con blocco temporale (bloccato o appena
    /// sbloccato): l'altezza target.
    target_height: Option<u32>,
    /// Solo per "bloccato_nel_tempo": l'altezza corrente, se la
    /// verifica è riuscita.
    current_height: Option<u32>,
    /// Solo per "bloccato_nel_tempo": presente se la verifica
    /// dell'altezza corrente è fallita (rete assente, endpoint non
    /// raggiungibile...), invece di current_height.
    height_check_error: Option<String>,
}

/// Come [`build_decrypt_view_inner`], ma riconosce prima di tutto un
/// eventuale blocco temporale (funzione sperimentale): se presente,
/// verifica l'altezza blocco corrente (secondo le preferenze Tor/
/// endpoint salvate) e mostra il contenuto solo se l'altezza target è
/// già stata raggiunta, altrimenti quanto manca.
fn build_decrypt_view(
    data: Vec<u8>,
    filename: Option<String>,
    signature: message::SignatureStatus,
    settings: &settings::Settings,
) -> DecryptView {
    let (signature_status, signer_fingerprint) = match signature {
        message::SignatureStatus::Unsigned => ("non_firmato".to_string(), None),
        message::SignatureStatus::Verified(fp) => {
            ("verificata".to_string(), Some(fp.to_spaced_hex()))
        }
        message::SignatureStatus::Unverifiable => ("non_verificabile".to_string(), None),
    };

    // Il blocco temporale è una funzione *sperimentale*: finché l'utente
    // non l'ha attivata esplicitamente (default: spenta), un messaggio
    // marcato come "bloccato nel tempo" NON deve essere processato come
    // tale — in particolare non deve far partire la verifica dell'altezza
    // blocco, che è una richiesta di rete verso un endpoint indicato
    // *dentro* il messaggio dal mittente. Senza questo controllo, aprire
    // un messaggio ostile equivarrebbe a un "tracking pixel" (rivela IP e
    // orario di apertura a chi l'ha mandato) e a un possibile SSRF verso
    // risorse di rete interne, del tutto all'insaputa di chi non ha mai
    // toccato le funzioni sperimentali. A feature spenta lo trattiamo
    // quindi come un dato binario opaco (salvabile come file).
    if settings.experimental_features_enabled && sigillo_core::timelock::is_timelocked(&data) {
        if let Ok(locked) = sigillo_core::timelock::decode(&data) {
            // Un endpoint incluso nel messaggio è scelto dal mittente, non
            // da chi riceve: prima di contattarlo va ristretto (solo https,
            // niente IP letterali o localhost — vedi la funzione).
            if let Some(sender_endpoint) = locked
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
            {
                if let Err(why) = validate_sender_supplied_endpoint(sender_endpoint) {
                    return DecryptView {
                        kind: "bloccato_nel_tempo".to_string(),
                        plaintext: None,
                        image_data_base64: None,
                        image_mime: None,
                        media_temp_path: None,
                        filename,
                        signature_status,
                        signer_fingerprint,
                        target_height: Some(locked.target_height),
                        current_height: None,
                        height_check_error: Some(why),
                    };
                }
            }

            let endpoint = effective_endpoint(locked.endpoint.as_deref());
            let use_tor = should_use_tor(&endpoint, settings.tor_enabled);
            match fetch_block_height(&endpoint, use_tor, &settings.tor_socks_host, settings.tor_socks_port) {
                Ok(current) if current >= locked.target_height => {
                    // Altezza raggiunta: si mostra il contenuto interno
                    // come al solito, con in più l'indicazione che era
                    // (ed è ora) sbloccato.
                    let mut view = build_decrypt_view_inner(
                        locked.inner,
                        filename,
                        signature_status,
                        signer_fingerprint,
                    );
                    view.target_height = Some(locked.target_height);
                    view.current_height = Some(current);
                    return view;
                }
                Ok(current) => {
                    return DecryptView {
                        kind: "bloccato_nel_tempo".to_string(),
                        plaintext: None,
                        image_data_base64: None,
                        image_mime: None,
                        media_temp_path: None,
                        filename,
                        signature_status,
                        signer_fingerprint,
                        target_height: Some(locked.target_height),
                        current_height: Some(current),
                        height_check_error: None,
                    };
                }
                Err(height_check_error) => {
                    return DecryptView {
                        kind: "bloccato_nel_tempo".to_string(),
                        plaintext: None,
                        image_data_base64: None,
                        image_mime: None,
                        media_temp_path: None,
                        filename,
                        signature_status,
                        signer_fingerprint,
                        target_height: Some(locked.target_height),
                        current_height: None,
                        height_check_error: Some(height_check_error),
                    };
                }
            }
        }
        // Marcato come bloccato nel tempo ma illeggibile: ripiega sul
        // trattarlo come gli altri casi, invece di far fallire tutto.
    }

    build_decrypt_view_inner(data, filename, signature_status, signer_fingerprint)
}

/// Nucleo di `build_decrypt_view`: riconosce testo/immagine/video/file,
/// assumendo che `data` NON sia (più) un pacchetto con blocco temporale
/// (quello è gestito da `build_decrypt_view`, che chiama questa funzione
/// sia per un messaggio mai bloccato sia per il contenuto interno di
/// uno appena sbloccato).
fn build_decrypt_view_inner(
    data: Vec<u8>,
    filename: Option<String>,
    signature_status: String,
    signer_fingerprint: Option<String>,
) -> DecryptView {
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
                target_height: None,
                current_height: None,
                height_check_error: None,
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
            target_height: None,
            current_height: None,
            height_check_error: None,
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
            target_height: None,
            current_height: None,
            height_check_error: None,
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
        target_height: None,
        current_height: None,
        height_check_error: None,
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
/// Prova a decifrare `input` con ciascuna delle identità disponibili sul
/// dispositivo, non solo quella attiva: un messaggio in arrivo potrebbe
/// essere indirizzato a una qualsiasi delle identità dell'utente, non
/// necessariamente quella scelta l'ultima volta in "La mia identità".
/// Nucleo di `decrypt_with_any_identity`, separato per poter essere
/// testato senza dover costruire un `State<AppState>` (che richiede il
/// runtime di Tauri): prova `certs` uno per uno, nell'ordine dato,
/// finché uno non riesce a decifrare `input`.
fn decrypt_with_any_cert(
    certs: &[Cert],
    contacts_certs: &[Cert],
    input: &[u8],
) -> Result<message::DecryptedBytes, String> {
    if certs.is_empty() {
        return Err("genera o importa prima la tua identità".to_string());
    }

    let mut last_err = None;
    for cert in certs {
        match message::decrypt_bytes(cert, contacts_certs, input) {
            Ok(result) => return Ok(result),
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(last_err.unwrap_or_else(|| "impossibile decifrare il messaggio".to_string()))
}

fn decrypt_with_any_identity(
    state: &State<AppState>,
    contacts_certs: &[Cert],
    input: &[u8],
) -> Result<message::DecryptedBytes, String> {
    let identities = state.identities.lock().unwrap();
    let certs: Vec<Cert> = identities.iter().map(|li| li.identity.cert.clone()).collect();
    decrypt_with_any_cert(&certs, contacts_certs, input)
}

#[tauri::command]
fn decrypt_message(
    app: AppHandle,
    state: State<AppState>,
    contacts_armored: Vec<String>,
    ciphertext: String,
) -> Result<DecryptView, String> {
    let contacts_certs = recipients_from_armored(&contacts_armored)?;
    let decrypted = decrypt_with_any_identity(&state, &contacts_certs, ciphertext.as_bytes())?;
    let settings = settings::load_settings(&settings_path(&app)?).map_err(|e| e.to_string())?;

    Ok(build_decrypt_view(
        decrypted.data,
        decrypted.filename,
        decrypted.signature,
        &settings,
    ))
}

/// Come [`decrypt_message`], ma leggendo l'input da un file su disco
/// invece che da testo incollato: serve per i file .gpg (binari, non
/// incollabili in una casella di testo).
#[tauri::command]
fn decrypt_file(
    app: AppHandle,
    state: State<AppState>,
    contacts_armored: Vec<String>,
    path: String,
) -> Result<DecryptView, String> {
    let contacts_certs = recipients_from_armored(&contacts_armored)?;

    let input = std::fs::read(&path).map_err(|e| format!("impossibile leggere il file: {e}"))?;
    let decrypted = decrypt_with_any_identity(&state, &contacts_certs, &input)?;
    let settings = settings::load_settings(&settings_path(&app)?).map_err(|e| e.to_string())?;

    Ok(build_decrypt_view(
        decrypted.data,
        decrypted.filename,
        decrypted.signature,
        &settings,
    ))
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

    cleanup_stale_temp_previews();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
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
            encrypt_image,
            encrypt_combined,
            encrypt_timelocked,
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
    fn decrypt_with_any_cert_tries_every_identity_until_one_matches() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let carol = identity::generate(identity::SeedWordCount::Twelve, "Carol").unwrap();

        // Il mittente cifra per Carol, che sul dispositivo e' la TERZA
        // identita' (non quella "attiva"/prima in elenco): deve comunque
        // riuscire a decifrare, provando le identita' una per una.
        let ciphertext =
            message::encrypt(&alice.cert, &[carol.cert.clone()], "solo per Carol", false).unwrap();

        let certs = vec![alice.cert.clone(), bob.cert.clone(), carol.cert.clone()];
        let result = decrypt_with_any_cert(&certs, &[], ciphertext.as_bytes()).unwrap();
        assert_eq!(String::from_utf8(result.data).unwrap(), "solo per Carol");
    }

    #[test]
    fn decrypt_with_any_cert_fails_clearly_when_no_identity_matches() {
        let alice = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let bob = identity::generate(identity::SeedWordCount::Twelve, "Bob").unwrap();
        let mallory = identity::generate(identity::SeedWordCount::Twelve, "Mallory").unwrap();

        let ciphertext =
            message::encrypt(&alice.cert, &[bob.cert.clone()], "solo per Bob", false).unwrap();

        // Sul dispositivo c'e' solo Mallory: nessuna identita' corrisponde.
        let certs = vec![mallory.cert.clone()];
        assert!(decrypt_with_any_cert(&certs, &[], ciphertext.as_bytes()).is_err());
    }

    #[test]
    fn decrypt_with_any_cert_reports_missing_identity_when_none_loaded() {
        let err = decrypt_with_any_cert(&[], &[], b"qualunque cosa").unwrap_err();
        assert!(err.contains("genera o importa"));
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

    fn settings_with_experimental(enabled: bool) -> settings::Settings {
        let mut s = settings::Settings::default();
        s.experimental_features_enabled = enabled;
        s
    }

    /// Il bug: un messaggio marcato come "bloccato nel tempo" faceva
    /// partire una richiesta di rete (verso un endpoint scelto dal
    /// mittente) al solo aprirlo, ANCHE se l'utente non aveva mai
    /// attivato le funzioni sperimentali. A feature spenta il messaggio
    /// deve invece essere trattato come dato opaco, senza toccare la rete.
    #[test]
    fn timelocked_message_is_inert_when_experimental_features_are_off() {
        // Endpoint volutamente "cattivo" (metadati cloud): se il gate non
        // funzionasse, questo test proverebbe a contattarlo.
        let blob = sigillo_core::timelock::encode(
            10_000_000,
            Some("http://169.254.169.254/latest/meta-data/"),
            b"contenuto interno del messaggio bloccato",
        );

        let view = build_decrypt_view(
            blob,
            None,
            message::SignatureStatus::Unsigned,
            &settings_with_experimental(false),
        );

        assert_ne!(
            view.kind, "bloccato_nel_tempo",
            "a funzioni sperimentali spente il messaggio non deve essere processato come time-lock"
        );
        assert_eq!(view.kind, "file", "va mostrato come dato grezzo salvabile");
        assert!(view.target_height.is_none());
        assert!(view.current_height.is_none());
        assert!(view.height_check_error.is_none());
    }

    /// A feature attiva, un endpoint indicato dal mittente che non
    /// supererebbe la validazione (qui: IP cloud-metadata in chiaro) non
    /// deve essere contattato: il messaggio resta bloccato con un errore
    /// esplicito, non parte alcuna richiesta.
    #[test]
    fn timelocked_message_with_disallowed_sender_endpoint_is_not_contacted() {
        let blob = sigillo_core::timelock::encode(
            10_000_000,
            Some("http://169.254.169.254/latest/meta-data/"),
            b"contenuto interno",
        );

        let view = build_decrypt_view(
            blob,
            None,
            message::SignatureStatus::Unsigned,
            &settings_with_experimental(true),
        );

        assert_eq!(view.kind, "bloccato_nel_tempo");
        assert_eq!(view.target_height, Some(10_000_000));
        assert!(
            view.height_check_error.is_some(),
            "deve riportare perché l'endpoint non è stato contattato"
        );
    }

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
    fn detects_gif_both_87a_and_89a() {
        let mut old = b"GIF87a".to_vec();
        old.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_media_mime(&old), Some("image/gif"));

        let mut animated = b"GIF89a".to_vec();
        animated.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_media_mime(&animated), Some("image/gif"));
    }

    #[test]
    fn text_starting_like_gif_but_not_a_gif_is_not_detected() {
        assert_eq!(detect_media_mime(b"GIF ma non davvero"), None);
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
