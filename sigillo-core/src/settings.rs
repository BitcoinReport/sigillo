//! Preferenze dell'app, persistite sul dispositivo. A differenza
//! dell'identità (`storage.rs`) qui non c'è nulla di segreto: nessuna
//! cifratura, stesso schema "file temporaneo + rename atomico" usato
//! anche per la rubrica (`contacts.rs`).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Formato di cifratura scelto per le immagini. Il testo non ha questa
/// scelta: è sempre ASCII armored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    /// ASCII armored (.asc): testo puro, leggibile e riconoscibile da
    /// qualsiasi programma OpenPGP, ma circa un terzo più pesante
    /// dell'originale. Predefinito.
    #[default]
    Asc,
    /// Binario compatto (.gpg): stessa dimensione dell'originale, ma
    /// meno immediato da riconoscere per chi non ha familiarità con la
    /// crittografia.
    Gpg,
}

/// Tutte le preferenze salvate. I campi aggiunti dopo la prima versione
/// hanno `#[serde(default)]` (a livello di struct): un file scritto da
/// una versione precedente continua a caricarsi correttamente, con i
/// nuovi campi ai loro valori predefiniti.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub image_format: ImageFormat,
    /// "Funzioni sperimentali": finché disattivato (il default), la UI
    /// del time-lock non deve comparire da nessuna parte dell'app, non
    /// solo essere disabilitata.
    pub experimental_features_enabled: bool,
    /// Instrada le verifiche dell'altezza blocco (per il time-lock)
    /// attraverso un proxy SOCKS5, invece che in chiaro: pensato per un
    /// demone Tor già in esecuzione sul dispositivo (es. Tor Browser, o
    /// `tor` da riga di comando), non incorporato nell'app stessa.
    pub tor_enabled: bool,
    pub tor_socks_host: String,
    pub tor_socks_port: u16,
    /// Endpoint personalizzato per verificare l'altezza blocco (es. un
    /// nodo proprio), al posto del servizio pubblico predefinito
    /// (mempool.space). Un endpoint che termina in ".onion" richiede
    /// comunque Tor per essere raggiunto, indipendentemente da
    /// `tor_enabled`.
    pub timelock_custom_endpoint: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            image_format: ImageFormat::default(),
            experimental_features_enabled: false,
            tor_enabled: false,
            tor_socks_host: "127.0.0.1".to_string(),
            tor_socks_port: 9050,
            timelock_custom_endpoint: None,
        }
    }
}

/// Legge tutte le preferenze salvate. Se non è mai stato salvato nulla
/// (nessun file ancora), restituisce i valori predefiniti invece di un
/// errore: è lo stato normale al primo avvio.
pub fn load_settings(path: &Path) -> Result<Settings> {
    if !path.is_file() {
        return Ok(Settings::default());
    }
    let data = fs::read_to_string(path).context("impossibile leggere le impostazioni salvate")?;
    serde_json::from_str(&data).context("il file delle impostazioni è danneggiato")
}

/// Salva tutte le preferenze, sovrascrivendo il file precedente. Le
/// singole funzioni `save_*` sotto leggono prima lo stato attuale e
/// modificano solo il proprio campo, cosi' da non perdere le altre
/// preferenze salvate nel frattempo.
pub fn save_settings(path: &Path, settings: &Settings) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("impossibile creare la cartella dati dell'app")?;
    }
    let data = serde_json::to_string_pretty(settings)
        .context("errore interno nella serializzazione delle impostazioni")?;

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, data).context("impossibile scrivere le impostazioni")?;
    fs::rename(&tmp_path, path).context("impossibile salvare le impostazioni")?;
    Ok(())
}

pub fn load_image_format(path: &Path) -> Result<ImageFormat> {
    Ok(load_settings(path)?.image_format)
}

pub fn save_image_format(path: &Path, format: ImageFormat) -> Result<()> {
    let mut settings = load_settings(path)?;
    settings.image_format = format;
    save_settings(path, &settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_asc_when_no_file_exists_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert_eq!(load_image_format(&path).unwrap(), ImageFormat::Asc);
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        save_image_format(&path, ImageFormat::Gpg).unwrap();
        assert_eq!(load_image_format(&path).unwrap(), ImageFormat::Gpg);

        // Sopravvive a un "riavvio" (nuova lettura da un file gia salvato).
        assert_eq!(load_image_format(&path).unwrap(), ImageFormat::Gpg);

        save_image_format(&path, ImageFormat::Asc).unwrap();
        assert_eq!(load_image_format(&path).unwrap(), ImageFormat::Asc);
    }

    #[test]
    fn corrupted_settings_file_is_reported_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"non sono json valido").unwrap();
        assert!(load_image_format(&path).is_err());
    }

    #[test]
    fn defaults_are_safe_experimental_features_off_tor_off() {
        let settings = Settings::default();
        assert!(!settings.experimental_features_enabled);
        assert!(!settings.tor_enabled);
        assert_eq!(settings.tor_socks_host, "127.0.0.1");
        assert_eq!(settings.tor_socks_port, 9050);
        assert_eq!(settings.timelock_custom_endpoint, None);
    }

    #[test]
    fn saving_image_format_does_not_clobber_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        let mut settings = Settings::default();
        settings.experimental_features_enabled = true;
        settings.tor_enabled = true;
        settings.tor_socks_port = 9150;
        settings.timelock_custom_endpoint = Some("https://mio-nodo.esempio/altezza".to_string());
        save_settings(&path, &settings).unwrap();

        // Cambiare solo il formato immagine non deve azzerare le altre
        // preferenze appena salvate.
        save_image_format(&path, ImageFormat::Gpg).unwrap();

        let reloaded = load_settings(&path).unwrap();
        assert_eq!(reloaded.image_format, ImageFormat::Gpg);
        assert!(reloaded.experimental_features_enabled);
        assert!(reloaded.tor_enabled);
        assert_eq!(reloaded.tor_socks_port, 9150);
        assert_eq!(
            reloaded.timelock_custom_endpoint,
            Some("https://mio-nodo.esempio/altezza".to_string())
        );
    }

    #[test]
    fn settings_saved_before_experimental_features_still_load() {
        // Simula un file scritto da una versione precedente dell'app,
        // con solo il campo image_format.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{"image_format":"gpg"}"#).unwrap();

        let settings = load_settings(&path).unwrap();
        assert_eq!(settings.image_format, ImageFormat::Gpg);
        assert!(!settings.experimental_features_enabled);
        assert!(!settings.tor_enabled);
    }
}
