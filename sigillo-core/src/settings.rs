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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct Settings {
    image_format: ImageFormat,
}

/// Legge il formato immagine salvato. Se non è mai stato salvato nulla
/// (nessun file ancora), restituisce il valore predefinito (.asc)
/// invece di un errore: è lo stato normale al primo avvio.
pub fn load_image_format(path: &Path) -> Result<ImageFormat> {
    if !path.is_file() {
        return Ok(ImageFormat::default());
    }
    let data = fs::read_to_string(path).context("impossibile leggere le impostazioni salvate")?;
    let settings: Settings =
        serde_json::from_str(&data).context("il file delle impostazioni è danneggiato")?;
    Ok(settings.image_format)
}

/// Salva il formato immagine scelto, sovrascrivendo il file precedente.
pub fn save_image_format(path: &Path, format: ImageFormat) -> Result<()> {
    let settings = Settings {
        image_format: format,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("impossibile creare la cartella dati dell'app")?;
    }
    let data = serde_json::to_string_pretty(&settings)
        .context("errore interno nella serializzazione delle impostazioni")?;

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, data).context("impossibile scrivere le impostazioni")?;
    fs::rename(&tmp_path, path).context("impossibile salvare le impostazioni")?;
    Ok(())
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
}
