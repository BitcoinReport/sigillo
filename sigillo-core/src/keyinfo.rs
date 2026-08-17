//! Dettagli tecnici di una chiave OpenPGP (algoritmo, date), destinati
//! solo alla sezione "avanzate": nel resto dell'app questi dettagli non
//! devono comparire, per restare comprensibili a chi non ha competenze
//! tecniche.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::crypto::mpi;
use openpgp::policy::StandardPolicy;
use openpgp::Cert;

#[derive(Debug, Clone)]
pub struct KeyDetail {
    pub label: String,
    pub algorithm: String,
    pub created_unix: i64,
    pub expires_unix: Option<i64>,
}

fn system_time_to_unix(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

fn describe_algorithm(mpis: &mpi::PublicKey) -> String {
    match mpis {
        mpi::PublicKey::EdDSA { curve, .. } => format!("EdDSA ({curve})"),
        mpi::PublicKey::ECDH { curve, .. } => format!("ECDH ({curve})"),
        mpi::PublicKey::ECDSA { curve, .. } => format!("ECDSA ({curve})"),
        mpi::PublicKey::RSA { n, .. } => format!("RSA {} bit", n.bits()),
        other => other
            .algo()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "algoritmo sconosciuto".to_string()),
    }
}

/// Elenca chiave primaria e sottochiavi di `cert` con algoritmo, data di
/// creazione ed eventuale scadenza (come timestamp Unix, da formattare
/// lato interfaccia).
pub fn technical_details(cert: &Cert) -> Result<Vec<KeyDetail>> {
    let p = &StandardPolicy::new();
    let primary_fingerprint = cert.fingerprint();

    let mut details = Vec::new();
    for ka in cert.keys().with_policy(p, None) {
        let is_primary = ka.key().fingerprint() == primary_fingerprint;
        let label = if is_primary {
            "Chiave primaria (identità e firma)".to_string()
        } else {
            "Sottochiave (cifratura dei messaggi)".to_string()
        };

        details.push(KeyDetail {
            label,
            algorithm: describe_algorithm(ka.key().mpis()),
            created_unix: system_time_to_unix(ka.key().creation_time()),
            expires_unix: ka.key_expiration_time().map(system_time_to_unix),
        });
    }

    Ok(details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    #[test]
    fn reports_primary_and_subkey_with_expected_algorithms() {
        let id = identity::generate(identity::SeedWordCount::Twelve, "Alice").unwrap();
        let details = technical_details(&id.cert).unwrap();

        assert_eq!(details.len(), 2);
        assert!(details[0].label.contains("primaria"));
        assert!(details[0].algorithm.contains("EdDSA"));
        assert!(details[1].label.contains("cifratura"));
        assert!(details[1].algorithm.contains("ECDH"));

        // Le nostre chiavi non hanno scadenza.
        assert!(details.iter().all(|d| d.expires_unix.is_none()));

        // La data di creazione è il timestamp fisso documentato in identity.rs.
        assert!(details.iter().all(|d| d.created_unix == 1_231_006_505));
    }
}
