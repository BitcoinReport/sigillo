//! Formato del contenuto "bloccato nel tempo" (funzione sperimentale,
//! disattivata di default): un pacchetto che indica un'altezza blocco
//! Bitcoin target e l'eventuale endpoint di verifica da usare, insieme
//! al contenuto vero e proprio (testo semplice, o gia' un pacchetto
//! "combinato" testo+immagine/video), impacchettati in un'unica
//! sequenza di byte PRIMA di essere cifrati con il normale motore
//! OpenPGP — lo stesso principio gia' usato per combinare testo e
//! immagine (vedi `composite.rs`).
//!
//! Importante: questo e' un blocco applicativo "per gioco", non una
//! garanzia crittografica. Chiunque abbia la chiave privata giusta puo'
//! decifrare il messaggio OpenPGP in qualunque momento (e' cifratura
//! OpenPGP normale, invariata); e' solo l'interfaccia di Sigillo che si
//! rifiuta di mostrare il contenuto finche' l'altezza target non e'
//! raggiunta.

use anyhow::{bail, Context, Result};

const MAGIC: &[u8] = b"SIGILLO-TIMELOCK-1\0";

pub struct TimeLockedMessage {
    pub target_height: u32,
    /// `None` = usa l'endpoint predefinito (mempool.space). Se termina
    /// in ".onion", raggiungerlo richiede comunque Tor, a prescindere
    /// dalla preferenza locale.
    pub endpoint: Option<String>,
    /// Il contenuto vero e proprio: testo semplice, oppure un pacchetto
    /// "combinato" (vedi `composite::encode`) se include anche
    /// un'immagine o un video.
    pub inner: Vec<u8>,
}

pub fn is_timelocked(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

pub fn encode(target_height: u32, endpoint: Option<&str>, inner: &[u8]) -> Vec<u8> {
    let endpoint_bytes = endpoint.unwrap_or("").as_bytes();

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + 2 + endpoint_bytes.len() + 4 + inner.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&target_height.to_le_bytes());
    out.extend_from_slice(&(endpoint_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(endpoint_bytes);
    out.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    out.extend_from_slice(inner);
    out
}

pub fn decode(data: &[u8]) -> Result<TimeLockedMessage> {
    if !is_timelocked(data) {
        bail!("non e' un messaggio con blocco temporale");
    }
    let mut pos = MAGIC.len();

    let target_height = u32::from_le_bytes(read_bytes(data, &mut pos, 4)?.try_into().unwrap());

    let endpoint_len = u16::from_le_bytes(read_bytes(data, &mut pos, 2)?.try_into().unwrap()) as usize;
    let endpoint_bytes = read_bytes(data, &mut pos, endpoint_len)?;
    let endpoint = if endpoint_bytes.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(endpoint_bytes.to_vec())
                .context("messaggio con blocco temporale corrotto (endpoint non valido)")?,
        )
    };

    let inner_len = u32::from_le_bytes(read_bytes(data, &mut pos, 4)?.try_into().unwrap()) as usize;
    let inner = read_bytes(data, &mut pos, inner_len)?.to_vec();

    Ok(TimeLockedMessage {
        target_height,
        endpoint,
        inner,
    })
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .context("messaggio con blocco temporale troncato")?;
    let slice = data
        .get(*pos..end)
        .context("messaggio con blocco temporale troncato")?;
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_custom_endpoint() {
        let encoded = encode(900_000, Some("https://mio-nodo.esempio/altezza"), b"ciao Bob!");
        assert!(is_timelocked(&encoded));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.target_height, 900_000);
        assert_eq!(decoded.endpoint.as_deref(), Some("https://mio-nodo.esempio/altezza"));
        assert_eq!(decoded.inner, b"ciao Bob!");
    }

    #[test]
    fn round_trip_with_default_endpoint() {
        let encoded = encode(850_123, None, b"contenuto qualsiasi");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.endpoint, None);
    }

    #[test]
    fn plain_text_is_not_recognized_as_timelocked() {
        assert!(!is_timelocked(b"ciao, sono un messaggio normale"));
    }

    #[test]
    fn plain_image_bytes_are_not_recognized_as_timelocked() {
        assert!(!is_timelocked(&[0xFF, 0xD8, 0xFF, 0, 0, 0]));
    }

    #[test]
    fn truncated_data_is_reported_cleanly_not_panicking() {
        let mut encoded = encode(900_000, None, b"contenuto abbastanza lungo da poter troncare");
        encoded.truncate(encoded.len() - 5);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn can_wrap_a_combined_text_and_media_inner_payload() {
        // Il contenuto interno puo' essere a sua volta un pacchetto
        // "combinato" (testo + immagine/video): timelock non deve
        // sapere/preoccuparsi di cosa contiene, solo trasportarlo.
        let inner = crate::composite::encode("didascalia", Some("foto.png"), "image/png", &[1, 2, 3]);
        let encoded = encode(700_000, None, &inner);
        let decoded = decode(&encoded).unwrap();
        assert!(crate::composite::is_combined(&decoded.inner));
        let combined = crate::composite::decode(&decoded.inner).unwrap();
        assert_eq!(combined.text, "didascalia");
    }
}
