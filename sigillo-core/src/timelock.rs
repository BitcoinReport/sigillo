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

use std::io::Read;

use anyhow::{bail, Context, Result};

const MAGIC: &[u8] = b"SIGILLO-TIMELOCK-1\0";

/// Quanti byte servono, come minimo, per riconoscere un messaggio con
/// blocco temporale da [`is_timelocked`].
pub const MAGIC_LEN: usize = MAGIC.len();

/// La parte che precede il contenuto vero e proprio: basta leggere
/// questa per sapere fino a quale altezza blocco il messaggio e'
/// bloccato, senza caricare il contenuto (che puo' essere un file
/// grande) in memoria.
pub struct TimelockHeader {
    pub target_height: u32,
    pub endpoint: Option<String>,
    /// Quanti byte di contenuto seguono l'intestazione.
    pub inner_len: u64,
}

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

/// Intestazione (tutto tranne il contenuto interno), per poter cifrare
/// "a flusso" un contenuto grande senza costruirlo prima in memoria.
pub fn encode_header(
    target_height: u32,
    endpoint: Option<&str>,
    inner_len: u64,
) -> Result<Vec<u8>> {
    let endpoint_bytes = endpoint.unwrap_or("").as_bytes();
    if u16::try_from(endpoint_bytes.len()).is_err() {
        bail!("l'indirizzo di verifica e' troppo lungo");
    }
    if inner_len > u64::from(u32::MAX) {
        bail!("il contenuto supera i 4 GB, il limite di Sigillo per un messaggio con blocco temporale");
    }

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + 2 + endpoint_bytes.len() + 4);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&target_height.to_le_bytes());
    out.extend_from_slice(&(endpoint_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(endpoint_bytes);
    out.extend_from_slice(&(inner_len as u32).to_le_bytes());
    Ok(out)
}

pub fn encode(target_height: u32, endpoint: Option<&str>, inner: &[u8]) -> Result<Vec<u8>> {
    let mut out = encode_header(target_height, endpoint, inner.len() as u64)?;
    out.extend_from_slice(inner);
    Ok(out)
}

fn read_array<R: Read + ?Sized, const N: usize>(r: &mut R) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)
        .context("messaggio con blocco temporale troncato")?;
    Ok(buf)
}

/// Legge l'intestazione da un flusso (anche di dati decifrati "al
/// volo"), lasciandolo posizionato sul primo byte del contenuto.
pub fn read_header<R: Read + ?Sized>(r: &mut R) -> Result<TimelockHeader> {
    let magic: [u8; MAGIC_LEN] = read_array(r)?;
    if magic != MAGIC {
        bail!("non e' un messaggio con blocco temporale");
    }

    let target_height = u32::from_le_bytes(read_array(r)?);

    let endpoint_len = u16::from_le_bytes(read_array(r)?) as usize;
    let mut endpoint_bytes = vec![0u8; endpoint_len];
    r.read_exact(&mut endpoint_bytes)
        .context("messaggio con blocco temporale troncato")?;
    let endpoint = if endpoint_bytes.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(endpoint_bytes)
                .context("messaggio con blocco temporale corrotto (endpoint non valido)")?,
        )
    };

    let inner_len = u32::from_le_bytes(read_array(r)?) as u64;

    Ok(TimelockHeader {
        target_height,
        endpoint,
        inner_len,
    })
}

pub fn decode(data: &[u8]) -> Result<TimeLockedMessage> {
    if !is_timelocked(data) {
        bail!("non e' un messaggio con blocco temporale");
    }
    let mut cursor = std::io::Cursor::new(data);
    let header = read_header(&mut cursor)?;

    let mut inner = Vec::new();
    cursor
        .take(header.inner_len)
        .read_to_end(&mut inner)
        .context("messaggio con blocco temporale illeggibile")?;
    if inner.len() as u64 != header.inner_len {
        bail!("messaggio con blocco temporale troncato");
    }

    Ok(TimeLockedMessage {
        target_height: header.target_height,
        endpoint: header.endpoint,
        inner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_custom_endpoint() {
        let encoded = encode(900_000, Some("https://mio-nodo.esempio/altezza"), b"ciao Bob!").unwrap();
        assert!(is_timelocked(&encoded));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.target_height, 900_000);
        assert_eq!(decoded.endpoint.as_deref(), Some("https://mio-nodo.esempio/altezza"));
        assert_eq!(decoded.inner, b"ciao Bob!");
    }

    #[test]
    fn round_trip_with_default_endpoint() {
        let encoded = encode(850_123, None, b"contenuto qualsiasi").unwrap();
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
        let mut encoded = encode(900_000, None, b"contenuto abbastanza lungo da poter troncare").unwrap();
        encoded.truncate(encoded.len() - 5);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn can_wrap_a_combined_text_and_media_inner_payload() {
        // Il contenuto interno puo' essere a sua volta un pacchetto
        // "combinato" (testo + immagine/video): timelock non deve
        // sapere/preoccuparsi di cosa contiene, solo trasportarlo.
        let inner = crate::composite::encode("didascalia", Some("foto.png"), "image/png", &[1, 2, 3]).unwrap();
        let encoded = encode(700_000, None, &inner).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert!(crate::composite::is_combined(&decoded.inner));
        let combined = crate::composite::decode(&decoded.inner).unwrap();
        assert_eq!(combined.text, "didascalia");
    }

    #[test]
    fn header_then_inner_is_byte_identical_to_the_in_memory_encoding() {
        let inner = vec![5u8; 300];
        let whole = encode(812_345, Some("https://x.example/h"), &inner).unwrap();
        let mut streamed = encode_header(812_345, Some("https://x.example/h"), 300).unwrap();
        streamed.extend_from_slice(&inner);
        assert_eq!(whole, streamed);

        let mut cursor = std::io::Cursor::new(&whole);
        let header = read_header(&mut cursor).unwrap();
        assert_eq!(header.target_height, 812_345);
        assert_eq!(header.endpoint.as_deref(), Some("https://x.example/h"));
        assert_eq!(header.inner_len, 300);
    }

    #[test]
    fn truncation_at_every_length_never_panics() {
        let encoded = encode(900_000, Some("https://x.example/h"), b"contenuto").unwrap();
        for cut in 0..encoded.len() {
            let _ = decode(&encoded[..cut]);
        }
    }

    #[test]
    fn oversized_inner_is_refused() {
        assert!(encode_header(1, None, u64::from(u32::MAX) + 1).is_err());
    }
}
