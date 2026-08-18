use anyhow::{bail, Context, Result};

/// Marcatore che identifica un messaggio combinato testo+immagine dentro
/// il blob di byte che viene passato al motore di cifratura: un testo o
/// un'immagine reali hanno probabilita' trascurabile di iniziare per
/// caso con questa sequenza.
const MAGIC: &[u8] = b"SIGILLO-COMBINATO-1\0";

/// Un messaggio che contiene sia testo sia un'immagine, impacchettato in
/// un'unica sequenza di byte prima di essere cifrata: cosi' il motore
/// crittografico (Sequoia) continua a vedere e cifrare "una sequenza di
/// byte", senza bisogno di supportare piu' allegati nel formato OpenPGP.
pub struct CombinedMessage {
    pub text: String,
    pub image_filename: Option<String>,
    pub image_mime: String,
    pub image_data: Vec<u8>,
}

/// Vero se `data` e' un messaggio combinato codificato con [`encode`]
/// (da controllare prima di provare a interpretare i byte come testo o
/// come immagine pura).
pub fn is_combined(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// Formato: magic, poi per ciascun campo una lunghezza seguita dai byte
/// del campo stesso (little-endian): testo (u32), nome file immagine
/// (u16, vuoto se assente), tipo MIME (u8, es. "image/png"), dati
/// dell'immagine (u32).
pub fn encode(text: &str, image_filename: Option<&str>, image_mime: &str, image_data: &[u8]) -> Vec<u8> {
    let text_bytes = text.as_bytes();
    let filename_bytes = image_filename.unwrap_or("").as_bytes();
    let mime_bytes = image_mime.as_bytes();

    let mut out = Vec::with_capacity(
        MAGIC.len() + 4 + text_bytes.len() + 2 + filename_bytes.len() + 1 + mime_bytes.len() + 4 + image_data.len(),
    );
    out.extend_from_slice(MAGIC);

    out.extend_from_slice(&(text_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(text_bytes);

    out.extend_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(filename_bytes);

    out.push(mime_bytes.len() as u8);
    out.extend_from_slice(mime_bytes);

    out.extend_from_slice(&(image_data.len() as u32).to_le_bytes());
    out.extend_from_slice(image_data);

    out
}

pub fn decode(data: &[u8]) -> Result<CombinedMessage> {
    if !is_combined(data) {
        bail!("non e' un messaggio combinato");
    }
    let mut pos = MAGIC.len();

    let text_len = read_u32(data, &mut pos)? as usize;
    let text = String::from_utf8(read_bytes(data, &mut pos, text_len)?.to_vec())
        .context("testo non valido nel messaggio combinato")?;

    let filename_len = read_u16(data, &mut pos)? as usize;
    let filename_bytes = read_bytes(data, &mut pos, filename_len)?;
    let image_filename = if filename_bytes.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(filename_bytes.to_vec())
                .context("nome file non valido nel messaggio combinato")?,
        )
    };

    let mime_len = read_u8(data, &mut pos)? as usize;
    let image_mime = String::from_utf8(read_bytes(data, &mut pos, mime_len)?.to_vec())
        .context("tipo immagine non valido nel messaggio combinato")?;

    let image_len = read_u32(data, &mut pos)? as usize;
    let image_data = read_bytes(data, &mut pos, image_len)?.to_vec();

    Ok(CombinedMessage {
        text,
        image_filename,
        image_mime,
        image_data,
    })
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    Ok(read_bytes(data, pos, 1)?[0])
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    let bytes = read_bytes(data, pos, 2)?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    let bytes = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(len).context("messaggio combinato troncato")?;
    let slice = data.get(*pos..end).context("messaggio combinato troncato")?;
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_filename() {
        let encoded = encode("ciao Bob!", Some("foto.png"), "image/png", &[1, 2, 3, 4]);
        assert!(is_combined(&encoded));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.text, "ciao Bob!");
        assert_eq!(decoded.image_filename.as_deref(), Some("foto.png"));
        assert_eq!(decoded.image_mime, "image/png");
        assert_eq!(decoded.image_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn round_trip_without_filename() {
        let encoded = encode("testo", None, "image/jpeg", &[9, 9]);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.image_filename, None);
    }

    #[test]
    fn round_trip_empty_text() {
        let encoded = encode("", Some("x.png"), "image/png", &[0xFF]);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.text, "");
    }

    #[test]
    fn plain_text_is_not_recognized_as_combined() {
        assert!(!is_combined(b"ciao, sono un messaggio normale"));
    }

    #[test]
    fn plain_image_bytes_are_not_recognized_as_combined() {
        assert!(!is_combined(&[0xFF, 0xD8, 0xFF, 0, 0, 0]));
    }

    #[test]
    fn truncated_data_is_reported_cleanly_not_panicking() {
        let mut encoded = encode("ciao", Some("foto.png"), "image/png", &[1, 2, 3, 4, 5, 6, 7, 8]);
        encoded.truncate(encoded.len() - 3);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn garbage_with_magic_prefix_only_is_reported_cleanly() {
        assert!(decode(MAGIC).is_err());
    }
}
