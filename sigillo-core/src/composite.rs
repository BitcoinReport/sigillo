use std::io::Read;

use anyhow::{bail, Context, Result};

/// Marcatore che identifica un messaggio combinato testo+allegato dentro
/// il blob di byte che viene passato al motore di cifratura: un testo o
/// un file reali hanno probabilita' trascurabile di iniziare per caso
/// con questa sequenza.
const MAGIC: &[u8] = b"SIGILLO-COMBINATO-1\0";

/// Un testo piu' un file (immagine, video, PDF, documento... qualunque
/// cosa) impacchettati in un'unica sequenza di byte prima di essere
/// cifrati: cosi' il motore crittografico (Sequoia) continua a vedere e
/// cifrare "una sequenza di byte", senza bisogno di supportare piu'
/// allegati nel formato OpenPGP.
///
/// Il formato su disco e' lo stesso fin dalla prima versione che
/// combinava testo e immagine (i campi si chiamavano `image_*` perche'
/// allora gli allegati erano solo immagini): i messaggi creati dalle
/// versioni precedenti continuano a leggersi senza modifiche.
pub struct CombinedMessage {
    pub text: String,
    pub attachment_filename: Option<String>,
    pub attachment_mime: String,
    pub attachment_data: Vec<u8>,
}

/// La parte del messaggio combinato che precede i byte del file: basta
/// leggere questa per sapere cosa c'e' dentro, senza caricare il file
/// in memoria (che si puo' poi copiare a pezzi dal flusso).
pub struct CompositeHeader {
    pub text: String,
    pub attachment_filename: Option<String>,
    pub attachment_mime: String,
    /// Quanti byte di file seguono l'intestazione.
    pub attachment_len: u64,
}

/// Limite al testo di accompagnamento letto da un flusso: serve a non
/// allocare quantita' assurde se un messaggio ostile dichiara un testo
/// lungo 4 GB.
pub const MAX_TEXT_BYTES: usize = 32 * 1024 * 1024;

/// Il formato memorizza la lunghezza del file in 4 byte: oltre non si
/// puo' andare (per i messaggi combinati e con blocco temporale).
pub const MAX_ATTACHMENT_BYTES: u64 = u32::MAX as u64;

/// Vero se `data` e' un messaggio combinato codificato con [`encode`]
/// (da controllare prima di provare a interpretare i byte come testo o
/// come file puro).
pub fn is_combined(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// Quanti byte servono, come minimo, per riconoscere un messaggio
/// combinato da [`is_combined`].
pub const MAGIC_LEN: usize = MAGIC.len();

/// Formato: magic, poi per ciascun campo una lunghezza seguita dai byte
/// del campo stesso (little-endian): testo (u32), nome file (u16, vuoto
/// se assente), tipo MIME (u8, es. "application/pdf"), dati del file
/// (u32). Questa funzione produce tutto tranne i dati del file.
pub fn encode_header(
    text: &str,
    attachment_filename: Option<&str>,
    attachment_mime: &str,
    attachment_len: u64,
) -> Result<Vec<u8>> {
    let text_bytes = text.as_bytes();
    let filename_bytes = attachment_filename.unwrap_or("").as_bytes();
    let mime_bytes = attachment_mime.as_bytes();

    if u32::try_from(text_bytes.len()).is_err() {
        bail!("il testo del messaggio e' troppo lungo");
    }
    if u16::try_from(filename_bytes.len()).is_err() {
        bail!("il nome del file e' troppo lungo");
    }
    if u8::try_from(mime_bytes.len()).is_err() {
        bail!("il tipo del file e' troppo lungo");
    }
    if attachment_len > MAX_ATTACHMENT_BYTES {
        bail!("il file supera i 4 GB, il limite di Sigillo per un allegato");
    }

    let mut out = Vec::with_capacity(
        MAGIC.len() + 4 + text_bytes.len() + 2 + filename_bytes.len() + 1 + mime_bytes.len() + 4,
    );
    out.extend_from_slice(MAGIC);

    out.extend_from_slice(&(text_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(text_bytes);

    out.extend_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(filename_bytes);

    out.push(mime_bytes.len() as u8);
    out.extend_from_slice(mime_bytes);

    out.extend_from_slice(&(attachment_len as u32).to_le_bytes());

    Ok(out)
}

/// Intero messaggio combinato in memoria (intestazione + dati).
pub fn encode(
    text: &str,
    attachment_filename: Option<&str>,
    attachment_mime: &str,
    attachment_data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = encode_header(
        text,
        attachment_filename,
        attachment_mime,
        attachment_data.len() as u64,
    )?;
    out.extend_from_slice(attachment_data);
    Ok(out)
}

/// Legge `len` byte dal flusso senza fidarsi della lunghezza dichiarata
/// per riservare memoria: il vettore cresce solo man mano che i dati
/// arrivano davvero, quindi un messaggio troncato o ostile fallisce con
/// un errore invece di allocare gigabyte.
fn read_exact_vec<R: Read + ?Sized>(r: &mut R, len: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(len as u64)
        .read_to_end(&mut buf)
        .context("messaggio combinato illeggibile")?;
    if buf.len() != len {
        bail!("messaggio combinato troncato");
    }
    Ok(buf)
}

fn read_u8<R: Read + ?Sized>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).context("messaggio combinato troncato")?;
    Ok(b[0])
}

fn read_u16<R: Read + ?Sized>(r: &mut R) -> Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b).context("messaggio combinato troncato")?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32<R: Read + ?Sized>(r: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).context("messaggio combinato troncato")?;
    Ok(u32::from_le_bytes(b))
}

/// Legge l'intestazione di un messaggio combinato da un flusso (anche un
/// flusso di dati decifrati "al volo"), lasciandolo posizionato sul
/// primo byte del file.
pub fn read_header<R: Read + ?Sized>(r: &mut R) -> Result<CompositeHeader> {
    let mut magic = [0u8; MAGIC_LEN];
    r.read_exact(&mut magic).context("messaggio combinato troncato")?;
    if magic != MAGIC {
        bail!("non e' un messaggio combinato");
    }

    let text_len = read_u32(r)? as usize;
    if text_len > MAX_TEXT_BYTES {
        bail!("il testo del messaggio combinato e' troppo lungo");
    }
    let text = String::from_utf8(read_exact_vec(r, text_len)?)
        .context("testo non valido nel messaggio combinato")?;

    let filename_len = read_u16(r)? as usize;
    let filename_bytes = read_exact_vec(r, filename_len)?;
    let attachment_filename = if filename_bytes.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(filename_bytes)
                .context("nome file non valido nel messaggio combinato")?,
        )
    };

    let mime_len = read_u8(r)? as usize;
    let attachment_mime = String::from_utf8(read_exact_vec(r, mime_len)?)
        .context("tipo del file non valido nel messaggio combinato")?;

    let attachment_len = read_u32(r)? as u64;

    Ok(CompositeHeader {
        text,
        attachment_filename,
        attachment_mime,
        attachment_len,
    })
}

pub fn decode(data: &[u8]) -> Result<CombinedMessage> {
    if !is_combined(data) {
        bail!("non e' un messaggio combinato");
    }
    let mut cursor = std::io::Cursor::new(data);
    let header = read_header(&mut cursor)?;
    let attachment_data = read_exact_vec(&mut cursor, header.attachment_len as usize)?;

    Ok(CombinedMessage {
        text: header.text,
        attachment_filename: header.attachment_filename,
        attachment_mime: header.attachment_mime,
        attachment_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_text_filename_and_image() {
        let image = vec![1u8, 2, 3, 4, 5, 255, 0, 9];
        let encoded = encode("Ciao Bob!", Some("foto.png"), "image/png", &image).unwrap();
        assert!(is_combined(&encoded));

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.text, "Ciao Bob!");
        assert_eq!(decoded.attachment_filename.as_deref(), Some("foto.png"));
        assert_eq!(decoded.attachment_mime, "image/png");
        assert_eq!(decoded.attachment_data, image);
    }

    #[test]
    fn round_trip_without_filename_or_text() {
        let encoded = encode("", None, "application/octet-stream", b"abc").unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.text, "");
        assert_eq!(decoded.attachment_filename, None);
        assert_eq!(decoded.attachment_data, b"abc");
    }

    #[test]
    fn round_trip_with_any_kind_of_file_and_unicode_names() {
        let pdf = b"%PDF-1.7\n\x00\x01\x02 contenuto binario \xff\xfe".to_vec();
        let encoded = encode(
            "Ecco il documento: è importante ✓",
            Some("Relazione è finale.pdf"),
            "application/pdf",
            &pdf,
        )
        .unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.text, "Ecco il documento: è importante ✓");
        assert_eq!(decoded.attachment_filename.as_deref(), Some("Relazione è finale.pdf"));
        assert_eq!(decoded.attachment_mime, "application/pdf");
        assert_eq!(decoded.attachment_data, pdf);
    }

    #[test]
    fn plain_text_and_plain_images_are_not_recognized_as_combined() {
        assert!(!is_combined(b"ciao, sono un messaggio normale"));
        assert!(!is_combined(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]));
    }

    #[test]
    fn header_then_data_is_byte_identical_to_the_in_memory_encoding() {
        // La cifratura "a flusso" scrive prima l'intestazione e poi copia
        // il file a pezzi: il risultato deve coincidere con encode().
        let data = vec![7u8; 1000];
        let whole = encode("testo", Some("a.zip"), "application/zip", &data).unwrap();
        let mut streamed = encode_header("testo", Some("a.zip"), "application/zip", 1000).unwrap();
        streamed.extend_from_slice(&data);
        assert_eq!(whole, streamed);
    }

    #[test]
    fn header_can_be_read_from_a_stream_leaving_the_data_unread() {
        let data = vec![9u8; 64];
        let encoded = encode("didascalia", Some("x.pdf"), "application/pdf", &data).unwrap();
        let mut cursor = std::io::Cursor::new(&encoded);
        let header = read_header(&mut cursor).unwrap();
        assert_eq!(header.text, "didascalia");
        assert_eq!(header.attachment_filename.as_deref(), Some("x.pdf"));
        assert_eq!(header.attachment_mime, "application/pdf");
        assert_eq!(header.attachment_len, 64);

        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, data);
    }

    #[test]
    fn a_message_written_by_the_previous_versions_still_reads() {
        // Costruito a mano con il layout storico (campi "image_*"): i
        // file .asc creati prima degli allegati generici devono
        // continuare a decifrarsi esattamente come prima.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(b"SIGILLO-COMBINATO-1\0");
        legacy.extend_from_slice(&5u32.to_le_bytes());
        legacy.extend_from_slice(b"ciao!");
        legacy.extend_from_slice(&8u16.to_le_bytes());
        legacy.extend_from_slice(b"foto.png");
        legacy.push(9);
        legacy.extend_from_slice(b"image/png");
        legacy.extend_from_slice(&4u32.to_le_bytes());
        legacy.extend_from_slice(&[1, 2, 3, 4]);

        let decoded = decode(&legacy).unwrap();
        assert_eq!(decoded.text, "ciao!");
        assert_eq!(decoded.attachment_filename.as_deref(), Some("foto.png"));
        assert_eq!(decoded.attachment_mime, "image/png");
        assert_eq!(decoded.attachment_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn truncated_data_is_reported_cleanly_not_panicking() {
        let encoded = encode("testo", Some("a.png"), "image/png", &[1, 2, 3, 4, 5, 6]).unwrap();
        // Troncato a meta' dei dati del file.
        assert!(decode(&encoded[..encoded.len() - 3]).is_err());
        // Troncato a ogni lunghezza possibile: mai un panico.
        for cut in 0..encoded.len() {
            let _ = decode(&encoded[..cut]);
        }
    }

    #[test]
    fn garbage_with_magic_prefix_only_is_reported_cleanly() {
        assert!(decode(MAGIC).is_err());
    }

    #[test]
    fn declared_huge_lengths_do_not_allocate_or_panic() {
        // Testo dichiarato lungo 4 GB, ma i dati finiscono subito.
        let mut bogus = MAGIC.to_vec();
        bogus.extend_from_slice(&u32::MAX.to_le_bytes());
        bogus.extend_from_slice(b"poca roba");
        assert!(decode(&bogus).is_err());

        // File dichiarato lungo 4 GB ma assente.
        let mut bogus = encode_header("", None, "image/png", 10).unwrap();
        let len_pos = bogus.len() - 4;
        bogus[len_pos..].copy_from_slice(&u32::MAX.to_le_bytes());
        bogus.extend_from_slice(b"pochi byte");
        assert!(decode(&bogus).is_err());
    }

    #[test]
    fn oversized_attachment_is_refused_instead_of_being_silently_truncated() {
        let err = encode_header(
            "",
            Some("enorme.bin"),
            "application/octet-stream",
            u64::from(u32::MAX) + 1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("4 GB"));
        assert!(encode_header("", None, "application/octet-stream", u64::from(u32::MAX)).is_ok());
    }

    #[test]
    fn over_long_fields_are_refused() {
        let long_mime = "a".repeat(300);
        assert!(encode_header("", None, &long_mime, 1).is_err());
        let long_name = "n".repeat(70_000);
        assert!(encode_header("", Some(&long_name), "x/y", 1).is_err());
    }

    #[test]
    fn not_a_combined_message_is_rejected() {
        assert!(decode(b"testo normale").is_err());
        assert!(
            read_header(&mut std::io::Cursor::new(b"testo normale che non e' combinato")).is_err()
        );
    }
}
