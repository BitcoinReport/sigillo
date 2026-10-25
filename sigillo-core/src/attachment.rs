//! Allegati generici: qualunque file (PDF, documenti Office, audio,
//! archivi...) trattato come un blocco di byte con un nome e un tipo.
//!
//! Questo modulo non cifra nulla: raccoglie le regole che servono per
//! decidere *cosa* si sta maneggiando senza mai fidarsi ciecamente di
//! quello che dichiara un messaggio ricevuto:
//!
//! - [`sanitize_filename`]: il nome file arriva dentro un messaggio di
//!   terzi, quindi è input non fidato. Prima di usarlo per scrivere su
//!   disco o proporlo come nome di salvataggio va ridotto al solo nome
//!   base, senza separatori di percorso, `..`, caratteri di controllo,
//!   caratteri che invertono il verso del testo (usati per travestire
//!   un `.exe` da `.pdf`) né nomi riservati di Windows.
//! - [`resolve_mime`]: tipo del contenuto dai primi byte (affidabile
//!   per immagini, video e PDF), poi dall'estensione, infine
//!   `application/octet-stream`. Non fallisce mai per un formato
//!   sconosciuto.
//! - [`is_potentially_dangerous`]: estensioni di programmi/script per
//!   cui l'app chiede conferma prima di aprire il file.

/// Tipo usato quando non si riesce a riconoscere il contenuto.
pub const GENERIC_MIME: &str = "application/octet-stream";

/// Nome proposto quando il messaggio non ne contiene uno utilizzabile.
pub const FALLBACK_FILE_NAME: &str = "file-decifrato";

/// Lunghezza massima (in byte UTF-8) di un nome file dopo la
/// sanificazione: ben sotto i 255 byte che impongono la maggior parte
/// dei file system e il pacchetto "dati letterali" di OpenPGP.
pub const MAX_FILE_NAME_BYTES: usize = 200;

/// Famiglia di un allegato, usata dall'interfaccia per scegliere
/// l'icona (e per sapere se esiste un'anteprima).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Image,
    Video,
    Pdf,
    Document,
    Spreadsheet,
    Presentation,
    Audio,
    Archive,
    Text,
    Generic,
}

impl Category {
    /// Identificatore stabile scambiato con il frontend.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Image => "immagine",
            Category::Video => "video",
            Category::Pdf => "pdf",
            Category::Document => "documento",
            Category::Spreadsheet => "foglio",
            Category::Presentation => "presentazione",
            Category::Audio => "audio",
            Category::Archive => "archivio",
            Category::Text => "testo",
            Category::Generic => "generico",
        }
    }
}

/// Caratteri da eliminare del tutto da un nome file: controllo (compreso
/// NUL), controlli di direzione del testo e caratteri a larghezza zero.
/// Con un RLO, `"fattura\u{202E}fdp.exe"` si leggerebbe come
/// `fatturaexe.pdf`: un eseguibile travestito da PDF.
fn is_invisible_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
            | '\u{2028}' | '\u{2029}'
        )
}

/// Caratteri vietati nei nomi file di Windows (e comunque da evitare
/// ovunque): vengono sostituiti da `_`.
fn is_windows_forbidden(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

fn is_windows_reserved_stem(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0')
}

/// Accorcia `name` a `max_bytes` byte UTF-8 senza spezzare un carattere,
/// conservando l'estensione (se ragionevole) così il file resta
/// riconoscibile dal sistema.
pub fn shorten_filename(name: &str, max_bytes: usize) -> String {
    if name.len() <= max_bytes {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        // Una "estensione" lunghissima non è una vera estensione.
        Some(i) if i > 0 && name.len() - i <= 17 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let budget = max_bytes.saturating_sub(ext.len());
    let mut end = budget.min(stem.len());
    while end > 0 && !stem.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &stem[..end], ext)
}

/// Riduce un nome file *non fidato* a un nome base sicuro, oppure
/// `None` se non ne resta nulla di utilizzabile (l'chiamante userà
/// allora [`FALLBACK_FILE_NAME`]).
///
/// Si fa SEMPRE, a prescindere dal sistema operativo in uso: un
/// messaggio creato su Windows con `C:\Users\x\fattura.pdf` deve
/// ridursi a `fattura.pdf` anche su Mac, e viceversa.
pub fn sanitize_filename(name: &str) -> Option<String> {
    // 1. Solo l'ultimo componente del percorso, con entrambi i
    //    separatori. `..\..\x` e `../../x` diventano `x`.
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");

    // 2. Via i caratteri di controllo e invisibili; sostituiti da `_`
    //    quelli vietati da Windows.
    let cleaned: String = base
        .chars()
        .filter(|c| !is_invisible_or_control(*c))
        .map(|c| if is_windows_forbidden(c) { '_' } else { c })
        .collect();
    let mut cleaned = cleaned;

    // 3. Niente sequenze `..` (anche se, ridotto al nome base, non
    //    potrebbero più risalire di cartella: meglio non lasciarle).
    while cleaned.contains("..") {
        cleaned = cleaned.replace("..", ".");
    }

    // 4. Windows scarta in silenzio spazi e punti finali: meglio
    //    toglierli qui, così il nome mostrato è quello che finisce
    //    davvero su disco.
    let trimmed = cleaned.trim_matches(|c: char| c.is_whitespace());
    let trimmed = trimmed.trim_end_matches(['.', ' ']);
    let trimmed = trimmed.trim_start();

    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        return None;
    }

    // 5. Nomi riservati di Windows (CON, NUL, COM1...): con o senza
    //    estensione. Si prefissa invece di rifiutare.
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let mut result = if is_windows_reserved_stem(stem) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    };

    // 6. Lunghezza.
    result = shorten_filename(&result, MAX_FILE_NAME_BYTES);

    // Il troncamento può aver lasciato spazi o punti in coda.
    let result = result.trim_end_matches(['.', ' ']).to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Come [`sanitize_filename`], con [`FALLBACK_FILE_NAME`] quando non
/// resta niente.
pub fn sanitize_filename_or_fallback(name: Option<&str>) -> String {
    name.and_then(sanitize_filename)
        .unwrap_or_else(|| FALLBACK_FILE_NAME.to_string())
}

/// Estensione in minuscolo (senza il punto), se il nome ne ha una.
pub fn extension_of(filename: &str) -> Option<String> {
    let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Estensioni di programmi, script, pacchetti di installazione e
/// documenti con macro: aprirli può eseguire codice. Il salvataggio
/// resta sempre possibile; è solo l'apertura a richiedere conferma.
const DANGEROUS_EXTENSIONS: &[&str] = &[
    // Windows
    "exe", "msi", "msp", "bat", "cmd", "com", "scr", "pif", "lnk", "reg", "hta", "cpl", "msc",
    "dll", "sys", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "psd1", "gadget", "inf", "appx",
    "msix",
    // macOS
    "app", "dmg", "pkg", "command", "scpt", "applescript", "workflow", "action", "terminal",
    // Linux / Unix
    "sh", "bash", "zsh", "csh", "ksh", "run", "bin", "appimage", "deb", "rpm", "desktop",
    // Android / Java
    "apk", "aab", "xapk", "jar", "jnlp", "class",
    // Script e ricerche di rete
    "js", "jse", "mjs", "py", "pyw", "pl", "rb", "php", "url", "webloc", "chm", "iso", "img",
    // Documenti Office con macro
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
];

/// Vero se il nome indica un file che, aperto, potrebbe eseguire codice.
/// Conta l'ULTIMA estensione: `fattura.pdf.exe` è un `.exe`.
pub fn is_potentially_dangerous(filename: &str) -> bool {
    extension_of(filename)
        .map(|ext| DANGEROUS_EXTENSIONS.contains(&ext.as_str()))
        .unwrap_or(false)
}

/// Riconosce dai primi byte i formati per cui il tipo si può stabilire
/// con certezza (immagini, video, PDF): non cambia cifrando/decifrando
/// e funziona anche se chi ha cifrato ha usato un programma che non
/// imposta il nome file.
pub fn detect_mime_from_magic(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    // GIF, sia la variante storica "87a" sia "89a" (quella con
    // animazione): la mostra un normale tag <img>, che anima da solo.
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if data.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some("image/webp");
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
        // Le varianti più comuni del brand MP4 (ISO Base Media / MPEG-4).
        if matches!(
            brand,
            b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1" | b"M4V " | b"M4A " | b"3gp4" | b"3gp5"
        ) {
            return Some("video/mp4");
        }
    }
    // Alcuni file .mov più vecchi non hanno un box "ftyp" iniziale:
    // iniziano direttamente con uno dei box QuickTime più comuni.
    if data.len() > 8 && matches!(&data[4..8], b"moov" | b"mdat" | b"free" | b"wide") {
        return Some("video/quicktime");
    }
    None
}

/// Tipo dedotto dalla sola estensione del nome file.
pub fn mime_from_extension(filename: &str) -> Option<&'static str> {
    let ext = extension_of(filename)?;
    Some(match ext.as_str() {
        // Immagini e video (stessi tipi che l'app sa già mostrare).
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mov" => "video/quicktime",
        "mp4" | "m4v" => "video/mp4",
        // Documenti.
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "rtf" => "application/rtf",
        // Testo.
        "txt" | "log" => "text/plain",
        "csv" => "text/csv",
        "md" => "text/markdown",
        "json" => "application/json",
        "xml" => "application/xml",
        // Archivi.
        "zip" => "application/zip",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        // Audio.
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        _ => return None,
    })
}

/// Tipo di un file: prima i primi byte, poi l'estensione, infine
/// [`GENERIC_MIME`]. Non fallisce mai.
pub fn resolve_mime(head: &[u8], filename: Option<&str>) -> &'static str {
    detect_mime_from_magic(head)
        .or_else(|| filename.and_then(mime_from_extension))
        .unwrap_or(GENERIC_MIME)
}

/// Estensione (con il punto) da aggiungere a un file senza nome quando il
/// tipo si e' potuto riconoscere dal contenuto: senza estensione, su
/// Windows un PDF non si aprirebbe con il lettore giusto.
pub fn default_extension_for_mime(mime: &str) -> Option<&'static str> {
    Some(match mime {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "image/heic" => ".heic",
        "video/mp4" => ".mp4",
        "video/quicktime" => ".mov",
        "application/pdf" => ".pdf",
        _ => return None,
    })
}

/// Famiglia di un allegato dal tipo (già risolto con [`resolve_mime`]).
pub fn category_for_mime(mime: &str) -> Category {
    match mime {
        "image/jpeg" | "image/png" | "image/gif" | "image/webp" | "image/heic" | "image/heif" => {
            Category::Image
        }
        m if m.starts_with("video/") => Category::Video,
        "application/pdf" => Category::Pdf,
        "application/msword"
        | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        | "application/vnd.oasis.opendocument.text"
        | "application/rtf" => Category::Document,
        "application/vnd.ms-excel"
        | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        | "application/vnd.oasis.opendocument.spreadsheet"
        | "text/csv" => Category::Spreadsheet,
        "application/vnd.ms-powerpoint"
        | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        | "application/vnd.oasis.opendocument.presentation" => Category::Presentation,
        m if m.starts_with("audio/") => Category::Audio,
        "application/zip"
        | "application/x-7z-compressed"
        | "application/vnd.rar"
        | "application/x-tar"
        | "application/gzip" => Category::Archive,
        "text/plain" | "text/markdown" | "application/json" | "application/xml" => Category::Text,
        _ => Category::Generic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- sanitize_filename ----------

    #[test]
    fn plain_names_are_unchanged() {
        assert_eq!(sanitize_filename("fattura.pdf").as_deref(), Some("fattura.pdf"));
        assert_eq!(
            sanitize_filename("Relazione finale (v2).docx").as_deref(),
            Some("Relazione finale (v2).docx")
        );
        assert_eq!(sanitize_filename("città perché.txt").as_deref(), Some("città perché.txt"));
    }

    #[test]
    fn path_traversal_is_reduced_to_the_base_name() {
        assert_eq!(sanitize_filename("../../qualcosa").as_deref(), Some("qualcosa"));
        assert_eq!(sanitize_filename("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(sanitize_filename("a/b/../../c.txt").as_deref(), Some("c.txt"));
        assert_eq!(
            sanitize_filename("..\\..\\Windows\\System32\\evil.dll").as_deref(),
            Some("evil.dll")
        );
        assert_eq!(sanitize_filename("/etc/cron.d/x").as_deref(), Some("x"));
        assert_eq!(sanitize_filename("C:\\Users\\Mario\\fattura.pdf").as_deref(), Some("fattura.pdf"));
        // Mescolando i due separatori.
        assert_eq!(sanitize_filename("..\\../x.txt").as_deref(), Some("x.txt"));
    }

    #[test]
    fn names_with_nothing_usable_become_none() {
        assert_eq!(sanitize_filename(""), None);
        assert_eq!(sanitize_filename("."), None);
        assert_eq!(sanitize_filename(".."), None);
        assert_eq!(sanitize_filename("...."), None);
        assert_eq!(sanitize_filename("   "), None);
        assert_eq!(sanitize_filename("cartella/"), None);
        assert_eq!(sanitize_filename("../"), None);
        assert_eq!(sanitize_filename("\0\0"), None);
    }

    #[test]
    fn control_characters_and_nul_bytes_are_removed() {
        assert_eq!(sanitize_filename("evil\0.pdf").as_deref(), Some("evil.pdf"));
        assert_eq!(sanitize_filename("a\nb\r\tc.txt").as_deref(), Some("abc.txt"));
        assert_eq!(sanitize_filename("x\u{7f}y.txt").as_deref(), Some("xy.txt"));
    }

    #[test]
    fn right_to_left_override_cannot_disguise_an_executable() {
        // "fattura" + RLO + "fdp.exe" si leggerebbe come "fatturaexe.pdf".
        let cleaned = sanitize_filename("fattura\u{202E}fdp.exe").unwrap();
        assert_eq!(cleaned, "fatturafdp.exe");
        assert!(is_potentially_dangerous(&cleaned));
        // Nessun carattere invisibile ammesso.
        assert!(!cleaned.chars().any(|c| ('\u{202A}'..='\u{202E}').contains(&c)));
        assert_eq!(sanitize_filename("a\u{200B}b\u{FEFF}c.txt").as_deref(), Some("abc.txt"));
    }

    #[test]
    fn windows_forbidden_characters_are_replaced() {
        assert_eq!(
            sanitize_filename("a<b>c:d\"e|f?g*h.txt").as_deref(),
            Some("a_b_c_d_e_f_g_h.txt")
        );
    }

    #[test]
    fn dot_dot_sequences_inside_the_name_are_collapsed() {
        assert_eq!(sanitize_filename("a..b.txt").as_deref(), Some("a.b.txt"));
        assert_eq!(sanitize_filename("a....b").as_deref(), Some("a.b"));
    }

    #[test]
    fn trailing_dots_and_spaces_are_dropped_like_windows_would() {
        assert_eq!(sanitize_filename("relazione.pdf. . ").as_deref(), Some("relazione.pdf"));
        assert_eq!(sanitize_filename("  nome.txt").as_deref(), Some("nome.txt"));
    }

    #[test]
    fn windows_reserved_device_names_are_prefixed() {
        assert_eq!(sanitize_filename("CON").as_deref(), Some("_CON"));
        assert_eq!(sanitize_filename("nul.txt").as_deref(), Some("_nul.txt"));
        assert_eq!(sanitize_filename("COM1.pdf").as_deref(), Some("_COM1.pdf"));
        assert_eq!(sanitize_filename("lpt9").as_deref(), Some("_lpt9"));
        // Ma un nome che li contiene soltanto è normale.
        assert_eq!(sanitize_filename("console.txt").as_deref(), Some("console.txt"));
        assert_eq!(sanitize_filename("COM0.txt").as_deref(), Some("COM0.txt"));
    }

    #[test]
    fn very_long_names_are_shortened_keeping_the_extension() {
        let long = format!("{}.pdf", "a".repeat(500));
        let cleaned = sanitize_filename(&long).unwrap();
        assert!(cleaned.len() <= MAX_FILE_NAME_BYTES);
        assert!(cleaned.ends_with(".pdf"));

        // Senza spezzare un carattere multibyte.
        let long = format!("{}.docx", "è".repeat(300));
        let cleaned = sanitize_filename(&long).unwrap();
        assert!(cleaned.len() <= MAX_FILE_NAME_BYTES);
        assert!(cleaned.ends_with(".docx"));
        assert!(cleaned.is_char_boundary(cleaned.len()));

        // Una "estensione" interminabile non viene conservata per intero.
        let weird = format!("x.{}", "b".repeat(400));
        assert!(sanitize_filename(&weird).unwrap().len() <= MAX_FILE_NAME_BYTES);
    }

    #[test]
    fn fallback_is_used_when_nothing_is_left() {
        assert_eq!(sanitize_filename_or_fallback(None), FALLBACK_FILE_NAME);
        assert_eq!(sanitize_filename_or_fallback(Some("../")), FALLBACK_FILE_NAME);
        assert_eq!(sanitize_filename_or_fallback(Some("ok.txt")), "ok.txt");
    }

    #[test]
    fn sanitized_names_never_contain_separators_or_traversal() {
        let hostile = [
            "../../../x",
            "..\\..\\x",
            "....//....//x",
            "x/../../y",
            "/absolute/x",
            "\\\\server\\share\\x",
            "x\0/../y",
            ".../x",
            "a\\..\\..\\b",
        ];
        for name in hostile {
            if let Some(cleaned) = sanitize_filename(name) {
                assert!(!cleaned.contains('/'), "{name:?} -> {cleaned:?}");
                assert!(!cleaned.contains('\\'), "{name:?} -> {cleaned:?}");
                assert!(!cleaned.contains(".."), "{name:?} -> {cleaned:?}");
                assert!(!cleaned.contains('\0'), "{name:?} -> {cleaned:?}");
            }
        }
    }

    // ---------- pericolosità ----------

    #[test]
    fn executables_and_scripts_are_flagged() {
        for name in [
            "setup.exe", "INSTALL.MSI", "run.bat", "x.cmd", "go.sh", "app.apk", "Tool.app",
            "disco.dmg", "lib.jar", "s.scr", "a.js", "a.vbs", "a.ps1", "pkg.deb", "x.AppImage",
            "macro.xlsm", "fattura.pdf.exe",
        ] {
            assert!(is_potentially_dangerous(name), "{name} dovrebbe essere segnalato");
        }
    }

    #[test]
    fn ordinary_documents_are_not_flagged() {
        for name in [
            "a.pdf", "a.docx", "a.xlsx", "a.pptx", "a.odt", "a.txt", "a.csv", "a.zip", "a.mp3",
            "a.jpg", "senza_estensione", "exe", ".exe", "a.pdf.txt",
        ] {
            assert!(!is_potentially_dangerous(name), "{name} non dovrebbe essere segnalato");
        }
    }

    // ---------- tipo del contenuto ----------

    #[test]
    fn magic_bytes_identify_images_video_and_pdf() {
        assert_eq!(detect_mime_from_magic(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(
            detect_mime_from_magic(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0]),
            Some("image/png")
        );
        assert_eq!(detect_mime_from_magic(b"GIF89a\x01\x00"), Some("image/gif"));
        assert_eq!(detect_mime_from_magic(b"GIF87a\x01\x00"), Some("image/gif"));
        assert_eq!(detect_mime_from_magic(b"%PDF-1.7\n"), Some("application/pdf"));
        assert_eq!(detect_mime_from_magic(b"RIFF\x00\x00\x00\x00WEBPVP8 "), Some("image/webp"));

        let mut mp4 = vec![0u8; 4];
        mp4.extend_from_slice(b"ftypisom\0\0\0\0");
        assert_eq!(detect_mime_from_magic(&mp4), Some("video/mp4"));
        let mut mov = vec![0u8; 4];
        mov.extend_from_slice(b"ftypqt  \0\0\0\0");
        assert_eq!(detect_mime_from_magic(&mov), Some("video/quicktime"));
        let mut heic = vec![0u8; 4];
        heic.extend_from_slice(b"ftypheic\0\0\0\0");
        assert_eq!(detect_mime_from_magic(&heic), Some("image/heic"));
        let mut old_mov = vec![0u8; 4];
        old_mov.extend_from_slice(b"moov\0\0\0\0\0");
        assert_eq!(detect_mime_from_magic(&old_mov), Some("video/quicktime"));
    }

    #[test]
    fn text_or_unknown_bytes_have_no_magic_type() {
        assert_eq!(detect_mime_from_magic(b"ciao, sono testo normale"), None);
        assert_eq!(detect_mime_from_magic(b"GIF ma non davvero"), None);
        assert_eq!(detect_mime_from_magic(b""), None);
        assert_eq!(detect_mime_from_magic(b"%PD"), None);
    }

    #[test]
    fn extension_table_covers_the_common_formats() {
        let cases = [
            ("a.pdf", "application/pdf"),
            ("a.doc", "application/msword"),
            ("a.DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            ("a.xls", "application/vnd.ms-excel"),
            ("a.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            ("a.ppt", "application/vnd.ms-powerpoint"),
            ("a.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
            ("a.odt", "application/vnd.oasis.opendocument.text"),
            ("a.ods", "application/vnd.oasis.opendocument.spreadsheet"),
            ("a.odp", "application/vnd.oasis.opendocument.presentation"),
            ("a.txt", "text/plain"),
            ("a.csv", "text/csv"),
            ("a.rtf", "application/rtf"),
            ("a.zip", "application/zip"),
            ("a.mp3", "audio/mpeg"),
            ("a.m4a", "audio/mp4"),
            ("a.wav", "audio/wav"),
            ("a.ogg", "audio/ogg"),
        ];
        for (name, mime) in cases {
            assert_eq!(mime_from_extension(name), Some(mime), "{name}");
        }
    }

    #[test]
    fn unknown_formats_fall_back_to_the_generic_type_without_failing() {
        assert_eq!(resolve_mime(b"\x01\x02\x03", Some("dati.xyz")), GENERIC_MIME);
        assert_eq!(resolve_mime(b"\x01\x02\x03", None), GENERIC_MIME);
        assert_eq!(resolve_mime(b"", Some("senza_estensione")), GENERIC_MIME);
        assert_eq!(resolve_mime(b"", Some("")), GENERIC_MIME);
    }

    #[test]
    fn content_wins_over_the_declared_extension() {
        // Un PNG chiamato .pdf è un PNG: si decide dal contenuto.
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert_eq!(resolve_mime(&png, Some("finto.pdf")), "image/png");
        // Se il contenuto non è riconoscibile si usa l'estensione.
        assert_eq!(resolve_mime(b"PK\x03\x04....", Some("a.docx")),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    }

    #[test]
    fn categories_drive_the_icon_choice() {
        assert_eq!(category_for_mime("image/png"), Category::Image);
        assert_eq!(category_for_mime("video/mp4"), Category::Video);
        assert_eq!(category_for_mime("application/pdf"), Category::Pdf);
        assert_eq!(
            category_for_mime("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            Category::Document
        );
        assert_eq!(category_for_mime("text/csv"), Category::Spreadsheet);
        assert_eq!(
            category_for_mime("application/vnd.ms-powerpoint"),
            Category::Presentation
        );
        assert_eq!(category_for_mime("audio/mpeg"), Category::Audio);
        assert_eq!(category_for_mime("application/zip"), Category::Archive);
        assert_eq!(category_for_mime("text/plain"), Category::Text);
        assert_eq!(category_for_mime(GENERIC_MIME), Category::Generic);
        assert_eq!(category_for_mime("qualcosa/di-strano"), Category::Generic);
        // L'SVG può contenere script: non si tratta come immagine.
        assert_eq!(category_for_mime("image/svg+xml"), Category::Generic);
    }
}
