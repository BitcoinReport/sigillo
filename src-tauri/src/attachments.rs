//! Allegati decifrati: dove finiscono su disco, come si descrivono al
//! frontend e come si ripuliscono.
//!
//! Principio: il contenuto di un allegato NON attraversa mai il ponte
//! JS/Rust (IPC). Chi decifra scrive il file in una cartella privata
//! dell'app e il frontend riceve solo il percorso e i metadati. Cosi' un
//! PDF da 40 MB o un video non finiscono in una stringa gigante (che su
//! alcune webview, Android in testa, arriva troncata o a 0 byte), e il
//! file puo' essere salvato o aperto direttamente da disco.

use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sigillo_core::{attachment, composite, settings, timelock};

/// Sopra questa soglia un contenuto senza nome e senza tipo riconoscibile
/// non si tiene in memoria come possibile testo: va su file.
pub const MAX_TEXT_IN_MEMORY: usize = 16 * 1024 * 1024;

/// Quanti byte iniziali si guardano per riconoscere il tipo di un
/// contenuto (e il marcatore dei messaggi combinati / con blocco).
const HEAD_BYTES: usize = 64;

/// Il file temporaneo ha un nome piu' corto di quello mostrato: i
/// percorsi di Windows oltre 260 caratteri mettono in difficolta' molti
/// programmi.
const TEMP_NAME_MAX_BYTES: usize = 100;

static ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------- Cartella privata ----------

/// La cartella privata dell'app dove si scrivono gli allegati decifrati
/// (in chiaro!) per anteprima, apertura o salvataggio. Ogni allegato ha
/// una sottocartella propria, cosi' il file mantiene il suo nome vero
/// (le app lo riconoscono dall'estensione) senza rischio di collisioni.
pub struct AttachmentStore {
    root: PathBuf,
}

#[cfg(unix)]
fn make_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn make_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

impl AttachmentStore {
    pub fn new(root: PathBuf) -> Self {
        AttachmentStore { root }
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Crea una sottocartella nuova e vi apre il file `temp_name`.
    /// Restituisce (cartella, percorso del file, file aperto in scrittura).
    fn create_entry(&self, temp_name: &str) -> io::Result<(PathBuf, PathBuf, File)> {
        make_private_dir(&self.root)?;
        loop {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let n = ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = self.root.join(format!("{:x}-{:x}", nanos, n));
            match fs::DirBuilder::new().create(&dir) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                    }
                    let path = dir.join(temp_name);
                    return match create_private_file(&path) {
                        Ok(file) => Ok((dir, path, file)),
                        Err(e) => {
                            let _ = fs::remove_dir_all(&dir);
                            Err(e)
                        }
                    };
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Vero solo per un file che sta esattamente in
    /// `<cartella privata>/<sottocartella>/<file>`: serve a non lasciare
    /// che il frontend (o un messaggio ostile) faccia salvare, aprire o
    /// cancellare file qualunque del computer passando un percorso a piacere.
    pub fn owns(&self, path: &Path) -> bool {
        let (Ok(root), Ok(file)) = (fs::canonicalize(&self.root), fs::canonicalize(path)) else {
            return false;
        };
        file.is_file() && file.parent().and_then(Path::parent) == Some(root.as_path())
    }

    /// Cancella un allegato (con la sua sottocartella). Un percorso
    /// fuori dalla cartella privata viene rifiutato; uno gia'
    /// inesistente e' un successo (e' lo stato voluto).
    pub fn discard(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        if !self.owns(path) {
            bail!("il file non e' un allegato decifrato di Sigillo");
        }
        let dir = fs::canonicalize(path)?
            .parent()
            .map(Path::to_path_buf)
            .context("percorso non valido")?;
        fs::remove_dir_all(dir).context("impossibile eliminare il file temporaneo")
    }

    /// Elimina tutti gli allegati decifrati rimasti (all'avvio e alla
    /// chiusura dell'app), compresa la vecchia cartella nella directory
    /// temporanea di sistema usata dalle versioni precedenti.
    pub fn purge(&self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(std::env::temp_dir().join("sigillo-anteprime"));
    }
}

/// Tiene traccia dei file scritti durante UNA decifratura: se non si
/// conferma con [`Session::commit`] (perche' e' andato storto qualcosa,
/// o perche' al termine il messaggio non e' risultato autentico) tutto
/// quello che si era scritto viene rimosso. Cosi' un messaggio troncato
/// o manomesso non lascia mai in giro file decifrati a meta'.
pub struct Session<'a> {
    store: &'a AttachmentStore,
    dirs: RefCell<Vec<PathBuf>>,
    committed: Cell<bool>,
}

impl<'a> Session<'a> {
    pub fn new(store: &'a AttachmentStore) -> Self {
        Session {
            store,
            dirs: RefCell::new(Vec::new()),
            committed: Cell::new(false),
        }
    }

    pub fn commit(&self) {
        self.committed.set(true);
    }

    /// Butta via quello che e' stato scritto finora (un tentativo di
    /// decifratura fallito), lasciando la sessione pronta per un altro.
    pub fn rollback(&self) {
        for dir in self.dirs.borrow_mut().drain(..) {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if !self.committed.get() {
            self.rollback();
        }
    }
}

// ---------- Descrizione per il frontend ----------

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct AttachmentView {
    /// Percorso del file decifrato nella cartella privata dell'app.
    pub path: String,
    /// Nome da mostrare / proporre per il salvataggio: gia' sanificato.
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// "immagine", "video", "pdf", "documento", "foglio", "presentazione",
    /// "audio", "archivio", "testo" o "generico": sceglie anteprima o icona.
    pub category: String,
    /// Programma o script: aprirlo richiede conferma esplicita.
    pub dangerous: bool,
}

/// Il risultato dell'interpretazione di un contenuto decifrato, prima
/// di aggiungervi lo stato della firma.
#[derive(Debug, Default)]
pub struct Processed {
    /// "testo", "allegato", "combinato" o "bloccato_nel_tempo".
    pub kind: &'static str,
    pub plaintext: Option<String>,
    pub attachment: Option<AttachmentView>,
    pub target_height: Option<u32>,
    pub current_height: Option<u32>,
    pub height_check_error: Option<String>,
}

// ---------- Lettura a flusso ----------

/// Un lettore su cui si puo' "sbirciare" i primi byte senza consumarli.
pub struct Peek<'r> {
    buf: Vec<u8>,
    pos: usize,
    inner: &'r mut dyn Read,
}

impl<'r> Peek<'r> {
    pub fn new(inner: &'r mut dyn Read) -> Self {
        Peek {
            buf: Vec::new(),
            pos: 0,
            inner,
        }
    }

    /// Fino a `n` byte dall'inizio di quello che resta da leggere (meno
    /// solo se il flusso finisce prima).
    pub fn peek(&mut self, n: usize) -> io::Result<&[u8]> {
        while self.buf.len() - self.pos < n {
            let mut chunk = [0u8; 8192];
            let read = self.inner.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            self.buf.extend_from_slice(&chunk[..read]);
        }
        let end = (self.pos + n).min(self.buf.len());
        Ok(&self.buf[self.pos..end])
    }
}

impl Read for Peek<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.buf.len() {
            let available = &self.buf[self.pos..];
            let n = available.len().min(out.len());
            out[..n].copy_from_slice(&available[..n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Ok(n);
        }
        self.inner.read(out)
    }
}

/// Nome del file temporaneo: corto e senza punti iniziali (sono nomi
/// "nascosti" e sfuggono ai permessi di accesso ai file dell'anteprima).
fn temp_file_name(display_name: &str) -> String {
    let short = attachment::shorten_filename(display_name, TEMP_NAME_MAX_BYTES);
    let stripped = short.trim_start_matches('.');
    if stripped.is_empty() {
        attachment::FALLBACK_FILE_NAME.to_string()
    } else if stripped.len() != short.len() {
        format!("_{stripped}")
    } else {
        short
    }
}

/// Copia `reader` in un nuovo file della cartella privata, riconoscendone
/// il tipo e sanificando il nome (input non fidato). Se `expected_len` e'
/// noto, un file piu' corto (flusso troncato) e' un errore.
pub fn save_stream(
    session: &Session,
    declared_name: Option<&str>,
    reader: &mut dyn Read,
    expected_len: Option<u64>,
) -> Result<AttachmentView> {
    // I primi byte servono a riconoscere il tipo.
    let mut head = Vec::with_capacity(HEAD_BYTES);
    reader
        .take(HEAD_BYTES as u64)
        .read_to_end(&mut head)
        .context("errore durante la lettura del contenuto decifrato")?;

    let usable_name = declared_name.and_then(attachment::sanitize_filename);
    let mut name = usable_name
        .clone()
        .unwrap_or_else(|| attachment::FALLBACK_FILE_NAME.to_string());
    let mime = attachment::resolve_mime(&head, Some(&name));
    if usable_name.is_none() {
        // Senza un nome, almeno un'estensione se il tipo e' riconosciuto.
        if let Some(ext) = attachment::default_extension_for_mime(mime) {
            name.push_str(ext);
        }
    }

    let (dir, path, file) = session
        .store
        .create_entry(&temp_file_name(&name))
        .context("impossibile creare il file temporaneo")?;
    session.dirs.borrow_mut().push(dir);

    let mut out = BufWriter::new(file);
    out.write_all(&head).context("impossibile scrivere il file temporaneo")?;
    let mut size = head.len() as u64;
    size += io::copy(reader, &mut out).context("errore durante la lettura del contenuto decifrato")?;
    out.flush().context("impossibile scrivere il file temporaneo")?;

    if let Some(expected) = expected_len {
        if size != expected {
            bail!("allegato troncato: il messaggio e' incompleto o danneggiato");
        }
    }

    Ok(AttachmentView {
        path: path.to_string_lossy().into_owned(),
        dangerous: attachment::is_potentially_dangerous(&name),
        category: attachment::category_for_mime(mime).as_str().to_string(),
        mime: mime.to_string(),
        name,
        size,
    })
}

/// Il nome incorporato nel messaggio, se utilizzabile.
fn usable_literal_name(name: Option<String>) -> Option<String> {
    name.filter(|n| !n.trim().is_empty())
}

fn attachment_only(view: AttachmentView) -> Processed {
    Processed {
        kind: "allegato",
        attachment: Some(view),
        ..Default::default()
    }
}

/// Interpreta un contenuto decifrato (letto a flusso) e lo traduce in
/// quello che vede l'utente: testo, allegato su file, o blocco temporale.
fn classify(
    stream: &mut Peek,
    literal_filename: &dyn Fn() -> Option<String>,
    session: &Session,
) -> Result<Processed> {
    let head = stream.peek(HEAD_BYTES)?.to_vec();

    // Prima di tutto: un pacchetto combinato non ha i byte magici di
    // un'immagine pura, ma per puro caso i suoi byte potrebbero essere
    // UTF-8 valido e finire scambiati per testo semplice.
    if composite::is_combined(&head) {
        let header = composite::read_header(stream)?;
        let mut body = (&mut *stream).take(header.attachment_len);
        // Il tipo dichiarato dal mittente non si usa: lo decidiamo noi
        // dal contenuto e dal nome (gia' sanificato in save_stream).
        let view = save_stream(
            session,
            header.attachment_filename.as_deref(),
            &mut body,
            Some(header.attachment_len),
        )?;
        let with_text = !header.text.is_empty();
        return Ok(Processed {
            kind: if with_text { "combinato" } else { "allegato" },
            plaintext: with_text.then_some(header.text),
            attachment: Some(view),
            ..Default::default()
        });
    }

    let filename = usable_literal_name(literal_filename());
    if filename.is_some() || attachment::detect_mime_from_magic(&head).is_some() {
        // Un file vero e proprio (cifrato da Sigillo come solo allegato, o
        // da un altro programma OpenPGP): ha un nome, o un contenuto
        // riconoscibile come immagine, video o PDF.
        let view = save_stream(session, filename.as_deref(), stream, None)?;
        return Ok(attachment_only(view));
    }

    // Niente nome e niente tipo riconoscibile: di solito e' testo.
    let mut buf = Vec::new();
    (&mut *stream)
        .take(MAX_TEXT_IN_MEMORY as u64 + 1)
        .read_to_end(&mut buf)
        .context("errore durante la lettura del contenuto decifrato")?;
    if buf.len() <= MAX_TEXT_IN_MEMORY {
        match String::from_utf8(buf) {
            Ok(text) => {
                return Ok(Processed {
                    kind: "testo",
                    plaintext: Some(text),
                    ..Default::default()
                })
            }
            Err(e) => buf = e.into_bytes(),
        }
    }
    // Binario senza nome (o testo enorme): su file, senza tenerlo in memoria.
    let mut whole = io::Cursor::new(buf).chain(&mut *stream);
    let view = save_stream(session, None, &mut whole, None)?;
    Ok(attachment_only(view))
}

/// Punto d'ingresso: legge il contenuto decifrato da `plain` e lo
/// interpreta. `fetch_height(endpoint, usa_tor)` verifica l'altezza
/// blocco corrente (iniettata per poterla sostituire nei test).
pub fn process_plaintext(
    plain: &mut dyn Read,
    literal_filename: &dyn Fn() -> Option<String>,
    settings: &settings::Settings,
    session: &Session,
    fetch_height: &dyn Fn(&str, bool) -> Result<u32, String>,
) -> Result<Processed> {
    let mut stream = Peek::new(plain);
    let head = stream.peek(HEAD_BYTES)?.to_vec();

    // Il blocco temporale e' una funzione *sperimentale*: finche' l'utente
    // non l'ha attivata (default: spenta), un messaggio marcato come
    // "bloccato nel tempo" NON deve essere processato come tale — in
    // particolare non deve far partire la verifica dell'altezza blocco,
    // che e' una richiesta di rete verso un endpoint indicato *dentro* il
    // messaggio dal mittente: aprire un messaggio ostile equivarrebbe a
    // un "tracking pixel" (rivela IP e orario di apertura) e a un
    // possibile SSRF verso risorse di rete interne, all'insaputa di chi
    // non ha mai toccato le funzioni sperimentali. A funzione spenta lo
    // trattiamo come un normale dato binario (salvabile come file).
    if !(settings.experimental_features_enabled && timelock::is_timelocked(&head)) {
        return classify(&mut stream, literal_filename, session);
    }

    let header = timelock::read_header(&mut stream)?;
    let locked = |current_height: Option<u32>, error: Option<String>| Processed {
        kind: "bloccato_nel_tempo",
        target_height: Some(header.target_height),
        current_height,
        height_check_error: error,
        ..Default::default()
    };

    // Un endpoint incluso nel messaggio e' scelto dal mittente, non da chi
    // riceve: prima di contattarlo va ristretto (solo https, niente IP
    // letterali o localhost).
    if let Some(sender_endpoint) = header
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        if let Err(why) = super::validate_sender_supplied_endpoint(sender_endpoint) {
            return Ok(locked(None, Some(why)));
        }
    }

    let endpoint = super::effective_endpoint(header.endpoint.as_deref());
    let use_tor = super::should_use_tor(&endpoint, settings.tor_enabled);
    match fetch_height(&endpoint, use_tor) {
        Ok(current) if current >= header.target_height => {
            // Altezza raggiunta: si mostra il contenuto interno come al
            // solito, con in piu' l'indicazione che era (ed e' ora) sbloccato.
            let mut inner_reader = (&mut stream).take(header.inner_len);
            let mut inner = Peek::new(&mut inner_reader);
            let mut processed = classify(&mut inner, literal_filename, session)?;
            // Il resto del contenuto interno, se classify non l'ha letto.
            io::copy(&mut inner, &mut io::sink())
                .context("errore durante la lettura del contenuto decifrato")?;
            processed.target_height = Some(header.target_height);
            processed.current_height = Some(current);
            Ok(processed)
        }
        Ok(current) => Ok(locked(Some(current), None)),
        Err(error) => Ok(locked(None, Some(error))),
    }
}

// ---------- Salvataggio, apertura ----------

/// Copia un allegato decifrato nella destinazione scelta dall'utente.
/// Rifiuta qualunque origine che non sia nella cartella privata.
pub fn copy_to_destination(store: &AttachmentStore, temp_path: &Path, dest_path: &Path) -> Result<()> {
    if !store.owns(temp_path) {
        bail!("il file non e' un allegato decifrato di Sigillo");
    }
    fs::copy(temp_path, dest_path).context("impossibile salvare il file")?;
    Ok(())
}

/// Controlla se un allegato si puo' aprire: i programmi e gli script
/// richiedono una conferma esplicita.
pub fn check_open_allowed(store: &AttachmentStore, path: &Path, confirmed: bool) -> Result<()> {
    if !store.owns(path) {
        bail!("il file non e' un allegato decifrato di Sigillo");
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if attachment::is_potentially_dangerous(&name) && !confirmed {
        bail!("questo file e' un programma: serve la conferma esplicita per aprirlo");
    }
    Ok(())
}

/// Informazioni su un file scelto per essere allegato (nome, tipo,
/// dimensione): le stesse regole usate poi alla cifratura.
#[derive(Serialize, Debug)]
pub struct AttachmentInfo {
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub category: String,
    pub dangerous: bool,
    /// Oltre questo limite l'allegato non si puo' combinare con un testo
    /// o bloccare nel tempo (il formato usa 4 byte per la lunghezza).
    pub too_large: bool,
}

pub fn describe_source_file(path: &Path) -> Result<AttachmentInfo> {
    let meta = fs::metadata(path).context("impossibile leggere il file")?;
    if !meta.is_file() {
        bail!("puoi allegare solo un file, non una cartella");
    }
    let mut head = Vec::with_capacity(HEAD_BYTES);
    File::open(path)
        .context("impossibile leggere il file")?
        .take(HEAD_BYTES as u64)
        .read_to_end(&mut head)
        .context("impossibile leggere il file")?;

    let name = attachment::sanitize_filename_or_fallback(
        path.file_name().map(|n| n.to_string_lossy()).as_deref(),
    );
    let mime = attachment::resolve_mime(&head, Some(&name));
    Ok(AttachmentInfo {
        dangerous: attachment::is_potentially_dangerous(&name),
        category: attachment::category_for_mime(mime).as_str().to_string(),
        mime: mime.to_string(),
        size: meta.len(),
        too_large: meta.len() > composite::MAX_ATTACHMENT_BYTES,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

    fn store() -> (tempfile::TempDir, AttachmentStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = AttachmentStore::new(dir.path().join("anteprime"));
        (dir, store)
    }

    fn never_fetch(_: &str, _: bool) -> Result<u32, String> {
        panic!("non doveva partire nessuna verifica dell'altezza blocco");
    }

    fn settings(experimental: bool) -> settings::Settings {
        let mut s = settings::Settings::default();
        s.experimental_features_enabled = experimental;
        s
    }

    fn run(
        store: &AttachmentStore,
        data: Vec<u8>,
        literal_name: Option<&str>,
        experimental: bool,
        fetch: &dyn Fn(&str, bool) -> Result<u32, String>,
    ) -> Result<(Processed, bool)> {
        let session = Session::new(store);
        let name = literal_name.map(str::to_string);
        let get_name = move || name.clone();
        let mut cursor = Cursor::new(data);
        let processed = process_plaintext(&mut cursor, &get_name, &settings(experimental), &session, fetch)?;
        session.commit();
        let has_file = processed.attachment.is_some();
        Ok((processed, has_file))
    }

    fn read_back(view: &AttachmentView) -> Vec<u8> {
        fs::read(&view.path).unwrap()
    }

    // ---------- cartella privata ----------

    #[test]
    fn each_attachment_gets_its_own_subfolder_keeping_the_file_name() {
        let (_guard, store) = store();
        let (data, _) = run(&store, b"%PDF-1.7 corpo".to_vec(), Some("relazione.pdf"), false, &never_fetch).unwrap();
        let (data2, _) = run(&store, b"%PDF-1.7 altro".to_vec(), Some("relazione.pdf"), false, &never_fetch).unwrap();
        let a = data.attachment.unwrap();
        let b = data2.attachment.unwrap();

        assert_ne!(a.path, b.path, "due allegati con lo stesso nome non devono collidere");
        assert!(Path::new(&a.path).starts_with(store.root()));
        assert_eq!(Path::new(&a.path).file_name().unwrap(), "relazione.pdf");
        assert_eq!(read_back(&a), b"%PDF-1.7 corpo");
        assert_eq!(read_back(&b), b"%PDF-1.7 altro");
    }

    #[cfg(unix)]
    #[test]
    fn the_private_folder_and_files_are_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, store) = store();
        let (p, _) = run(&store, b"%PDF-1.7".to_vec(), Some("a.pdf"), false, &never_fetch).unwrap();
        let path = PathBuf::from(p.attachment.unwrap().path);
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        let root_mode = fs::metadata(store.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
        assert_eq!(root_mode, 0o700);
    }

    #[test]
    fn owns_accepts_only_files_inside_the_private_folder() {
        let (guard, store) = store();
        let (p, _) = run(&store, b"%PDF-1.7".to_vec(), Some("a.pdf"), false, &never_fetch).unwrap();
        let inside = PathBuf::from(p.attachment.unwrap().path);
        assert!(store.owns(&inside));

        // Un file qualunque altrove.
        let outside = guard.path().join("segreto.txt");
        fs::write(&outside, b"x").unwrap();
        assert!(!store.owns(&outside));

        // Risalire di cartella partendo da un percorso valido.
        let sneaky = inside.parent().unwrap().join("..").join("..").join("segreto.txt");
        assert!(!store.owns(&sneaky));
        // La cartella privata stessa e una sottocartella non sono file di allegato.
        assert!(!store.owns(store.root()));
        assert!(!store.owns(inside.parent().unwrap()));
        // Inesistente.
        assert!(!store.owns(&store.root().join("nessuna").join("cosa.txt")));
    }

    #[test]
    fn discard_removes_the_attachment_and_refuses_foreign_paths() {
        let (guard, store) = store();
        let (p, _) = run(&store, b"%PDF-1.7".to_vec(), Some("a.pdf"), false, &never_fetch).unwrap();
        let inside = PathBuf::from(p.attachment.unwrap().path);

        let outside = guard.path().join("importante.txt");
        fs::write(&outside, b"non toccare").unwrap();
        assert!(store.discard(&outside).is_err());
        assert!(outside.exists(), "un file fuori dalla cartella privata non si cancella");

        assert!(store.discard(&inside).is_ok());
        assert!(!inside.exists());
        assert!(!inside.parent().unwrap().exists(), "anche la sottocartella va via");
        // Cancellare di nuovo non e' un errore.
        assert!(store.discard(&inside).is_ok());
    }

    #[test]
    fn purge_removes_everything_left_behind() {
        let (_guard, store) = store();
        for i in 0..3 {
            run(&store, b"%PDF-1.7".to_vec(), Some(&format!("f{i}.pdf")), false, &never_fetch).unwrap();
        }
        assert!(store.root().exists());
        store.purge();
        assert!(!store.root().exists());
    }

    #[test]
    fn an_uncommitted_session_removes_what_it_wrote() {
        // E' cio' che succede con un messaggio che risulta manomesso alla
        // fine: nessun file decifrato a meta' deve restare.
        let (_guard, store) = store();
        let path = {
            let session = Session::new(&store);
            let mut cursor = Cursor::new(b"%PDF-1.7 contenuto".to_vec());
            let view = save_stream(&session, Some("x.pdf"), &mut cursor, None).unwrap();
            assert!(Path::new(&view.path).exists());
            PathBuf::from(view.path)
            // session scartata senza commit
        };
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
    }

    // ---------- interpretazione del contenuto ----------

    #[test]
    fn plain_text_is_text() {
        let (_g, store) = store();
        let (p, _) = run(&store, "Ciao, è un messaggio".as_bytes().to_vec(), None, false, &never_fetch).unwrap();
        assert_eq!(p.kind, "testo");
        assert_eq!(p.plaintext.as_deref(), Some("Ciao, è un messaggio"));
        assert!(p.attachment.is_none());
        assert!(!store.root().exists(), "il testo non scrive nulla su disco");
    }

    #[test]
    fn a_named_pdf_becomes_an_attachment_card_with_its_name_and_size() {
        let (_g, store) = store();
        let pdf = [b"%PDF-1.7\n".to_vec(), vec![0xAB; 5000]].concat();
        let (p, _) = run(&store, pdf.clone(), Some("Bilancio 2025.pdf"), false, &never_fetch).unwrap();
        assert_eq!(p.kind, "allegato");
        let a = p.attachment.unwrap();
        assert_eq!(a.name, "Bilancio 2025.pdf");
        assert_eq!(a.mime, "application/pdf");
        assert_eq!(a.category, "pdf");
        assert_eq!(a.size, pdf.len() as u64);
        assert!(!a.dangerous);
        assert_eq!(read_back(&a), pdf);
    }

    #[test]
    fn a_named_text_file_is_an_attachment_not_a_message() {
        // Un .txt allegato deve tornare come file con il suo nome, non
        // confondersi con il testo di un messaggio.
        let (_g, store) = store();
        let (p, _) = run(&store, "riga 1\nriga 2\n".as_bytes().to_vec(), Some("note.txt"), false, &never_fetch).unwrap();
        assert_eq!(p.kind, "allegato");
        let a = p.attachment.unwrap();
        assert_eq!(a.name, "note.txt");
        assert_eq!(a.category, "testo");
        assert_eq!(read_back(&a), b"riga 1\nriga 2\n");
    }

    #[test]
    fn an_unknown_extension_is_a_generic_attachment_and_never_an_error() {
        let (_g, store) = store();
        let (p, _) = run(&store, vec![1, 2, 3, 0, 255], Some("dati.xyz"), false, &never_fetch).unwrap();
        let a = p.attachment.unwrap();
        assert_eq!(a.name, "dati.xyz");
        assert_eq!(a.mime, "application/octet-stream");
        assert_eq!(a.category, "generico");
    }

    #[test]
    fn images_and_videos_keep_being_recognized_for_preview() {
        let (_g, store) = store();
        let png = [vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], vec![0; 20]].concat();
        let (p, _) = run(&store, png, Some("foto.png"), false, &never_fetch).unwrap();
        let a = p.attachment.unwrap();
        assert_eq!((a.mime.as_str(), a.category.as_str()), ("image/png", "immagine"));

        let mut mp4 = vec![0u8; 4];
        mp4.extend_from_slice(b"ftypisom\0\0\0\0");
        mp4.extend_from_slice(&[0; 30]);
        let (p, _) = run(&store, mp4, Some("clip.mp4"), false, &never_fetch).unwrap();
        let a = p.attachment.unwrap();
        assert_eq!((a.mime.as_str(), a.category.as_str()), ("video/mp4", "video"));

        // Anche senza nome: lo riconosce dal contenuto e gli dà l'estensione.
        let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;".to_vec();
        let (p, _) = run(&store, gif, None, false, &never_fetch).unwrap();
        let a = p.attachment.unwrap();
        assert_eq!(a.mime, "image/gif");
        assert_eq!(a.name, "file-decifrato.gif");
    }

    #[test]
    fn binary_without_name_or_known_type_is_saved_as_a_generic_file() {
        let (_g, store) = store();
        let (p, _) = run(&store, vec![0xFF, 0xFE, 0x00, 0x80, 0x81], None, false, &never_fetch).unwrap();
        assert_eq!(p.kind, "allegato");
        let a = p.attachment.unwrap();
        assert_eq!(a.name, "file-decifrato");
        assert_eq!(a.size, 5);
    }

    #[test]
    fn combined_text_and_pdf_come_back_together() {
        let (_g, store) = store();
        let pdf = [b"%PDF-1.4\n".to_vec(), vec![7; 2000]].concat();
        let combined = composite::encode("Ecco la fattura", Some("fattura.pdf"), "application/pdf", &pdf).unwrap();
        let (p, _) = run(&store, combined, None, false, &never_fetch).unwrap();
        assert_eq!(p.kind, "combinato");
        assert_eq!(p.plaintext.as_deref(), Some("Ecco la fattura"));
        let a = p.attachment.unwrap();
        assert_eq!(a.name, "fattura.pdf");
        assert_eq!(read_back(&a), pdf);
    }

    #[test]
    fn combined_with_empty_text_is_an_attachment() {
        let (_g, store) = store();
        let combined = composite::encode("", Some("a.zip"), "application/zip", b"PK\x03\x04xx").unwrap();
        let (p, _) = run(&store, combined, None, false, &never_fetch).unwrap();
        assert_eq!(p.kind, "allegato");
        assert!(p.plaintext.is_none());
        assert_eq!(p.attachment.unwrap().name, "a.zip");
    }

    #[test]
    fn a_message_from_the_previous_versions_still_opens() {
        // Testo + immagine, nel formato scritto da v0.2.3 in poi.
        let (_g, store) = store();
        let png = [vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], vec![9; 40]].concat();
        let legacy = composite::encode("guarda!", Some("foto.png"), "image/png", &png).unwrap();
        let (p, _) = run(&store, legacy, None, false, &never_fetch).unwrap();
        assert_eq!(p.kind, "combinato");
        assert_eq!(p.plaintext.as_deref(), Some("guarda!"));
        assert_eq!(p.attachment.as_ref().unwrap().category, "immagine");
        assert_eq!(read_back(p.attachment.as_ref().unwrap()), png);

        // Solo immagine, con il nome nel pacchetto OpenPGP.
        let (p, _) = run(&store, png.clone(), Some("foto.jpeg"), false, &never_fetch).unwrap();
        assert_eq!(p.kind, "allegato");
        assert_eq!(read_back(p.attachment.as_ref().unwrap()), png);
    }

    // ---------- sicurezza: nomi ostili ----------

    #[test]
    fn a_hostile_file_name_cannot_write_outside_the_private_folder() {
        let (guard, store) = store();
        let hostile = [
            "../../fuga.txt",
            "..\\..\\fuga.txt",
            "/tmp/fuga.txt",
            "a/../../../fuga.txt",
            "..",
            "../",
            "con\0trollo.txt",
            "\u{202E}gnp.exe",
        ];
        for name in hostile {
            let combined = composite::encode("", Some(name), "application/pdf", b"%PDF-1.7 x").unwrap();
            let (p, _) = run(&store, combined, None, false, &never_fetch).unwrap();
            let a = p.attachment.unwrap();
            let path = PathBuf::from(&a.path);
            assert!(store.owns(&path), "{name:?} -> {path:?} fuori dalla cartella privata");
            assert!(!a.name.contains('/') && !a.name.contains('\\') && !a.name.contains(".."), "{name:?} -> {:?}", a.name);
        }
        // E nulla e' stato scritto accanto o sopra la cartella privata.
        let escaped: Vec<_> = fs::read_dir(guard.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(escaped, vec!["anteprime"], "file fuori posto: {escaped:?}");
    }

    #[test]
    fn a_hostile_literal_data_file_name_is_sanitized_too() {
        let (_g, store) = store();
        let (p, _) = run(&store, b"%PDF-1.7 x".to_vec(), Some("../../../etc/cron.d/x.pdf"), false, &never_fetch).unwrap();
        let a = p.attachment.unwrap();
        assert_eq!(a.name, "x.pdf");
        assert!(store.owns(Path::new(&a.path)));
    }

    #[test]
    fn executable_names_are_flagged_dangerous() {
        let (_g, store) = store();
        for name in ["setup.exe", "script.sh", "app.apk", "x.bat", "fattura.pdf.exe"] {
            let (p, _) = run(&store, b"MZ....".to_vec(), Some(name), false, &never_fetch).unwrap();
            assert!(p.attachment.unwrap().dangerous, "{name}");
        }
        let (p, _) = run(&store, b"%PDF-1.7".to_vec(), Some("ok.pdf"), false, &never_fetch).unwrap();
        assert!(!p.attachment.unwrap().dangerous);
    }

    #[test]
    fn opening_a_program_requires_explicit_confirmation() {
        let (_g, store) = store();
        let (p, _) = run(&store, b"MZ....".to_vec(), Some("setup.exe"), false, &never_fetch).unwrap();
        let path = PathBuf::from(p.attachment.unwrap().path);
        assert!(check_open_allowed(&store, &path, false).is_err());
        assert!(check_open_allowed(&store, &path, true).is_ok());

        let (p, _) = run(&store, b"%PDF-1.7".to_vec(), Some("ok.pdf"), false, &never_fetch).unwrap();
        let pdf = PathBuf::from(p.attachment.unwrap().path);
        assert!(check_open_allowed(&store, &pdf, false).is_ok());
    }

    #[test]
    fn opening_or_saving_a_file_outside_the_private_folder_is_refused() {
        let (guard, store) = store();
        let outside = guard.path().join("estraneo.pdf");
        fs::write(&outside, b"%PDF").unwrap();
        assert!(check_open_allowed(&store, &outside, true).is_err());
        assert!(copy_to_destination(&store, &outside, &guard.path().join("copia.pdf")).is_err());
        assert!(!guard.path().join("copia.pdf").exists());
    }

    #[test]
    fn saving_copies_the_file_and_keeps_the_temporary_until_discarded() {
        let (guard, store) = store();
        let pdf = [b"%PDF-1.7\n".to_vec(), vec![3; 10_000]].concat();
        let (p, _) = run(&store, pdf.clone(), Some("a.pdf"), false, &never_fetch).unwrap();
        let temp = PathBuf::from(p.attachment.unwrap().path);

        let dest = guard.path().join("salvato.pdf");
        copy_to_destination(&store, &temp, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), pdf);
        assert!(temp.exists());
        store.discard(&temp).unwrap();
        assert!(!temp.exists());
        assert!(dest.exists(), "il salvataggio dell'utente non si tocca");
    }

    // ---------- flussi danneggiati ----------

    #[test]
    fn a_truncated_combined_message_fails_and_leaves_nothing_behind() {
        let (_g, store) = store();
        let pdf = [b"%PDF-1.7\n".to_vec(), vec![1; 4000]].concat();
        let mut combined = composite::encode("x", Some("a.pdf"), "application/pdf", &pdf).unwrap();
        combined.truncate(combined.len() - 1500);

        let session = Session::new(&store);
        let get_name = || None;
        let result = process_plaintext(&mut Cursor::new(combined), &get_name, &settings(false), &session, &never_fetch);
        assert!(result.is_err());
        drop(session);
        let left = fs::read_dir(store.root()).map(|d| d.count()).unwrap_or(0);
        assert_eq!(left, 0, "nessun file a meta' deve restare");
    }

    #[test]
    fn a_declared_length_longer_than_the_stream_is_an_error_not_a_hang() {
        let (_g, store) = store();
        let mut combined = composite::encode_header("", Some("a.bin"), "x/y", 10).unwrap();
        let at = combined.len() - 4;
        combined[at..].copy_from_slice(&u32::MAX.to_le_bytes());
        combined.extend_from_slice(b"pochi byte");
        let session = Session::new(&store);
        let get_name = || None;
        assert!(process_plaintext(&mut Cursor::new(combined), &get_name, &settings(false), &session, &never_fetch).is_err());
    }

    // ---------- blocco temporale ----------

    #[test]
    fn timelocked_content_is_inert_when_experimental_features_are_off() {
        // Il bug di privacy/SSRF: a funzioni sperimentali spente un
        // messaggio "bloccato nel tempo" non deve far partire NESSUNA
        // richiesta di rete (never_fetch fa fallire il test se parte).
        let (_g, store) = store();
        let blob = timelock::encode(
            10_000_000,
            Some("http://169.254.169.254/latest/meta-data/"),
            b"contenuto interno del messaggio bloccato",
        )
        .unwrap();
        let (p, _) = run(&store, blob, None, false, &never_fetch).unwrap();
        assert_ne!(p.kind, "bloccato_nel_tempo");
        assert_eq!(p.kind, "allegato", "trattato come dato grezzo salvabile");
        assert!(p.target_height.is_none() && p.current_height.is_none());
        assert!(p.height_check_error.is_none());
    }

    #[test]
    fn a_disallowed_sender_endpoint_is_never_contacted() {
        let (_g, store) = store();
        let blob = timelock::encode(10_000_000, Some("http://169.254.169.254/latest/meta-data/"), b"x").unwrap();
        let (p, _) = run(&store, blob, None, true, &never_fetch).unwrap();
        assert_eq!(p.kind, "bloccato_nel_tempo");
        assert_eq!(p.target_height, Some(10_000_000));
        assert!(p.height_check_error.is_some());
    }

    #[test]
    fn a_locked_message_does_not_write_its_content_to_disk() {
        let (_g, store) = store();
        let inner = composite::encode("segreto", Some("piano.pdf"), "application/pdf", b"%PDF-1.7 riservato").unwrap();
        let blob = timelock::encode(900_000, None, &inner).unwrap();
        let (p, _) = run(&store, blob, None, true, &|_, _| Ok(800_000)).unwrap();
        assert_eq!(p.kind, "bloccato_nel_tempo");
        assert_eq!(p.current_height, Some(800_000));
        assert!(p.attachment.is_none() && p.plaintext.is_none());
        assert!(!store.root().exists(), "un contenuto ancora bloccato non va su disco");
    }

    #[test]
    fn once_the_height_is_reached_the_inner_attachment_appears() {
        let (_g, store) = store();
        let pdf = [b"%PDF-1.7\n".to_vec(), vec![5; 3000]].concat();
        let inner = composite::encode("didascalia", Some("piano.pdf"), "application/pdf", &pdf).unwrap();
        let blob = timelock::encode(900_000, None, &inner).unwrap();

        let seen = Cell::new(false);
        let fetch = |endpoint: &str, _tor: bool| {
            seen.set(true);
            assert_eq!(endpoint, super::super::DEFAULT_TIMELOCK_ENDPOINT);
            Ok(900_001)
        };
        let (p, _) = run(&store, blob, None, true, &fetch).unwrap();
        assert!(seen.get());
        assert_eq!(p.kind, "combinato");
        assert_eq!(p.target_height, Some(900_000));
        assert_eq!(p.current_height, Some(900_001));
        assert_eq!(p.plaintext.as_deref(), Some("didascalia"));
        assert_eq!(read_back(p.attachment.as_ref().unwrap()), pdf);
    }

    #[test]
    fn a_failed_height_check_keeps_the_message_locked_with_the_reason() {
        let (_g, store) = store();
        let blob = timelock::encode(900_000, None, b"testo").unwrap();
        let (p, _) = run(&store, blob, None, true, &|_, _| Err("rete assente".to_string())).unwrap();
        assert_eq!(p.kind, "bloccato_nel_tempo");
        assert_eq!(p.height_check_error.as_deref(), Some("rete assente"));
    }

    #[test]
    fn an_unlocked_plain_text_message_is_shown_as_text() {
        let (_g, store) = store();
        let blob = timelock::encode(900_000, None, "ciao".as_bytes()).unwrap();
        let (p, _) = run(&store, blob, None, true, &|_, _| Ok(900_000)).unwrap();
        assert_eq!(p.kind, "testo");
        assert_eq!(p.plaintext.as_deref(), Some("ciao"));
        assert_eq!(p.current_height, Some(900_000));
    }

    // ---------- file di partenza ----------

    #[test]
    fn describing_a_source_file_uses_the_same_rules_as_encryption() {
        let dir = tempfile::tempdir().unwrap();
        let pdf = dir.path().join("Contratto firmato.pdf");
        fs::write(&pdf, b"%PDF-1.7 corpo").unwrap();
        let info = describe_source_file(&pdf).unwrap();
        assert_eq!(info.name, "Contratto firmato.pdf");
        assert_eq!(info.mime, "application/pdf");
        assert_eq!(info.category, "pdf");
        assert_eq!(info.size, 14);
        assert!(!info.dangerous && !info.too_large);

        let unknown = dir.path().join("dati.xyz");
        fs::write(&unknown, [1, 2, 3]).unwrap();
        let info = describe_source_file(&unknown).unwrap();
        assert_eq!((info.mime.as_str(), info.category.as_str()), ("application/octet-stream", "generico"));

        let exe = dir.path().join("setup.exe");
        fs::write(&exe, b"MZ").unwrap();
        assert!(describe_source_file(&exe).unwrap().dangerous);

        assert!(describe_source_file(dir.path()).is_err(), "una cartella non e' un allegato");
        assert!(describe_source_file(&dir.path().join("non-esiste.pdf")).is_err());
    }

    #[test]
    fn temp_file_names_are_short_and_never_hidden() {
        assert_eq!(temp_file_name("relazione.pdf"), "relazione.pdf");
        assert_eq!(temp_file_name(".nascosto.pdf"), "_nascosto.pdf");
        assert!(temp_file_name(&format!("{}.docx", "a".repeat(190))).len() <= TEMP_NAME_MAX_BYTES);
        assert!(temp_file_name(&format!("{}.docx", "a".repeat(190))).ends_with(".docx"));
        assert_eq!(temp_file_name("..."), attachment::FALLBACK_FILE_NAME);
    }

    #[test]
    fn peek_does_not_consume_and_survives_short_streams() {
        let mut src = Cursor::new(b"abcdef".to_vec());
        let mut peek = Peek::new(&mut src);
        assert_eq!(peek.peek(3).unwrap(), b"abc");
        assert_eq!(peek.peek(64).unwrap(), b"abcdef");
        let mut all = Vec::new();
        peek.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"abcdef");
    }
}
