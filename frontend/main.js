const { invoke, convertFileSrc } = window.__TAURI__.core;
const { save, open } = window.__TAURI__.dialog;
const { writeTextFile, readFile, readTextFile } = window.__TAURI__.fs;
const { writeText } = window.__TAURI__.clipboardManager;
const { getCurrentWebview } = window.__TAURI__.webview;

/** @type {{name: string, key: string, fingerprintHex: string, fingerprintWords: string[], email: string|null, phone: string|null, notes: string|null, photoBase64: string|null, photoMime: string|null}[]} */
const contacts = [];

// Tutte le identità sbloccate su questo dispositivo in questa sessione
// (Sigillo supporta più identità/account contemporaneamente). "Attiva"
// e' quella mostrata in "La mia identità" e usata per firmare quando
// Scrivi non ne indica una diversa esplicitamente.
/** @type {{displayName: string, seedPhrase: string|null, seedWords: string[], fingerprintHex: string, fingerprintWords: string[], publicKeyArmored: string, isImported: boolean}[]} */
let identities = [];
let activeIdentityIndex = 0;

let pendingSeedWords = [];
let currentImageFormat = "asc";

// Funzioni sperimentali (disattivate di default): finche' spente, la UI
// del blocco temporale non deve comparire da nessuna parte, non solo
// essere disabilitata — vedi renderExperimentalFeaturesUi().
let experimentalFeaturesEnabled = false;
let torSettings = { enabled: false, socksHost: "127.0.0.1", socksPort: 9050, customEndpoint: null };

// L'ultima richiesta di decifratura effettuata (testo incollato o file
// aperto): serve al pulsante "Controlla di nuovo" di un messaggio
// bloccato nel tempo, per ripetere esattamente la stessa chiamata.
let lastDecryptRequest = null; // { kind: "message", ciphertext } oppure { kind: "file", path }

// Indice (in "contacts") del contatto attualmente aperto nella scheda
// dettaglio, o null quando quella schermata non è la vista corrente.
let contactDetailIndex = null;

// Foto scelta per il contatto aperto nella scheda dettaglio, in attesa
// di essere salvata: { base64, mime } oppure null se non impostata o
// appena rimossa. Diventa persistente solo al click su "Salva modifiche".
let contactDetailPendingPhoto = undefined; // undefined = "non toccata"

function contactFromView(view) {
  return {
    name: view.name,
    key: view.key,
    fingerprintHex: view.fingerprint_hex,
    fingerprintWords: view.fingerprint_words,
    email: view.email || null,
    phone: view.phone || null,
    notes: view.notes || null,
    photoBase64: view.photo_base64 || null,
    photoMime: view.photo_mime || null,
  };
}

// File allegato nella scheda "Scrivi", in attesa di essere cifrato:
// { path, name, size, mime, category, dangerous } (descritto dal backend
// con attachment_info: stesse regole che userà poi la cifratura). Il
// contenuto del file non passa mai da qui: si cifra leggendolo dal disco.
let attachedFile = null;
let attachedPreviewUrl = null;

// L'allegato decifrato attualmente mostrato in "Decifra": un file
// temporaneo nella cartella privata dell'app (il frontend ne conosce solo
// il percorso e i metadati), che va tolto dal disco quando non serve più.
// { ...AttachmentView, tempExists, savedTo }
let currentAttachment = null;

// Solo immagini: usata per la foto profilo dei contatti, dove i video
// non hanno senso.
const IMAGE_MIME_BY_EXTENSION = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  gif: "image/gif",
  heic: "image/heic",
  heif: "image/heif",
};

function guessImageMime(filename) {
  const ext = (filename || "").split(".").pop().toLowerCase();
  return IMAGE_MIME_BY_EXTENSION[ext] || null;
}

// In "Scrivi" non si genera un'anteprima di un'immagine/video sopra
// questa soglia: leggerla per mostrarla farebbe transitare un file
// enorme dal disco all'interfaccia solo per una miniatura (la cifratura
// vera e propria legge comunque il file direttamente dal disco).
const LARGE_MEDIA_BYTES = 60 * 1024 * 1024;

// Oltre questa dimensione si avvisa che cifrare può richiedere tempo (e
// che il file .asc risulta circa un terzo più pesante), senza bloccare.
const BIG_ATTACHMENT_BYTES = 100 * 1024 * 1024;

const FILE_CATEGORY_LABELS = {
  immagine: "Immagine",
  video: "Video",
  pdf: "Documento PDF",
  documento: "Documento",
  foglio: "Foglio di calcolo",
  presentazione: "Presentazione",
  audio: "Audio",
  archivio: "Archivio",
  testo: "File di testo",
  generico: "File",
};

function formatFileSize(bytes) {
  const nf = (n) => n.toLocaleString("it-IT", { maximumFractionDigits: 1 });
  if (bytes < 1024) return `${bytes} byte`;
  if (bytes < 1024 * 1024) return `${nf(Math.max(0.1, bytes / 1024))} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${nf(bytes / (1024 * 1024))} MB`;
  return `${nf(bytes / (1024 * 1024 * 1024))} GB`;
}

// Riempie una scheda file (icona del tipo, nome, "tipo · dimensione").
// `prefix` è "attach" (Scrivi) o "decrypt" (Decifra). Il nome va sempre
// scritto con textContent: arriva da un messaggio ricevuto da terzi.
function fillFileCard(prefix, { name, size, category }) {
  const card = document.getElementById(`${prefix}-file-card`);
  const known = Object.prototype.hasOwnProperty.call(FILE_CATEGORY_LABELS, category);
  const cat = known ? category : "generico";
  card.dataset.category = cat;
  document.getElementById(`${prefix}-file-icon`).setAttribute("href", `#icon-${cat}`);
  document.getElementById(`${prefix}-file-name`).textContent = name;
  document.getElementById(`${prefix}-file-meta`).textContent =
    `${FILE_CATEGORY_LABELS[cat]} · ${formatFileSize(size)}`;
  card.hidden = false;
}

// Nessun motore di rendering dei webview usati da Sigillo (WebKitGTK su
// Linux, WKWebView su macOS, WebView2 su Windows) sa mostrare in modo
// affidabile un'immagine HEIC/HEIF tramite <img>: meglio riconoscerlo
// subito e mostrare un messaggio chiaro, invece di tentare il
// caricamento sperando che l'evento "error" scatti sempre allo stesso
// modo su ogni piattaforma.
const UNSUPPORTED_PREVIEW_MIMES = new Set(["image/heic", "image/heif"]);

// Su Linux la webview è WebKitGTK, che riproduce i video appoggiandosi a
// GStreamer: su diverse combinazioni di driver/plugin di sistema (VA-API
// difettosa, plugin mancanti...) la costruzione della pipeline di
// riproduzione può terminare l'intero processo della webview — schermo
// bianco, nessun errore intercettabile da JavaScript. Il rischio non
// vale un'anteprima: su Linux i video decifrati (e quelli allegati in
// "Scrivi") non vengono mostrati in un <video>, si offre invece di
// salvarli/aprirli con il lettore del sistema. Su macOS e Windows
// l'anteprima inline resta invariata.
const INLINE_VIDEO_PREVIEW_SUPPORTED = !/\bLinux\b/i.test(
  (typeof navigator !== "undefined" && navigator.userAgent) || ""
);

// Ridimensiona un'immagine (bytes grezzi) a un lato massimo di
// `maxDim` pixel e la restituisce come coppia { base64, mime }, pronta
// per essere salvata nella rubrica come foto profilo: evita di
// appesantire inutilmente il file della rubrica con foto originali da
// diversi MB per una miniatura tonda.
async function resizeImageToDataUrl(bytes, mime, maxDim) {
  const blob = new Blob([bytes], { type: mime });
  const bitmap = await createImageBitmap(blob);
  const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const h = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  canvas.getContext("2d").drawImage(bitmap, 0, 0, w, h);
  const dataUrl = canvas.toDataURL("image/jpeg", 0.85);
  return { base64: dataUrl.split(",")[1], mime: "image/jpeg" };
}

// ---------- Stato applicativo: una sola vista visibile alla volta ----------
//
// setView() è l'UNICO modo per cambiare schermata: aggiunge/rimuove la
// classe "active" (mai display:none via l'attributo hidden, vedi il
// commento in styles.css sul perché). Ogni bottone che fa avanzare il
// flusso chiama setView con l'id della vista successiva; nessuna vista è
// mai raggiungibile per scroll.

function setView(id) {
  // Fuori dalla schermata principale (es. Avanzate, rimozione identità)
  // un allegato decifrato non deve restare sul disco.
  if (id !== "screen-main") leaveDecryptScreen();
  for (const el of document.querySelectorAll(".screen")) {
    el.classList.toggle("active", el.id === id);
  }
}

document.querySelectorAll(".link-back").forEach((btn) => {
  btn.addEventListener("click", () => setView(btn.dataset.backTo));
});

/**
 * Esegue `action` (una funzione async) mostrando uno stato di caricamento
 * sul bottone che l'ha attivata: disabilita il bottone e ci mette sopra
 * uno spinner finché la chiamata non è finita, così ogni azione asincrona
 * (generare chiavi, cifrare, sbloccare...) dà un feedback immediato invece
 * di sembrare "morta" per uno o due secondi.
 */
async function withLoading(button, action) {
  if (button) {
    button.disabled = true;
    button.classList.add("is-loading");
  }
  try {
    return await action();
  } finally {
    if (button) {
      button.disabled = false;
      button.classList.remove("is-loading");
    }
  }
}

function setError(id, message) {
  const el = document.getElementById(id);
  if (!message) {
    el.hidden = true;
    el.textContent = "";
  } else {
    el.hidden = false;
    el.textContent = message;
  }
}

function identityFromView(view) {
  return {
    displayName: view.display_name,
    seedPhrase: view.seed_phrase,
    seedWords: view.seed_words,
    fingerprintHex: view.fingerprint_hex,
    fingerprintWords: view.fingerprint_words,
    publicKeyArmored: view.public_key_armored,
    isImported: view.is_imported,
  };
}

function renderActiveIdentity() {
  const id = identities[activeIdentityIndex];
  if (!id) return;
  document.getElementById("my-name").textContent = id.displayName;
  document.getElementById("my-imported-hint").hidden = !id.isImported;
  document.getElementById("my-fingerprint-words").textContent = id.fingerprintWords.join("  ");
  document.getElementById("my-public-key").value = id.publicKeyArmored;
}

// Il selettore compare solo quando c'e' davvero una scelta da fare: con
// una sola identita' sarebbe un menu inutile da mostrare sempre.
function renderIdentitySwitcher() {
  const row = document.getElementById("identity-switcher-row");
  const select = document.getElementById("identity-switcher");
  if (identities.length <= 1) {
    row.hidden = true;
    return;
  }
  select.innerHTML = "";
  identities.forEach((id, i) => {
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = id.displayName;
    select.appendChild(opt);
  });
  select.value = String(activeIdentityIndex);
  row.hidden = false;
}

function renderSenderSelect() {
  const row = document.getElementById("sender-select-row");
  const select = document.getElementById("sender-select");
  if (identities.length <= 1) {
    row.hidden = true;
    return;
  }
  select.innerHTML = "";
  identities.forEach((id, i) => {
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = id.displayName;
    select.appendChild(opt);
  });
  select.value = String(activeIdentityIndex);
  row.hidden = false;
}

/**
 * Applica l'elenco completo delle identità sul dispositivo (dopo uno
 * sblocco, o dopo aver aggiunto/creato un'identità) e ricarica lo stato
 * che dipende dall'avere un'identità attiva (rubrica, formato immagini).
 */
async function applyIdentitiesList(views, activeIdx) {
  identities = views.map(identityFromView);
  activeIdentityIndex = Math.min(Math.max(0, activeIdx), identities.length - 1);

  renderActiveIdentity();
  renderIdentitySwitcher();
  renderSenderSelect();
  document.getElementById("btn-open-advanced").hidden = false;

  // La rubrica è salvata sul dispositivo (non per singola identità): la
  // ricarichiamo ad ogni sblocco, così i contatti aggiunti in sessioni
  // precedenti sono ancora lì.
  contacts.length = 0;
  try {
    const saved = await invoke("load_contacts");
    for (const c of saved) {
      contacts.push(contactFromView(c));
    }
  } catch (err) {
    setError("contact-error", String(err));
  }
  renderContactList();

  try {
    currentImageFormat = await invoke("get_image_format");
  } catch (err) {
    currentImageFormat = "asc";
  }

  try {
    const settings = await invoke("get_app_settings");
    experimentalFeaturesEnabled = settings.experimental_features_enabled;
    torSettings = {
      enabled: settings.tor_enabled,
      socksHost: settings.tor_socks_host,
      socksPort: settings.tor_socks_port,
      customEndpoint: settings.timelock_custom_endpoint,
    };
    keyserverNoteShown = !!settings.keyserver_note_shown;
  } catch (err) {
    experimentalFeaturesEnabled = false;
  }
  renderExperimentalFeaturesUi();
}

// Punto unico da cui dipende tutta la visibilita' della UI legata alle
// funzioni sperimentali: col flag spento, nessuno di questi elementi
// deve essere visibile da nessuna parte dell'app (non solo disabilitato).
function renderExperimentalFeaturesUi() {
  document.getElementById("experimental-features-toggle").checked = experimentalFeaturesEnabled;
  document.getElementById("experimental-features-panel").hidden = !experimentalFeaturesEnabled;
  document.getElementById("timelock-option-row").hidden = !experimentalFeaturesEnabled;
  if (!experimentalFeaturesEnabled) {
    // Se l'utente disattiva le funzioni sperimentali con l'opzione di
    // blocco temporale gia' selezionata in Scrivi, la si ripristina
    // anche internamente, non solo visivamente.
    document.getElementById("timelock-toggle").checked = false;
    document.getElementById("timelock-fields").hidden = true;
  }

  document.getElementById("tor-toggle").checked = torSettings.enabled;
  document.getElementById("tor-fields").hidden = !torSettings.enabled;
  document.getElementById("tor-socks-host").value = torSettings.socksHost;
  document.getElementById("tor-socks-port").value = String(torSettings.socksPort);
  document.getElementById("timelock-custom-endpoint").value = torSettings.customEndpoint || "";
}

document.getElementById("identity-switcher").addEventListener("change", async (e) => {
  const idx = Number(e.target.value);
  try {
    await invoke("set_active_identity", { index: idx });
    activeIdentityIndex = idx;
    renderActiveIdentity();
    renderSenderSelect();
  } catch (err) {
    // Non dovrebbe mai succedere (l'indice viene sempre da questa
    // stessa lista): se capita comunque, non lasciamo l'interfaccia in
    // uno stato incoerente.
    e.target.value = String(activeIdentityIndex);
  }
});

function renderSeedGrid(words) {
  const grid = document.getElementById("seed-words");
  grid.innerHTML = "";
  words.forEach((word, i) => {
    const div = document.createElement("div");
    div.className = "seed-word";
    div.innerHTML = `<span class="idx">${i + 1}.</span>${word}`;
    grid.appendChild(div);
  });
}

function pickConfirmationPositions(total) {
  const positions = new Set();
  while (positions.size < Math.min(3, total)) {
    positions.add(Math.floor(Math.random() * total));
  }
  return [...positions].sort((a, b) => a - b);
}

function renderConfirmFields(positions) {
  const container = document.getElementById("confirm-fields");
  container.innerHTML = "";
  for (const pos of positions) {
    const wrapper = document.createElement("div");
    const label = document.createElement("label");
    label.textContent = `Parola numero ${pos + 1}`;
    const input = document.createElement("input");
    input.type = "text";
    input.dataset.position = String(pos);
    wrapper.appendChild(label);
    wrapper.appendChild(input);
    container.appendChild(wrapper);
  }
}

function renderRecipientList() {
  const container = document.getElementById("recipient-list");
  if (contacts.length === 0) {
    container.innerHTML =
      '<p class="hint">Nessun contatto ancora — aggiungine uno dalla scheda "Rubrica" quando vuoi scrivere a qualcuno in modo cifrato.</p>';
    return;
  }
  container.innerHTML = "";
  contacts.forEach((contact, i) => {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = String(i);
    label.appendChild(input);
    label.append(contact.name);
    container.appendChild(label);
  });
}

function buildAvatarElement(contact, sizeClass) {
  const avatar = document.createElement("span");
  avatar.className = `avatar ${sizeClass}`;
  if (contact.photoBase64) {
    const img = document.createElement("img");
    img.src = `data:${contact.photoMime};base64,${contact.photoBase64}`;
    img.alt = "";
    avatar.appendChild(img);
  } else {
    avatar.textContent = (contact.name || "?").trim().charAt(0).toUpperCase() || "?";
  }
  return avatar;
}

function renderContactList() {
  const list = document.getElementById("contact-list");
  list.innerHTML = "";
  if (contacts.length === 0) {
    list.innerHTML =
      '<li class="hint empty-state">Nessun contatto ancora — aggiungine uno quando vuoi scrivere a qualcuno in modo cifrato.</li>';
    renderRecipientList();
    return;
  }
  contacts.forEach((contact, i) => {
    const li = document.createElement("li");
    const row = document.createElement("button");
    row.type = "button";
    row.className = "contact-row";
    row.appendChild(buildAvatarElement(contact, "avatar-sm"));
    const nameSpan = document.createElement("span");
    nameSpan.className = "contact-row-name";
    nameSpan.textContent = contact.name;
    row.appendChild(nameSpan);
    row.addEventListener("click", () => openContactDetail(i));
    li.appendChild(row);
    list.appendChild(li);
  });
  renderRecipientList();
}

function resetAppToFirstRunState() {
  identities = [];
  activeIdentityIndex = 0;
  pendingSeedWords = [];
  contacts.length = 0;
  contactDetailIndex = null;
  contactDetailPendingPhoto = undefined;
  renderContactList();
  clearAttachment();
  discardCurrentAttachment();
  document.getElementById("btn-open-advanced").hidden = true;
  document.getElementById("display-name").value = "";
  document.getElementById("import-display-name").value = "";
  document.getElementById("import-phrase").value = "";
  document.getElementById("my-public-key").value = "";
  document.getElementById("ciphertext-in").value = "";
  document.getElementById("ciphertext-out").value = "";
  document.getElementById("message-text").value = "";
  document.getElementById("import-fingerprint").value = "";
  document.getElementById("import-text").value = "";
  importCandidates = [];
  importQueue = [];
}

// ---------- Allegato (scheda "Scrivi") ----------

// Un solo allegato per messaggio, di qualunque tipo. Per immagini, GIF e
// video si mostra l'anteprima (se la webview la sa fare), per tutto il
// resto una scheda con icona, nome e dimensione: l'anteprima è un extra,
// mai un requisito per poter allegare un file.
async function setAttachment(path) {
  setError("encrypt-error", null);

  let info;
  try {
    info = await invoke("attachment_info", { path });
  } catch (err) {
    setError("encrypt-error", String(err));
    return;
  }
  if (info.too_large) {
    setError(
      "encrypt-error",
      `Il file è troppo grande (${formatFileSize(info.size)}): Sigillo non può allegare file oltre i 4 GB.`
    );
    return;
  }

  clearAttachment();
  attachedFile = { path, ...info };

  const img = document.getElementById("image-preview");
  const video = document.getElementById("attach-video-preview");
  const unsupported = document.getElementById("image-preview-unsupported");
  const tooLarge = document.getElementById("attach-media-toolarge-hint");

  fillFileCard("attach", info);
  document.getElementById("attach-big-file-hint").hidden = info.size <= BIG_ATTACHMENT_BYTES;

  const isImage = info.category === "immagine";
  const isVideo = info.category === "video";

  if ((isImage || isVideo) && info.size > LARGE_MEDIA_BYTES) {
    // Niente anteprima per file enormi: la cifratura legge comunque il
    // file direttamente dal disco, a prescindere dalla dimensione.
    tooLarge.hidden = false;
  } else if (isImage && UNSUPPORTED_PREVIEW_MIMES.has(info.mime)) {
    unsupported.hidden = false;
  } else if (isVideo && !INLINE_VIDEO_PREVIEW_SUPPORTED) {
    // Su Linux niente anteprima video inline (vedi
    // INLINE_VIDEO_PREVIEW_SUPPORTED): il file verrà comunque cifrato
    // leggendolo direttamente dal disco.
    unsupported.hidden = false;
  } else if (isImage || isVideo) {
    let bytes;
    try {
      bytes = await readFile(path);
    } catch {
      // L'anteprima è solo un extra: se non si riesce a leggere per
      // mostrarla, il file resta allegabile.
      unsupported.hidden = false;
      bytes = null;
    }
    if (bytes && attachedFile && attachedFile.path === path) {
      attachedPreviewUrl = URL.createObjectURL(new Blob([bytes], { type: info.mime }));
      if (isVideo) {
        // Se la webview non riesce a mostrare l'anteprima del video su
        // questo sistema, non è un problema: il file verrà comunque
        // cifrato leggendolo direttamente dal disco.
        video.onerror = () => {
          video.pause();
          video.removeAttribute("src");
          video.hidden = true;
          unsupported.hidden = false;
        };
        video.src = attachedPreviewUrl;
        video.hidden = false;
      } else {
        img.onload = () => {
          img.hidden = false;
          unsupported.hidden = true;
        };
        img.onerror = () => {
          img.hidden = true;
          unsupported.hidden = false;
        };
        img.src = attachedPreviewUrl;
      }
    }
  }

  document.getElementById("attach-preview-wrap").hidden = false;
  document.getElementById("attach-dropzone-prompt").hidden = true;
}

// Azzera davvero sia l'interfaccia sia lo stato interno: dopo la
// rimozione (o dopo aver cifrato) non deve restare nulla dell'allegato
// precedente, né a schermo né in memoria.
function clearAttachment() {
  if (attachedPreviewUrl) {
    URL.revokeObjectURL(attachedPreviewUrl);
    attachedPreviewUrl = null;
  }
  attachedFile = null;

  const img = document.getElementById("image-preview");
  img.onload = null;
  img.onerror = null;
  img.removeAttribute("src");
  img.hidden = true;

  const video = document.getElementById("attach-video-preview");
  video.pause();
  video.onerror = null;
  video.removeAttribute("src");
  video.hidden = true;

  document.getElementById("image-preview-unsupported").hidden = true;
  document.getElementById("attach-media-toolarge-hint").hidden = true;
  document.getElementById("attach-big-file-hint").hidden = true;
  document.getElementById("attach-file-card").hidden = true;
  document.getElementById("attach-file-name").textContent = "";
  document.getElementById("attach-file-meta").textContent = "";
  document.getElementById("attach-preview-wrap").hidden = true;
  document.getElementById("attach-dropzone-prompt").hidden = false;
}

document.getElementById("btn-choose-attachment").addEventListener("click", async () => {
  // Nessun filtro: si può scegliere qualunque tipo di file (su Android
  // un filtro per estensione escluderebbe tutto ciò che non è un media).
  const path = await open({ multiple: false });
  if (path) await setAttachment(path);
});

document.getElementById("btn-remove-attachment").addEventListener("click", () => {
  clearAttachment();
  setError("encrypt-error", null);
});

// Il drag&drop nativo di Tauri e' a livello di finestra (da' percorsi
// file, non oggetti File del browser): accettiamo un file solo quando la
// scheda "Scrivi" e' quella attiva, per non "rubare" un drop destinato ad
// altre parti dell'app.
getCurrentWebview().onDragDropEvent((event) => {
  const onMain = document.getElementById("screen-main").classList.contains("active");
  const onWrite = onMain && document.getElementById("tab-write").classList.contains("active");
  const onContacts =
    (onMain && document.getElementById("tab-contacts").classList.contains("active")) ||
    document.getElementById("screen-add-contact").classList.contains("active");

  const writeZone = document.getElementById("attach-dropzone");
  const importZone = document.getElementById("import-dropzone");
  const contactsCard = document.querySelector("#tab-contacts .card");

  if (event.payload.type === "over") {
    if (onWrite) writeZone.classList.add("dragover");
    if (onContacts) {
      importZone.classList.add("dragover");
      contactsCard.classList.add("dragover");
    }
    return;
  }
  writeZone.classList.remove("dragover");
  importZone.classList.remove("dragover");
  contactsCard.classList.remove("dragover");
  if (event.payload.type !== "drop") return;

  const path = event.payload.paths[0];
  if (!path) return;
  if (onWrite) setAttachment(path);
  else if (onContacts) importFromFile(path);
});

// ---------- Avvio: identità già presente su questo dispositivo? ----------

async function init() {
  try {
    const exists = await invoke("identity_exists_on_disk");
    setView(exists ? "screen-unlock" : "screen-welcome");
  } catch (err) {
    // Se per qualche motivo non riusciamo a controllare, non blocchiamo
    // l'utente: mostriamo comunque la schermata di ingresso.
    setView("screen-welcome");
  }
}

// ---------- Schermata: ingresso ----------

// La schermata di ingresso serve sia al primo avvio (nessuna identità
// ancora) sia per aggiungere un'identità in più da "La mia identità":
// in questo secondo caso il testo cambia leggermente e il tasto
// indietro riporta all'app invece che essere assente.
function showWelcomeScreen() {
  const adding = identities.length > 0;
  document.getElementById("btn-welcome-back").hidden = !adding;
  document.getElementById("welcome-title").textContent = adding
    ? "Aggiungi un'altra identità"
    : "Benvenuto in Sigillo";
  document.getElementById("welcome-text").textContent = adding
    ? "Crea una nuova identità, oppure importane una esistente (con la seed phrase o con una chiave PGP generata altrove)."
    : "Scrivi messaggi che solo il destinatario può leggere. Non serve un'email, non serve una password su un server: tutto resta su questo dispositivo.";
  setView("screen-welcome");
}

document.getElementById("btn-welcome-back").addEventListener("click", () => {
  document.querySelector('[data-tab="tab-identity"]').click();
  setView("screen-main");
});

document.getElementById("btn-go-create").addEventListener("click", () => {
  document.getElementById("display-name").value = "";
  setView("screen-create-name");
});

document.getElementById("btn-go-import").addEventListener("click", () => {
  document.getElementById("import-display-name").value = "";
  document.getElementById("import-phrase").value = "";
  setView("screen-import");
});

document.getElementById("btn-go-import-external").addEventListener("click", () => {
  document.getElementById("import-external-alias").value = "";
  document.getElementById("import-external-key").value = "";
  document.getElementById("import-external-passphrase").value = "";
  setError("import-external-error", null);
  setView("screen-import-external");
});

// ---------- Schermata: sblocco ----------

document.getElementById("btn-unlock").addEventListener("click", async (e) => {
  setError("unlock-error", null);
  const passphrase = document.getElementById("unlock-passphrase").value;
  try {
    const views = await withLoading(e.currentTarget, () =>
      invoke("unlock_identity", { passphrase })
    );
    await applyIdentitiesList(views, 0);
    setView("screen-main");
  } catch (err) {
    setError("unlock-error", String(err));
  }
});

document.getElementById("btn-forgot-remove").addEventListener("click", async (e) => {
  setError("forgot-error", null);
  const confirmText = document.getElementById("forgot-confirm-text").value.trim();
  if (confirmText !== "RIMUOVI") {
    setError("forgot-error", 'Scrivi esattamente "RIMUOVI" per confermare.');
    return;
  }
  try {
    await withLoading(e.currentTarget, () => invoke("remove_identity_from_disk"));
    resetAppToFirstRunState();
    document.getElementById("forgot-confirm-text").value = "";
    setView("screen-welcome");
  } catch (err) {
    setError("forgot-error", String(err));
  }
});

// ---------- Schermata: crea nuova identità ----------

document.getElementById("btn-generate").addEventListener("click", async (e) => {
  setError("setup-error", null);
  const displayName = document.getElementById("display-name").value;
  const wordCount = Number(
    document.querySelector('input[name="word-count"]:checked').value
  );
  try {
    const view = await withLoading(e.currentTarget, () =>
      invoke("generate_identity", { wordCount, displayName })
    );
    pendingSeedWords = view.seed_words;
    renderSeedGrid(pendingSeedWords);
    setView("screen-seed");
  } catch (err) {
    setError("setup-error", String(err));
  }
});

// ---------- Schermata: ho già un'identità (import da seed phrase) ----------

document.getElementById("btn-import").addEventListener("click", async (e) => {
  setError("import-error", null);
  const displayName = document.getElementById("import-display-name").value;
  const phrase = document.getElementById("import-phrase").value;
  try {
    await withLoading(e.currentTarget, () => invoke("import_identity", { phrase, displayName }));
    // Chi reinserisce una seed phrase la conosce già: non c'è bisogno di
    // rimostrarla/confermarla, si passa direttamente a proteggere questo
    // dispositivo con una passphrase locale.
    updateSetPassphraseScreenForMode();
    setView("screen-set-passphrase");
  } catch (err) {
    setError("import-error", String(err));
  }
});

// ---------- Schermata: importa chiave PGP esterna ----------

document.getElementById("btn-choose-external-key-file").addEventListener("click", async () => {
  setError("import-external-error", null);
  const path = await open({
    multiple: false,
    filters: [{ name: "Chiave privata OpenPGP", extensions: ["asc", "gpg", "pgp", "key", "txt"] }],
  });
  if (!path) return;
  try {
    document.getElementById("import-external-key").value = await readTextFile(path);
  } catch (err) {
    setError("import-external-error", String(err));
  }
});

document.getElementById("btn-import-external").addEventListener("click", async (e) => {
  setError("import-external-error", null);
  const alias = document.getElementById("import-external-alias").value;
  const armoredTsk = document.getElementById("import-external-key").value.trim();
  const keyPassphrase = document.getElementById("import-external-passphrase").value;

  if (!armoredTsk) {
    setError("import-external-error", "Incolla o scegli il file con la chiave privata.");
    return;
  }
  if (!alias.trim()) {
    setError("import-external-error", "Scegli un nome per riconoscere questa identità.");
    return;
  }

  try {
    await withLoading(e.currentTarget, () =>
      invoke("import_identity_external", {
        armoredTsk,
        keyPassphrase: keyPassphrase || null,
        alias,
      })
    );
    // Una chiave importata non ha una seed phrase Sigillo da
    // confermare: si passa direttamente alla passphrase del dispositivo.
    updateSetPassphraseScreenForMode();
    setView("screen-set-passphrase");
  } catch (err) {
    setError("import-external-error", String(err));
  }
});

// ---------- Schermata: mostra seed phrase ----------

document.getElementById("btn-seed-written").addEventListener("click", () => {
  const positions = pickConfirmationPositions(pendingSeedWords.length);
  renderConfirmFields(positions);
  setView("screen-confirm");
});

// ---------- Schermata: conferma seed phrase ----------

document.getElementById("btn-confirm-check").addEventListener("click", async (e) => {
  setError("confirm-error", null);
  const inputs = [...document.querySelectorAll("#confirm-fields input")];
  const positionsAndWords = inputs.map((input) => [
    Number(input.dataset.position),
    input.value,
  ]);
  try {
    const ok = await withLoading(e.currentTarget, () =>
      invoke("confirm_seed_words", { positionsAndWords })
    );
    if (ok) {
      updateSetPassphraseScreenForMode();
      setView("screen-set-passphrase");
    } else {
      document.getElementById("confirm-error").hidden = false;
    }
  } catch (err) {
    setError("confirm-error", String(err));
  }
});

// ---------- Schermata: imposta/conferma la passphrase locale ----------

// Con nessuna identita' ancora sbloccata siamo nel wizard di primo
// avvio (bisogna sceglierne una nuova, quindi va anche ripetuta); se
// invece ce n'e' gia' almeno una, stiamo aggiungendo un'identita' a un
// vault che esiste gia': la passphrase e' quella che protegge gia' il
// dispositivo, va solo confermata una volta.
function updateSetPassphraseScreenForMode() {
  const adding = identities.length > 0;
  document.getElementById("set-passphrase-title").textContent = adding
    ? "Conferma la passphrase del dispositivo"
    : "Proteggi questo dispositivo";
  document.getElementById("set-passphrase-text").textContent = adding
    ? 'Questa identità verrà aggiunta alle altre già presenti su questo dispositivo. Inserisci la passphrase che usi per sbloccare Sigillo qui: dev\'essere la stessa.'
    : "Scegli una passphrase per sbloccare Sigillo su questo computer. Non è la tua seed phrase (quella serve solo per reimportare l'identità su un altro dispositivo, o se rimuovi l'identità da qui): la passphrase resta locale.";
  document.getElementById("set-passphrase-label").textContent = adding
    ? "Passphrase del dispositivo"
    : "Passphrase (almeno 8 caratteri)";
  document.getElementById("set-passphrase").placeholder = adding
    ? "La passphrase di questo dispositivo"
    : "Scegli una passphrase";
  document.getElementById("set-passphrase-confirm-row").hidden = adding;
}

document.getElementById("btn-save-passphrase").addEventListener("click", async (e) => {
  setError("set-passphrase-error", null);
  const passphrase = document.getElementById("set-passphrase").value;
  const adding = identities.length > 0;

  if (passphrase.length < 8) {
    setError("set-passphrase-error", "La passphrase deve avere almeno 8 caratteri.");
    return;
  }
  if (!adding) {
    const confirmPassphrase = document.getElementById("set-passphrase-confirm").value;
    if (passphrase !== confirmPassphrase) {
      setError("set-passphrase-error", "Le due passphrase non coincidono.");
      return;
    }
  }

  try {
    const views = await withLoading(e.currentTarget, () =>
      invoke("save_identity_to_disk", { passphrase })
    );
    document.getElementById("set-passphrase").value = "";
    document.getElementById("set-passphrase-confirm").value = "";
    await applyIdentitiesList(views, views.length - 1);
    if (adding) {
      document.querySelector('[data-tab="tab-identity"]').click();
    }
    setView("screen-main");
  } catch (err) {
    setError("set-passphrase-error", String(err));
  }
});

// ---------- Tabs (sezioni della app operativa) ----------

for (const btn of document.querySelectorAll(".tab-btn")) {
  btn.addEventListener("click", () => {
    // Lasciando "Decifra" l'allegato decifrato esce dal disco.
    if (
      btn.dataset.tab !== "tab-decrypt" &&
      document.getElementById("tab-decrypt").classList.contains("active")
    ) {
      leaveDecryptScreen();
    }
    for (const b of document.querySelectorAll(".tab-btn")) b.classList.remove("active");
    for (const p of document.querySelectorAll(".tab-panel")) p.classList.remove("active");
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
}

// ---------- Rubrica ----------

// ---------- Rubrica: aggiungere un contatto ----------
//
// Tre modi di arrivare alla chiave di una persona — fingerprint (si
// scarica da keys.openpgp.org), file (.asc, .gpg...) o testo incollato —
// e SEMPRE la stessa schermata di conferma prima di salvare.

// La nota "la ricerca contatta un server pubblico" si mostra una sola
// volta (il backend la segna come vista alla prima ricerca senza Tor).
let keyserverNoteShown = false;

let importCandidates = []; // chiavi trovate dall'ultima importazione
let importQueue = []; // quelle scelte da confermare, una alla volta
let importQueueIndex = 0;
let importAddedCount = 0;
let importLastAddedName = null;

function fingerprintPlainOf(contact) {
  return (contact.fingerprintHex || "").replace(/\s+/g, "").toUpperCase();
}

async function reloadContacts() {
  const saved = await invoke("load_contacts");
  contacts.length = 0;
  for (const c of saved) contacts.push(contactFromView(c));
  renderContactList();
}

function clearImportMessages() {
  for (const id of ["import-fingerprint-error", "import-file-error", "import-text-error"]) {
    setError(id, null);
  }
  document.getElementById("import-private-warning").hidden = true;
}

function renderKeyserverNote() {
  document.getElementById("keyserver-note").hidden = torSettings.enabled || keyserverNoteShown;
}

function showAddContactScreen() {
  clearImportMessages();
  document.getElementById("import-methods").hidden = false;
  document.getElementById("import-choose").hidden = true;
  document.getElementById("import-search-progress").hidden = true;
  renderKeyserverNote();
  setView("screen-add-contact");
}

document.getElementById("btn-add-contact").addEventListener("click", () => {
  document.getElementById("contact-flash").hidden = true;
  showAddContactScreen();
});

document.getElementById("btn-close-add-contact").addEventListener("click", () => {
  importCandidates = [];
  importQueue = [];
  setView("screen-main");
});

// Una chiave PRIVATA non si importa mai: avviso ambra e basta. Il testo
// incollato si cancella subito dalla casella, per non tenerla a schermo.
function showPrivateKeyWarning() {
  document.getElementById("import-private-warning").hidden = false;
  document.getElementById("import-text").value = "";
  document.getElementById("import-private-warning").scrollIntoView?.({ block: "nearest" });
}

function handleImportResult(result, errorId) {
  if (result.private_key) {
    showPrivateKeyWarning();
    return;
  }
  if (!result.candidates || result.candidates.length === 0) {
    setError(errorId, "Non ho trovato nessuna chiave in questo contenuto.");
    return;
  }
  importCandidates = result.candidates;
  if (importCandidates.length === 1) {
    startConfirmation([0]);
  } else {
    showChooser();
  }
}

// ---- Più chiavi nello stesso file: si sceglie quali importare ----

function showChooser() {
  const list = document.getElementById("import-choose-list");
  list.innerHTML = "";
  importCandidates.forEach((cand, i) => {
    const label = document.createElement("label");
    label.className = "import-choose-item";
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = true;
    box.value = String(i);
    const text = document.createElement("span");
    const who = document.createElement("span");
    who.className = "who";
    who.textContent = [cand.name, cand.email && `<${cand.email}>`].filter(Boolean).join(" ") || "(senza nome)";
    const fp = document.createElement("span");
    fp.className = "fp";
    fp.textContent = cand.fingerprint_spaced;
    text.append(who, document.createElement("br"), fp);
    label.append(box, text);
    list.appendChild(label);
  });
  document.getElementById("import-choose-title").textContent =
    `Ho trovato ${importCandidates.length} chiavi: quali vuoi aggiungere?`;
  document.getElementById("import-methods").hidden = true;
  document.getElementById("import-choose").hidden = false;
}

document.getElementById("btn-choose-back").addEventListener("click", () => {
  importCandidates = [];
  showAddContactScreen();
});

document.getElementById("btn-choose-continue").addEventListener("click", () => {
  const chosen = [...document.querySelectorAll("#import-choose-list input:checked")].map((b) =>
    Number(b.value)
  );
  if (chosen.length === 0) return;
  startConfirmation(chosen);
});

// ---- Schermata di conferma (comune ai tre metodi) ----

function startConfirmation(indexes) {
  importQueue = indexes.map((i) => importCandidates[i]);
  importQueueIndex = 0;
  importAddedCount = 0;
  importLastAddedName = null;
  showConfirmation();
}

function currentCandidate() {
  return importQueue[importQueueIndex];
}

function showConfirmation() {
  const cand = currentCandidate();
  setError("confirm-error", null);
  document.getElementById("confirm-name").value = cand.existing_contact_name || cand.name || "";
  document.getElementById("confirm-email").value = cand.email || "";
  document.getElementById("confirm-notes").value = "";
  document.getElementById("confirm-fingerprint").textContent = cand.fingerprint_spaced;
  document.getElementById("confirm-fingerprint-words").textContent = cand.fingerprint_words.join("  ");
  document.getElementById("confirm-created").textContent = formatUnixDate(cand.created_unix);
  document.getElementById("confirm-expires").textContent = cand.expires_unix
    ? `${cand.status === "scaduta" ? "è scaduta" : "scade"} il ${formatUnixDate(cand.expires_unix)}`
    : "non ha scadenza";
  document.getElementById("confirm-override").checked = false;

  const progress = document.getElementById("confirm-progress");
  progress.hidden = importQueue.length < 2;
  progress.textContent = `Contatto ${importQueueIndex + 1} di ${importQueue.length}`;

  refreshConfirmState();
  setView("screen-confirm-contact");
}

// Avvisi e stato dei pulsanti: dipendono dalla chiave e, per l'omonimia,
// dal nome che si sta scrivendo.
function refreshConfirmState() {
  const cand = currentCandidate();
  if (!cand) return;

  const statusBox = document.getElementById("confirm-status-warning");
  const overrideRow = document.getElementById("confirm-override-row");
  let blocked = false;
  let needsOverride = false;
  let statusText = "";
  if (cand.status === "revocata") {
    statusText =
      "Questa chiave è stata revocata da chi l'ha creata: non è più sicura. Non è consigliato aggiungerla.";
    needsOverride = true;
  } else if (cand.status === "scaduta") {
    statusText = `Questa chiave è scaduta${
      cand.expires_unix ? ` il ${formatUnixDate(cand.expires_unix)}` : ""
    }. Non è consigliato usarla: chiedi alla persona una chiave aggiornata.`;
    needsOverride = true;
  } else if (cand.status === "senza_cifratura") {
    statusText =
      "Questa chiave non può ricevere messaggi cifrati, quindi non è utile come contatto. Chiedi alla persona la sua chiave completa.";
    blocked = true;
  }
  statusBox.hidden = !statusText;
  statusBox.textContent = statusText;
  overrideRow.hidden = !needsOverride;

  const dup = document.getElementById("confirm-duplicate");
  if (cand.existing_contact_name) {
    dup.hidden = false;
    dup.textContent = `Hai già questo contatto: «${cand.existing_contact_name}». Non lo aggiungo una seconda volta; se vuoi, puoi aggiornare il nome e le note.`;
  } else {
    dup.hidden = true;
  }

  // Stesso nome ma fingerprint diverso: evidente, perché potrebbe essere
  // un tentativo di sostituzione (o semplicemente una chiave cambiata).
  const typed = document.getElementById("confirm-name").value.trim().toLowerCase();
  const same = typed
    ? contacts.find(
        (c) =>
          c.name.trim().toLowerCase() === typed && fingerprintPlainOf(c) !== cand.fingerprint_plain
      )
    : null;
  const sameBox = document.getElementById("confirm-samename");
  sameBox.hidden = !same;
  if (same) {
    sameBox.textContent = `Attenzione: hai già un contatto chiamato «${same.name}» con un fingerprint DIVERSO. Può essere una persona omonima, una chiave che è cambiata oppure un tentativo di sostituzione: verifica con la persona prima di procedere.`;
  }

  const addBtn = document.getElementById("btn-confirm-add");
  addBtn.textContent = cand.existing_contact_name ? "Aggiorna contatto" : "Aggiungi a Rubrica";
  addBtn.disabled =
    blocked || (needsOverride && !document.getElementById("confirm-override").checked);
}

document.getElementById("confirm-name").addEventListener("input", refreshConfirmState);
document.getElementById("confirm-override").addEventListener("change", refreshConfirmState);

function nextInQueueOrFinish() {
  importQueueIndex += 1;
  if (importQueueIndex < importQueue.length) {
    showConfirmation();
    return;
  }
  if (importAddedCount > 0) {
    const flash = document.getElementById("contact-flash");
    flash.textContent =
      importAddedCount === 1 && importLastAddedName
        ? importLastAddedName
        : `${importAddedCount} contatti aggiunti alla rubrica.`;
    flash.hidden = false;
    importCandidates = [];
    importQueue = [];
    document.getElementById("import-fingerprint").value = "";
    document.getElementById("import-text").value = "";
    setView("screen-main");
  } else {
    showAddContactScreen();
  }
}

document.getElementById("btn-confirm-add").addEventListener("click", async (e) => {
  const cand = currentCandidate();
  if (!cand) return;
  setError("confirm-error", null);
  const name = document.getElementById("confirm-name").value.trim();
  if (!name) {
    setError("confirm-error", "Scrivi un nome per questo contatto.");
    return;
  }
  try {
    const outcome = await withLoading(e.currentTarget, () =>
      invoke("confirm_add_contact", {
        name,
        armoredPublicKey: cand.armored_public_key,
        email: document.getElementById("confirm-email").value,
        notes: document.getElementById("confirm-notes").value,
        updateExisting: !!cand.existing_contact_name,
      })
    );
    await reloadContacts();
    importAddedCount += 1;
    importLastAddedName =
      outcome.status === "aggiornato"
        ? `Contatto «${name}» aggiornato.`
        : outcome.status === "gia_presente"
          ? `«${name}» era già in rubrica.`
          : `${name} aggiunto/a alla rubrica.`;
    nextInQueueOrFinish();
  } catch (err) {
    setError("confirm-error", String(err));
  }
});

document.getElementById("btn-confirm-cancel").addEventListener("click", nextInQueueOrFinish);

document.getElementById("btn-confirm-back").addEventListener("click", () => {
  importQueue = [];
  if (importCandidates.length > 1) {
    setView("screen-add-contact");
    showChooser();
  } else {
    showAddContactScreen();
  }
});

// ---- Metodo 1: fingerprint ----

document.getElementById("btn-search-fingerprint").addEventListener("click", async (e) => {
  const button = e.currentTarget;
  clearImportMessages();
  const fingerprint = document.getElementById("import-fingerprint").value;
  const progress = document.getElementById("import-search-progress");
  progress.textContent = torSettings.enabled
    ? "Cerco la chiave tramite Tor… la prima volta può richiedere più di un minuto."
    : "Cerco la chiave…";
  progress.hidden = false;
  try {
    const result = await withLoading(button, () =>
      invoke("search_contact_by_fingerprint", { fingerprint })
    );
    handleImportResult(result, "import-fingerprint-error");
  } catch (err) {
    setError("import-fingerprint-error", String(err));
  } finally {
    progress.hidden = true;
    // Dopo la prima ricerca senza Tor la nota non va più mostrata.
    if (!torSettings.enabled && !keyserverNoteShown) {
      invoke("get_app_settings")
        .then((s) => {
          keyserverNoteShown = s.keyserver_note_shown;
          renderKeyserverNote();
        })
        .catch(() => {});
    }
  }
});

document.getElementById("import-fingerprint").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("btn-search-fingerprint").click();
});

// ---- Metodo 2: file ----

async function importFromFile(path) {
  showAddContactScreen();
  try {
    const result = await invoke("read_contact_file", { path });
    handleImportResult(result, "import-file-error");
  } catch (err) {
    setError("import-file-error", String(err));
  }
}

document.getElementById("btn-choose-key-file").addEventListener("click", async () => {
  // Nessun filtro: si può scegliere qualunque file (.asc, .pgp, .gpg,
  // .key, .txt...) e su Android un filtro per estensione escluderebbe i
  // file che non hanno un tipo noto. Conta il contenuto, non il nome.
  const path = await open({ multiple: false });
  if (path) await importFromFile(path);
});

// ---- Metodo 3: testo incollato ----

document.getElementById("btn-import-text").addEventListener("click", async () => {
  clearImportMessages();
  const text = document.getElementById("import-text").value;
  if (!text.trim()) {
    setError("import-text-error", "Incolla prima il testo della chiave.");
    return;
  }
  try {
    const result = await invoke("read_contact_text", { text });
    handleImportResult(result, "import-text-error");
  } catch (err) {
    setError("import-text-error", String(err));
  }
});

// ---------- Dettaglio contatto ----------

function renderContactDetailAvatar(contact) {
  const img = document.getElementById("contact-detail-photo");
  const initial = document.getElementById("contact-detail-initial");
  const base64 =
    contactDetailPendingPhoto !== undefined ? contactDetailPendingPhoto?.base64 : contact.photoBase64;
  const mime =
    contactDetailPendingPhoto !== undefined ? contactDetailPendingPhoto?.mime : contact.photoMime;

  if (base64) {
    img.src = `data:${mime};base64,${base64}`;
    img.hidden = false;
    initial.hidden = true;
  } else {
    img.hidden = true;
    img.src = "";
    initial.hidden = false;
    initial.textContent = (contact.name || "?").trim().charAt(0).toUpperCase() || "?";
  }
}

function openContactDetail(index) {
  const contact = contacts[index];
  if (!contact) return;
  contactDetailIndex = index;
  contactDetailPendingPhoto = undefined;
  setError("contact-detail-error", null);
  document.getElementById("contact-detail-saved-hint").hidden = true;

  document.getElementById("contact-detail-name").value = contact.name;
  document.getElementById("contact-detail-fingerprint-words").textContent =
    contact.fingerprintWords.join("  ");
  document.getElementById("contact-detail-key").value = contact.key;
  document.getElementById("contact-detail-email").value = contact.email || "";
  document.getElementById("contact-detail-phone").value = contact.phone || "";
  document.getElementById("contact-detail-notes").value = contact.notes || "";
  renderContactDetailAvatar(contact);

  setView("screen-contact-detail");
}

document.getElementById("btn-close-contact-detail").addEventListener("click", () => {
  contactDetailIndex = null;
  contactDetailPendingPhoto = undefined;
  setView("screen-main");
});

document.getElementById("btn-copy-contact-key").addEventListener("click", async () => {
  await writeText(document.getElementById("contact-detail-key").value);
});

document.getElementById("btn-choose-contact-photo").addEventListener("click", async () => {
  setError("contact-detail-error", null);
  const path = await open({
    multiple: false,
    filters: [{ name: "Immagini", extensions: ["jpg", "jpeg", "png"] }],
  });
  if (!path) return;
  try {
    const filename = path.split(/[\\/]/).pop();
    const mime = guessImageMime(filename);
    if (!mime || UNSUPPORTED_PREVIEW_MIMES.has(mime)) {
      setError(
        "contact-detail-error",
        "Formato non supportato per la foto profilo: usa un'immagine JPG o PNG."
      );
      return;
    }
    const bytes = await readFile(path);
    contactDetailPendingPhoto = await resizeImageToDataUrl(bytes, mime, 320);
    renderContactDetailAvatar(contacts[contactDetailIndex]);
  } catch (err) {
    setError("contact-detail-error", String(err));
  }
});

document.getElementById("btn-remove-contact-photo").addEventListener("click", () => {
  contactDetailPendingPhoto = null;
  renderContactDetailAvatar(contacts[contactDetailIndex]);
});

document.getElementById("btn-save-contact-detail").addEventListener("click", async (e) => {
  setError("contact-detail-error", null);
  document.getElementById("contact-detail-saved-hint").hidden = true;
  const contact = contacts[contactDetailIndex];
  if (!contact) return;

  const name = document.getElementById("contact-detail-name").value.trim();
  if (!name) {
    setError("contact-detail-error", "Il nome non può essere vuoto.");
    return;
  }
  const email = document.getElementById("contact-detail-email").value;
  const phone = document.getElementById("contact-detail-phone").value;
  const notes = document.getElementById("contact-detail-notes").value;

  const photo =
    contactDetailPendingPhoto !== undefined
      ? contactDetailPendingPhoto
      : { base64: contact.photoBase64, mime: contact.photoMime };

  try {
    const view = await withLoading(e.currentTarget, () =>
      invoke("update_contact", {
        publicKeyArmored: contact.key,
        name,
        email,
        phone,
        notes,
        photoBase64: photo?.base64 || null,
        photoMime: photo?.mime || null,
      })
    );
    contacts[contactDetailIndex] = contactFromView(view);
    contactDetailPendingPhoto = undefined;
    renderContactList();
    document.getElementById("contact-detail-saved-hint").hidden = false;
  } catch (err) {
    setError("contact-detail-error", String(err));
  }
});

// ---------- Scrivi / cifra ----------

// La spiegazione della firma compare solo quando l'utente tocca/apre
// l'opzione per la prima volta, non come testo sempre visibile.
document.getElementById("sign-message").addEventListener(
  "focus",
  () => {
    document.getElementById("sign-message-hint").hidden = false;
  },
  { once: true }
);

async function checkCurrentBlockHeightForTimelock(button) {
  const hint = document.getElementById("timelock-current-height-hint");
  const retryBtn = document.getElementById("btn-retry-timelock-height");
  setError("timelock-error", null);
  retryBtn.hidden = true;
  hint.textContent = torSettings.enabled
    ? "Verifica dell'altezza attuale tramite Tor... la costruzione di un circuito può richiedere anche oltre un minuto, specialmente la prima volta."
    : "Verifica dell'altezza attuale...";
  try {
    const current = await withLoading(button, () =>
      invoke("check_block_height", { customEndpoint: torSettings.customEndpoint })
    );
    hint.textContent = `Altezza blocco attuale: ${current.toLocaleString("it-IT")} (circa 10 minuti per blocco).`;
  } catch (err) {
    hint.textContent = "";
    setError("timelock-error", `Impossibile verificare l'altezza attuale: ${err}`);
    retryBtn.hidden = false;
  }
}

document.getElementById("timelock-toggle").addEventListener("change", async (e) => {
  const enabled = e.target.checked;
  document.getElementById("timelock-fields").hidden = !enabled;
  setError("timelock-error", null);
  document.getElementById("btn-retry-timelock-height").hidden = true;
  if (!enabled) return;
  await checkCurrentBlockHeightForTimelock(null);
});

document.getElementById("btn-retry-timelock-height").addEventListener("click", async (e) => {
  await checkCurrentBlockHeightForTimelock(e.currentTarget);
});

document.getElementById("btn-encrypt").addEventListener("click", async (e) => {
  setError("encrypt-error", null);
  document.getElementById("encrypt-result").hidden = true;
  document.getElementById("encrypt-image-result").hidden = true;

  const selected = [...document.querySelectorAll('#recipient-list input[type="checkbox"]:checked')]
    .map((el) => contacts[Number(el.value)].key);
  const plaintext = document.getElementById("message-text").value;
  const sign = document.getElementById("sign-message").checked;
  // Con una sola identita' il selettore e' nascosto: si usa sempre
  // quella attiva (undefined -> il backend ripiega da solo su di essa).
  const senderIndex =
    identities.length > 1 ? Number(document.getElementById("sender-select").value) : undefined;

  if (selected.length === 0) {
    setError("encrypt-error", "Seleziona almeno un destinatario.");
    return;
  }
  if (!plaintext && !attachedFile) {
    setError("encrypt-error", "Scrivi un messaggio o allega un file prima di cifrare.");
    return;
  }

  const timelockEnabled =
    experimentalFeaturesEnabled && document.getElementById("timelock-toggle").checked;
  let targetHeight = null;
  if (timelockEnabled) {
    setError("timelock-error", null);
    const raw = document.getElementById("timelock-target-height").value.trim();
    targetHeight = Number(raw);
    if (!raw || !Number.isInteger(targetHeight) || targetHeight <= 0) {
      setError("timelock-error", "Inserisci un'altezza blocco valida (un numero intero positivo).");
      return;
    }
  }

  try {
    await withLoading(e.currentTarget, async () => {
      let textDone = false;
      let imageDone = false;

      if (timelockEnabled) {
        // Blocco temporale (sperimentale): testo ed eventuale allegato
        // finiscono comunque in un unico file, come in encrypt_combined,
        // ma avvolti in un pacchetto che l'interfaccia di Sigillo non
        // mostrera' finche' l'altezza blocco scelta non e' raggiunta.
        const sourceName = attachedFile ? attachedFile.name : "messaggio";
        const ext = currentImageFormat === "gpg" ? "gpg" : "asc";
        const outputPath = await save({
          defaultPath: `${sourceName}.bloccato.${ext}`,
          filters: [{ name: "Messaggio cifrato", extensions: [ext] }],
        });
        if (outputPath) {
          await invoke("encrypt_timelocked", {
            recipientsArmored: selected,
            plaintext,
            sourcePath: attachedFile ? attachedFile.path : null,
            outputPath,
            sign,
            senderIndex,
            targetHeight,
            customEndpoint: torSettings.customEndpoint,
          });
          document.getElementById("encrypt-image-result-label").textContent =
            "Messaggio bloccato salvato:";
          document.getElementById("encrypt-image-saved-path").textContent = outputPath;
          document.getElementById("encrypt-image-result").hidden = false;
          textDone = true;
          imageDone = !!attachedFile;
        }
      } else if (plaintext && attachedFile) {
        // Testo e allegato insieme: un unico file cifrato, cosi' chi lo
        // riceve li ritrova entrambi aprendolo una sola volta (come un
        // messaggio con didascalia e foto, o con un PDF), invece di due
        // file separati.
        const sourceName = attachedFile.name;
        const ext = currentImageFormat === "gpg" ? "gpg" : "asc";
        const outputPath = await save({
          defaultPath: `${sourceName}.${ext}`,
          filters: [{ name: "Messaggio cifrato", extensions: [ext] }],
        });
        if (outputPath) {
          await invoke("encrypt_combined", {
            recipientsArmored: selected,
            plaintext,
            sourcePath: attachedFile.path,
            outputPath,
            sign,
            senderIndex,
          });
          document.getElementById("encrypt-image-result-label").textContent =
            "Messaggio cifrato salvato:";
          document.getElementById("encrypt-image-saved-path").textContent = outputPath;
          document.getElementById("encrypt-image-result").hidden = false;
          textDone = true;
          imageDone = true;
        }
      } else if (plaintext) {
        const ciphertext = await invoke("encrypt_message", {
          recipientsArmored: selected,
          plaintext,
          sign,
          senderIndex,
        });
        document.getElementById("ciphertext-out").value = ciphertext;
        document.getElementById("encrypt-result").hidden = false;
        textDone = true;
      } else if (attachedFile) {
        const sourceName = attachedFile.name;
        const ext = currentImageFormat === "gpg" ? "gpg" : "asc";
        const outputPath = await save({
          defaultPath: `${sourceName}.${ext}`,
          filters: [{ name: "File cifrato", extensions: [ext] }],
        });
        if (outputPath) {
          await invoke("encrypt_attachment", {
            recipientsArmored: selected,
            sourcePath: attachedFile.path,
            outputPath,
            sign,
            senderIndex,
          });
          document.getElementById("encrypt-image-result-label").textContent =
            "File cifrato salvato:";
          document.getElementById("encrypt-image-saved-path").textContent = outputPath;
          document.getElementById("encrypt-image-result").hidden = false;
          imageDone = true;
        }
      }

      // Il risultato appena prodotto resta visibile (per copiarlo o
      // ritrovare il percorso del file salvato): a svuotarsi sono solo i
      // campi di composizione, cosi' la scheda e' subito pronta per un
      // nuovo messaggio senza lasciare testo o immagini della volta
      // precedente. Se l'utente ha annullato il salvataggio
      // dell'immagine (outputPath non scelto), l'allegato resta: quella
      // parte non e' stata completata.
      if (textDone) {
        document.getElementById("message-text").value = "";
      }
      if (imageDone) {
        clearAttachment();
      }
      if (textDone || imageDone) {
        for (const checkbox of document.querySelectorAll(
          '#recipient-list input[type="checkbox"]:checked'
        )) {
          checkbox.checked = false;
        }
        document.getElementById("sign-message").checked = false;
        document.getElementById("timelock-toggle").checked = false;
        document.getElementById("timelock-fields").hidden = true;
        document.getElementById("timelock-target-height").value = "";
        setError("timelock-error", null);
      }
    });
  } catch (err) {
    setError("encrypt-error", String(err));
  }
});

document.getElementById("btn-copy-ciphertext").addEventListener("click", async () => {
  await writeText(document.getElementById("ciphertext-out").value);
});

document.getElementById("btn-save-ciphertext").addEventListener("click", async () => {
  const path = await save({
    defaultPath: "messaggio.asc",
    filters: [{ name: "Messaggio cifrato", extensions: ["asc"] }],
  });
  if (path) {
    await writeTextFile(path, document.getElementById("ciphertext-out").value);
  }
});

// ---------- Decifra ----------

// L'indicatore "Decifrando…" compare solo se l'operazione non è quasi
// istantanea: per un messaggio breve sarebbe solo un lampeggio.
async function withDecryptProgress(button, action) {
  const progress = document.getElementById("decrypt-progress");
  const timer = setTimeout(() => {
    progress.hidden = false;
  }, 400);
  try {
    return await withLoading(button, action);
  } finally {
    clearTimeout(timer);
    progress.hidden = true;
  }
}

// Smette di usare il file decifrato nelle anteprime (importante per
// poterlo cancellare: su Windows un file ancora in uso non si elimina).
function resetDecryptPreview() {
  closeLightbox();
  const img = document.getElementById("decrypt-image-preview");
  img.onload = null;
  img.onerror = null;
  img.removeAttribute("src");
  img.hidden = true;

  const video = document.getElementById("decrypt-video-preview");
  video.pause();
  video.onerror = null;
  video.removeAttribute("src");
  video.hidden = true;

  document.getElementById("decrypt-image-unsupported").hidden = true;
  document.getElementById("decrypt-video-unsupported").hidden = true;
}

// Toglie dal disco l'allegato decifrato mostrato adesso (file in chiaro
// nella cartella privata dell'app). Si chiama quando arriva un nuovo
// risultato, quando si lascia la schermata di decifratura e quando si
// rimuove l'identità; il backend lo ripete comunque alla chiusura e
// all'avvio dell'app.
function discardCurrentAttachment() {
  const att = currentAttachment;
  currentAttachment = null;
  resetDecryptPreview();
  if (att && att.tempExists) {
    invoke("discard_decrypted_attachment", { path: att.path }).catch(() => {
      /* se non si riesce adesso, ci pensa la pulizia alla chiusura/avvio */
    });
  }
}

// Si lascia la scheda "Decifra": l'allegato esce dal disco. Il testo
// eventualmente decifrato resta, la scheda del file lascia il posto a un
// avviso (non avrebbe più un file a cui riferirsi).
function leaveDecryptScreen() {
  if (!currentAttachment) return;
  discardCurrentAttachment();
  document.getElementById("decrypt-attachment-body").hidden = true;
  document.getElementById("decrypt-attachment-removed").hidden = false;
}

function showAttachmentPreview(att) {
  const img = document.getElementById("decrypt-image-preview");
  const video = document.getElementById("decrypt-video-preview");
  const unsupported = document.getElementById("decrypt-image-unsupported");
  const videoUnsupported = document.getElementById("decrypt-video-unsupported");

  if (att.category === "immagine") {
    if (UNSUPPORTED_PREVIEW_MIMES.has(att.mime)) {
      unsupported.hidden = false;
      return;
    }
    img.onload = () => {
      img.hidden = false;
      unsupported.hidden = true;
    };
    img.onerror = () => {
      img.hidden = true;
      unsupported.hidden = false;
    };
    // Il file è su disco: la webview lo legge direttamente (protocollo
    // "asset"), senza far passare i byte per l'interfaccia.
    img.src = convertFileSrc(att.path);
  } else if (att.category === "video") {
    if (!INLINE_VIDEO_PREVIEW_SUPPORTED) {
      // Su Linux non si tenta l'anteprima inline (vedi
      // INLINE_VIDEO_PREVIEW_SUPPORTED): si mostra solo l'avviso.
      videoUnsupported.hidden = false;
      return;
    }
    // macOS/Windows: anteprima inline, con rete di sicurezza se il
    // sistema non riesce comunque a decodificare/mostrare il video.
    video.onerror = () => {
      video.pause();
      video.removeAttribute("src");
      video.hidden = true;
      videoUnsupported.hidden = false;
    };
    video.src = convertFileSrc(att.path);
    video.hidden = false;
  }
  // Tutto il resto (PDF, documenti, audio, archivi...): nessuna
  // anteprima, solo la scheda con "Salva con nome" e "Apri". Un PDF
  // inline in un <iframe> non è affidabile su tutte le webview.
}

function showDecryptedAttachment(att) {
  currentAttachment = { ...att, tempExists: true, savedTo: null };

  fillFileCard("decrypt", att);
  setError("decrypt-attachment-error", null);
  document.getElementById("decrypt-saved-hint").hidden = true;
  document.getElementById("decrypt-saved-hint").textContent = "";
  document.getElementById("decrypt-danger-warning").hidden = true;
  document.getElementById("decrypt-attachment-removed").hidden = true;
  document.getElementById("decrypt-attachment-body").hidden = false;
  document.getElementById("btn-open-attachment").hidden = false;

  showAttachmentPreview(att);
}

async function saveCurrentAttachment() {
  const att = currentAttachment;
  if (!att || !att.tempExists) return;
  setError("decrypt-attachment-error", null);
  try {
    const dest = await save({ defaultPath: att.name });
    if (!dest) return;
    await invoke("save_decrypted_attachment", { tempPath: att.path, destPath: dest });
    att.savedTo = dest;

    const hint = document.getElementById("decrypt-saved-hint");
    hint.textContent = `Salvato in: ${dest}`;
    hint.hidden = false;

    // Se a schermo non c'è un'anteprima che usa il file, la copia
    // temporanea non serve più: si toglie subito dal disco.
    const previewShown =
      !document.getElementById("decrypt-image-preview").hidden ||
      !document.getElementById("decrypt-video-preview").hidden;
    if (!previewShown) {
      await invoke("discard_decrypted_attachment", { path: att.path }).catch(() => {});
      att.tempExists = false;
      document.getElementById("btn-open-attachment").hidden = true;
      document.getElementById("decrypt-danger-warning").hidden = true;
    }
  } catch (err) {
    setError("decrypt-attachment-error", String(err));
  }
}

// Apre l'allegato con il programma predefinito del sistema. Mai in
// automatico: solo su richiesta, e per programmi e script (.exe, .sh,
// .apk...) solo dopo aver mostrato l'avviso e avuto una conferma.
async function openCurrentAttachment(confirmed) {
  const att = currentAttachment;
  if (!att || !att.tempExists) return;
  setError("decrypt-attachment-error", null);

  if (att.dangerous && !confirmed) {
    document.getElementById("decrypt-danger-warning").hidden = false;
    return;
  }
  document.getElementById("decrypt-danger-warning").hidden = true;
  try {
    await invoke("open_decrypted_attachment", { path: att.path, confirmed: !!confirmed });
  } catch (err) {
    setError("decrypt-attachment-error", String(err));
  }
}

document.getElementById("btn-save-attachment").addEventListener("click", saveCurrentAttachment);
document.getElementById("btn-open-attachment").addEventListener("click", () => openCurrentAttachment(false));
document.getElementById("btn-open-anyway").addEventListener("click", () => openCurrentAttachment(true));
document.getElementById("btn-cancel-open").addEventListener("click", () => {
  document.getElementById("decrypt-danger-warning").hidden = true;
});
document.getElementById("decrypt-render-error-save").addEventListener("click", saveCurrentAttachment);

function formatBlocksEta(blocksRemaining) {
  const minutes = blocksRemaining * 10;
  if (minutes < 60) return `circa ${minutes} minuti`;
  const hours = minutes / 60;
  if (hours < 48) return `circa ${hours.toFixed(1)} ore`;
  return `circa ${(hours / 24).toFixed(1)} giorni`;
}

function renderTimelockedResult(result) {
  document.getElementById("timelocked-target").textContent =
    result.target_height.toLocaleString("it-IT");
  const progress = document.getElementById("timelocked-progress");
  const errorEl = document.getElementById("timelocked-error");

  if (result.height_check_error) {
    progress.hidden = true;
    errorEl.hidden = false;
    errorEl.textContent = `Non riesco a verificare l'altezza attuale: ${result.height_check_error}`;
  } else {
    errorEl.hidden = true;
    progress.hidden = false;
    const remaining = result.target_height - result.current_height;
    progress.textContent =
      `Altezza attuale: ${result.current_height.toLocaleString("it-IT")}. ` +
      `Mancano ${remaining.toLocaleString("it-IT")} blocchi (${formatBlocksEta(remaining)}).`;
  }
}

function renderDecryptResult(result) {
  // Il risultato precedente (e l'eventuale file decifrato su disco) esce di scena.
  discardCurrentAttachment();

  const statusEl = document.getElementById("signature-status");
  statusEl.className = "signature-status";
  if (result.signature_status === "verificata") {
    const known = contacts.find((c) => c.fingerprintHex === result.signer_fingerprint);
    statusEl.textContent = known
      ? `Firma verificata: è di ${known.name}.`
      : `Firma verificata (${result.signer_fingerprint}), ma questo contatto non è in rubrica.`;
    statusEl.classList.add("verified");
  } else if (result.signature_status === "non_verificabile") {
    statusEl.textContent =
      "Il messaggio è firmato, ma non conosci ancora la chiave di chi l'ha firmato: aggiungilo in rubrica per verificarlo.";
    statusEl.classList.add("unverifiable");
  } else {
    statusEl.textContent = "Messaggio non firmato.";
    statusEl.classList.add("unsigned");
  }

  const textBlock = document.getElementById("decrypt-result-text");
  const attachmentBlock = document.getElementById("decrypt-result-attachment");
  const timelockedBlock = document.getElementById("decrypt-result-timelocked");
  const renderErrorBlock = document.getElementById("decrypt-result-render-error");
  textBlock.hidden = true;
  attachmentBlock.hidden = true;
  timelockedBlock.hidden = true;
  renderErrorBlock.hidden = true;

  // Il contenuto è già stato decifrato correttamente a questo punto: qui
  // si tratta solo di *mostrarlo*. Se il rendering fallisce per una
  // incompatibilità della webview su questo sistema (è successo con i
  // video su Linux e con il testo su CubeOS/Qubes), non deve trascinarsi
  // dietro l'intera schermata: mostriamo un avviso leggibile e, quando
  // possibile, lasciamo comunque salvare il file. Nota: questo intercetta
  // solo gli errori JS sincroni; un crash del processo webview va
  // prevenuto a monte (vedi force_software_video_decoding nel backend).
  try {
    if (result.kind === "bloccato_nel_tempo") {
      renderTimelockedResult(result);
      timelockedBlock.hidden = false;
    } else if (result.kind === "testo") {
      document.getElementById("plaintext-out").value = result.plaintext;
      textBlock.hidden = false;
    } else if (result.kind === "allegato" || result.kind === "combinato") {
      if (result.kind === "combinato") {
        document.getElementById("plaintext-out").value = result.plaintext;
        textBlock.hidden = false;
      }
      showDecryptedAttachment(result.attachment);
      attachmentBlock.hidden = false;
    } else {
      throw new Error(`tipo di contenuto sconosciuto: ${result.kind}`);
    }
  } catch (err) {
    // Fallback: teniamo comunque pronto il salvataggio se il file c'è, e
    // — per il testo — lo stampiamo su stderr (visibile lanciando l'app
    // da terminale) così non è del tutto irraggiungibile.
    console.error("Errore nel mostrare il contenuto decifrato:", err);
    if (typeof result.plaintext === "string" && result.plaintext.length > 0) {
      console.error("Testo decifrato (non mostrato a schermo):\n" + result.plaintext);
    }
    if (!currentAttachment && result.attachment) {
      currentAttachment = { ...result.attachment, tempExists: true, savedTo: null };
    }
    // Se era un messaggio combinato e la didascalia era già stata
    // scritta prima del punto di rottura, la lasciamo visibile: a non
    // essersi potuto mostrare è solo l'allegato.
    const keepText =
      result.kind === "combinato" &&
      typeof result.plaintext === "string" &&
      document.getElementById("plaintext-out").value === result.plaintext;
    textBlock.hidden = !keepText;
    attachmentBlock.hidden = true;
    timelockedBlock.hidden = true;
    document.getElementById("decrypt-render-error-save").hidden = !(
      currentAttachment && currentAttachment.tempExists
    );
    renderErrorBlock.hidden = false;
  }

  document.getElementById("decrypt-result").hidden = false;
}

document.getElementById("btn-load-file").addEventListener("click", async (e) => {
  // Va catturato subito: dopo il primo "await" l'evento ha gia' finito
  // il suo dispatch e "currentTarget" torna null (comportamento standard
  // del DOM, non un bug del webview).
  const button = e.currentTarget;
  setError("decrypt-error", null);
  const path = await open({
    multiple: false,
    filters: [{ name: "Messaggio cifrato", extensions: ["asc", "gpg", "pgp", "txt"] }],
  });
  if (!path) return;

  discardCurrentAttachment();
  document.getElementById("decrypt-result").hidden = true;
  try {
    const result = await withDecryptProgress(button, () =>
      invoke("decrypt_file", { contactsArmored: contacts.map((c) => c.key), path })
    );
    lastDecryptRequest = { kind: "file", path };
    renderDecryptResult(result);
  } catch (err) {
    setError("decrypt-error", String(err));
  }
});

document.getElementById("btn-decrypt").addEventListener("click", async (e) => {
  setError("decrypt-error", null);
  discardCurrentAttachment();
  document.getElementById("decrypt-result").hidden = true;

  const ciphertext = document.getElementById("ciphertext-in").value;
  if (!ciphertext) {
    setError("decrypt-error", "Incolla o apri prima un messaggio cifrato.");
    return;
  }

  try {
    const result = await withDecryptProgress(e.currentTarget, () =>
      invoke("decrypt_message", { contactsArmored: contacts.map((c) => c.key), ciphertext })
    );
    lastDecryptRequest = { kind: "message", ciphertext };
    renderDecryptResult(result);
  } catch (err) {
    setError("decrypt-error", String(err));
  }
});

document.getElementById("btn-recheck-timelock").addEventListener("click", async (e) => {
  if (!lastDecryptRequest) return;
  setError("decrypt-error", null);
  try {
    const result = await withLoading(e.currentTarget, () => {
      const contactsArmored = contacts.map((c) => c.key);
      return lastDecryptRequest.kind === "file"
        ? invoke("decrypt_file", { contactsArmored, path: lastDecryptRequest.path })
        : invoke("decrypt_message", { contactsArmored, ciphertext: lastDecryptRequest.ciphertext });
    });
    renderDecryptResult(result);
  } catch (err) {
    setError("decrypt-error", String(err));
  }
});

// ---------- Identita ----------

document.getElementById("btn-copy-pubkey").addEventListener("click", async () => {
  await writeText(document.getElementById("my-public-key").value);
});

document.getElementById("btn-add-another-identity").addEventListener("click", () => {
  showWelcomeScreen();
});

// ---------- Avanzate ----------

function formatUnixDate(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleDateString("it-IT", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

function renderTechDetail(container, detail) {
  const div = document.createElement("div");
  div.className = "tech-key";
  const expires = detail.expires_unix ? formatUnixDate(detail.expires_unix) : "mai";
  const label = document.createElement("span");
  label.className = "tech-label";
  label.textContent = detail.label;
  const algoLine = document.createElement("span");
  algoLine.className = "tech-line";
  algoLine.textContent = `Algoritmo: ${detail.algorithm}`;
  const createdLine = document.createElement("span");
  createdLine.className = "tech-line";
  createdLine.textContent = `Creata il: ${formatUnixDate(detail.created_unix)}`;
  const expiresLine = document.createElement("span");
  expiresLine.className = "tech-line";
  expiresLine.textContent = `Scadenza: ${expires}`;
  div.append(label, algoLine, createdLine, expiresLine);
  container.appendChild(div);
}

async function populateAdvancedScreen() {
  renderExperimentalFeaturesUi();

  try {
    document.getElementById("adv-app-version").textContent = await invoke("app_version");
  } catch {
    document.getElementById("adv-app-version").textContent = "sconosciuta";
  }

  document.getElementById("adv-my-fingerprint-hex").textContent =
    identities[activeIdentityIndex] ? identities[activeIdentityIndex].fingerprintHex : "";

  const myDetails = document.getElementById("adv-my-details");
  myDetails.innerHTML = "";
  try {
    const details = await invoke("my_technical_details");
    for (const d of details) renderTechDetail(myDetails, d);
  } catch (err) {
    myDetails.innerHTML = `<p class="error">${String(err)}</p>`;
  }

  const formatRadio = document.querySelector(
    `input[name="image-format"][value="${currentImageFormat}"]`
  );
  if (formatRadio) formatRadio.checked = true;

  const contactsContainer = document.getElementById("adv-contacts");
  contactsContainer.innerHTML = "";
  if (contacts.length === 0) {
    contactsContainer.innerHTML =
      '<p class="hint">Non hai ancora contatti in rubrica — qui vedrai i loro dettagli tecnici quando ne aggiungerai.</p>';
    return;
  }
  for (const contact of contacts) {
    const details = document.createElement("details");
    details.className = "tech-contact";
    const summary = document.createElement("summary");
    summary.textContent = contact.name;
    details.appendChild(summary);

    const fp = document.createElement("p");
    fp.className = "fingerprint-hex";
    fp.textContent = contact.fingerprintHex;
    details.appendChild(fp);

    const techContainer = document.createElement("div");
    techContainer.className = "tech-details";
    details.appendChild(techContainer);

    details.addEventListener("toggle", async () => {
      if (!details.open || techContainer.childElementCount > 0) return;
      try {
        const keyDetails = await invoke("contact_technical_details", {
          armoredPublicKey: contact.key,
        });
        for (const d of keyDetails) renderTechDetail(techContainer, d);
      } catch (err) {
        techContainer.innerHTML = `<p class="error">${String(err)}</p>`;
      }
    });

    contactsContainer.appendChild(details);
  }
}

document.getElementById("btn-open-advanced").addEventListener("click", async (e) => {
  await withLoading(e.currentTarget, () => populateAdvancedScreen());
  setView("screen-advanced");
});

document.getElementById("btn-close-advanced").addEventListener("click", () => {
  setView("screen-main");
});

for (const radio of document.querySelectorAll('input[name="image-format"]')) {
  radio.addEventListener("change", async () => {
    setError("image-format-error", null);
    const format = radio.value;
    try {
      await invoke("set_image_format", { format });
      currentImageFormat = format;
    } catch (err) {
      setError("image-format-error", String(err));
    }
  });
}

// ---------- Funzioni sperimentali e blocco temporale (Avanzate) ----------

document.getElementById("experimental-features-toggle").addEventListener("change", async (e) => {
  setError("experimental-features-error", null);
  const enabled = e.target.checked;
  try {
    await invoke("set_experimental_features_enabled", { enabled });
    experimentalFeaturesEnabled = enabled;
    renderExperimentalFeaturesUi();
  } catch (err) {
    e.target.checked = !enabled;
    setError("experimental-features-error", String(err));
  }
});

document.getElementById("tor-toggle").addEventListener("change", async (e) => {
  setError("tor-settings-error", null);
  const enabled = e.target.checked;
  document.getElementById("tor-fields").hidden = !enabled;
  try {
    await invoke("set_tor_settings", {
      enabled,
      socksHost: document.getElementById("tor-socks-host").value,
      socksPort: Number(document.getElementById("tor-socks-port").value) || 9050,
      customEndpoint: document.getElementById("timelock-custom-endpoint").value || null,
    });
    torSettings.enabled = enabled;
  } catch (err) {
    e.target.checked = !enabled;
    document.getElementById("tor-fields").hidden = !e.target.checked;
    setError("tor-settings-error", String(err));
  }
});

document.getElementById("btn-save-tor-settings").addEventListener("click", async (e) => {
  setError("tor-settings-error", null);
  document.getElementById("tor-settings-saved-hint").hidden = true;
  const socksHost = document.getElementById("tor-socks-host").value.trim();
  const socksPortRaw = document.getElementById("tor-socks-port").value.trim();
  const socksPort = Number(socksPortRaw);
  const customEndpoint = document.getElementById("timelock-custom-endpoint").value.trim();

  if (!socksPortRaw || !Number.isInteger(socksPort) || socksPort <= 0 || socksPort > 65535) {
    setError("tor-settings-error", "La porta SOCKS5 deve essere un numero tra 1 e 65535.");
    return;
  }

  try {
    await withLoading(e.currentTarget, () =>
      invoke("set_tor_settings", {
        enabled: document.getElementById("tor-toggle").checked,
        socksHost,
        socksPort,
        customEndpoint: customEndpoint || null,
      })
    );
    torSettings = {
      enabled: document.getElementById("tor-toggle").checked,
      socksHost,
      socksPort,
      customEndpoint: customEndpoint || null,
    };
    document.getElementById("tor-settings-saved-hint").hidden = false;
  } catch (err) {
    setError("tor-settings-error", String(err));
  }
});

document.getElementById("btn-export-tsk").addEventListener("click", async (e) => {
  setError("export-tsk-error", null);
  const password = document.getElementById("export-tsk-password").value;
  if (!password) {
    setError("export-tsk-error", "Scegli una password per proteggere il file esportato.");
    return;
  }
  try {
    const armored = await withLoading(e.currentTarget, () =>
      invoke("export_private_key_file", { password })
    );
    const path = await save({
      defaultPath: "sigillo-chiave-privata.asc",
      filters: [{ name: "Chiave privata OpenPGP", extensions: ["asc"] }],
    });
    if (path) {
      await writeTextFile(path, armored);
    }
    document.getElementById("export-tsk-password").value = "";
  } catch (err) {
    setError("export-tsk-error", String(err));
  }
});

document.getElementById("btn-remove-identity").addEventListener("click", async (e) => {
  setError("remove-error", null);
  const confirmText = document.getElementById("remove-confirm-text").value.trim();
  if (confirmText !== "RIMUOVI") {
    setError("remove-error", 'Scrivi esattamente "RIMUOVI" per confermare.');
    return;
  }
  try {
    await withLoading(e.currentTarget, () => invoke("remove_identity_from_disk"));
    resetAppToFirstRunState();
    document.getElementById("remove-confirm-text").value = "";
    setView("screen-welcome");
  } catch (err) {
    setError("remove-error", String(err));
  }
});

// ---------- Lightbox per l'anteprima immagine ingrandita ----------

function openLightbox(imgEl) {
  if (imgEl.hidden || !imgEl.src) return;
  document.getElementById("lightbox-image").src = imgEl.src;
  document.getElementById("image-lightbox").hidden = false;
}

function closeLightbox() {
  document.getElementById("image-lightbox").hidden = true;
  document.getElementById("lightbox-image").src = "";
}

document.getElementById("decrypt-image-preview").addEventListener("click", (e) => {
  openLightbox(e.currentTarget);
});

document.getElementById("btn-close-lightbox").addEventListener("click", closeLightbox);

document.getElementById("image-lightbox").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeLightbox();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !document.getElementById("image-lightbox").hidden) closeLightbox();
});

init();
