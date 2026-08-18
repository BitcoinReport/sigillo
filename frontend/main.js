const { invoke } = window.__TAURI__.core;
const { save, open } = window.__TAURI__.dialog;
const { writeTextFile, writeFile, readFile } = window.__TAURI__.fs;
const { writeText } = window.__TAURI__.clipboardManager;
const { getCurrentWebview } = window.__TAURI__.webview;

/** @type {{name: string, key: string, fingerprintHex: string, fingerprintWords: string[]}[]} */
const contacts = [];
let currentIdentity = null;
let pendingSeedWords = [];
let currentImageFormat = "asc";

// Immagine allegata nella scheda "Scrivi", in attesa di essere cifrata.
let attachedImagePath = null;
let attachedImagePreviewUrl = null;

// Ultimo risultato di una decifratura non testuale (immagine o file
// generico), tenuto pronto per il bottone "Salva...".
let lastDecrypted = null; // { bytes: Uint8Array, filename: string | null }

const IMAGE_MIME_BY_EXTENSION = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  heic: "image/heic",
  heif: "image/heif",
};

function guessImageMime(filename) {
  const ext = (filename || "").split(".").pop().toLowerCase();
  return IMAGE_MIME_BY_EXTENSION[ext] || null;
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---------- Stato applicativo: una sola vista visibile alla volta ----------
//
// setView() è l'UNICO modo per cambiare schermata: aggiunge/rimuove la
// classe "active" (mai display:none via l'attributo hidden, vedi il
// commento in styles.css sul perché). Ogni bottone che fa avanzare il
// flusso chiama setView con l'id della vista successiva; nessuna vista è
// mai raggiungibile per scroll.

function setView(id) {
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

async function renderIdentity(view) {
  currentIdentity = view;
  document.getElementById("my-name").textContent = view.display_name;
  document.getElementById("my-fingerprint-words").textContent =
    view.fingerprint_words.join("  ");
  document.getElementById("my-public-key").value = view.public_key_armored;
  document.getElementById("btn-open-advanced").hidden = false;

  // La rubrica è salvata sul dispositivo: la ricarichiamo ad ogni sblocco,
  // così i contatti aggiunti in sessioni precedenti sono ancora lì.
  contacts.length = 0;
  try {
    const saved = await invoke("load_contacts");
    for (const c of saved) {
      contacts.push({
        name: c.name,
        key: c.key,
        fingerprintHex: c.fingerprint_hex,
        fingerprintWords: c.fingerprint_words,
      });
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
}

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

function renderContactList() {
  const list = document.getElementById("contact-list");
  list.innerHTML = "";
  if (contacts.length === 0) {
    list.innerHTML =
      '<li class="hint empty-state">Nessun contatto ancora — aggiungine uno quando vuoi scrivere a qualcuno in modo cifrato.</li>';
    renderRecipientList();
    return;
  }
  contacts.forEach((contact) => {
    const li = document.createElement("li");
    const nameSpan = document.createElement("span");
    nameSpan.textContent = contact.name;
    const fpSpan = document.createElement("span");
    fpSpan.className = "fp";
    fpSpan.textContent = contact.fingerprintWords.slice(0, 4).join(" ") + "...";
    li.appendChild(nameSpan);
    li.appendChild(fpSpan);
    list.appendChild(li);
  });
  renderRecipientList();
}

function resetAppToFirstRunState() {
  currentIdentity = null;
  pendingSeedWords = [];
  contacts.length = 0;
  renderContactList();
  clearAttachedImage();
  lastDecrypted = null;
  document.getElementById("btn-open-advanced").hidden = true;
  document.getElementById("display-name").value = "";
  document.getElementById("import-display-name").value = "";
  document.getElementById("import-phrase").value = "";
  document.getElementById("my-public-key").value = "";
  document.getElementById("ciphertext-in").value = "";
  document.getElementById("ciphertext-out").value = "";
  document.getElementById("message-text").value = "";
}

// ---------- Immagine allegata (scheda "Scrivi") ----------

async function setAttachedImage(path) {
  const filename = path.split(/[\\/]/).pop();
  const mime = guessImageMime(filename);
  if (!mime) {
    setError("encrypt-error", "Formato non supportato: usa un'immagine JPG, PNG o HEIC.");
    return;
  }
  setError("encrypt-error", null);

  let bytes;
  try {
    bytes = await readFile(path);
  } catch (err) {
    setError("encrypt-error", String(err));
    return;
  }

  if (attachedImagePreviewUrl) URL.revokeObjectURL(attachedImagePreviewUrl);
  attachedImagePreviewUrl = URL.createObjectURL(new Blob([bytes], { type: mime }));
  attachedImagePath = path;

  const img = document.getElementById("image-preview");
  const unsupported = document.getElementById("image-preview-unsupported");
  img.onload = () => {
    img.hidden = false;
    unsupported.hidden = true;
  };
  img.onerror = () => {
    img.hidden = true;
    unsupported.hidden = false;
  };
  img.src = attachedImagePreviewUrl;
  document.getElementById("image-preview-name").textContent = filename;
  document.getElementById("image-preview-wrap").hidden = false;
  document.getElementById("image-dropzone-prompt").hidden = true;
}

function clearAttachedImage() {
  if (attachedImagePreviewUrl) {
    URL.revokeObjectURL(attachedImagePreviewUrl);
    attachedImagePreviewUrl = null;
  }
  attachedImagePath = null;
  document.getElementById("image-preview-wrap").hidden = true;
  document.getElementById("image-dropzone-prompt").hidden = false;
}

document.getElementById("btn-choose-image").addEventListener("click", async () => {
  const path = await open({
    multiple: false,
    filters: [{ name: "Immagini", extensions: ["jpg", "jpeg", "png", "heic", "heif"] }],
  });
  if (path) await setAttachedImage(path);
});

document.getElementById("btn-remove-image").addEventListener("click", () => {
  clearAttachedImage();
});

// Il drag&drop nativo di Tauri e' a livello di finestra (da' percorsi
// file, non oggetti File del browser): accettiamo un file solo quando la
// scheda "Scrivi" e' quella attiva, per non "rubare" un drop destinato ad
// altre parti dell'app.
getCurrentWebview().onDragDropEvent((event) => {
  const dropzone = document.getElementById("image-dropzone");
  if (event.payload.type === "over") {
    if (document.getElementById("tab-write").classList.contains("active")) {
      dropzone.classList.add("dragover");
    }
    return;
  }
  dropzone.classList.remove("dragover");
  if (event.payload.type !== "drop") return;
  if (!document.getElementById("tab-write").classList.contains("active")) return;

  const path = event.payload.paths[0];
  if (path) setAttachedImage(path);
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

document.getElementById("btn-go-create").addEventListener("click", () => {
  setView("screen-create-name");
});

document.getElementById("btn-go-import").addEventListener("click", () => {
  setView("screen-import");
});

// ---------- Schermata: sblocco ----------

document.getElementById("btn-unlock").addEventListener("click", async (e) => {
  setError("unlock-error", null);
  const passphrase = document.getElementById("unlock-passphrase").value;
  try {
    const view = await withLoading(e.currentTarget, () =>
      invoke("unlock_identity", { passphrase })
    );
    await renderIdentity(view);
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
    await renderIdentity(view);
    pendingSeedWords = view.seed_words;
    renderSeedGrid(pendingSeedWords);
    setView("screen-seed");
  } catch (err) {
    setError("setup-error", String(err));
  }
});

// ---------- Schermata: ho già un'identità (import) ----------

document.getElementById("btn-import").addEventListener("click", async (e) => {
  setError("import-error", null);
  const displayName = document.getElementById("import-display-name").value;
  const phrase = document.getElementById("import-phrase").value;
  try {
    const view = await withLoading(e.currentTarget, () =>
      invoke("import_identity", { phrase, displayName })
    );
    await renderIdentity(view);
    // Chi reinserisce una seed phrase la conosce già: non c'è bisogno di
    // rimostrarla/confermarla, si passa direttamente a proteggere questo
    // dispositivo con una passphrase locale.
    setView("screen-set-passphrase");
  } catch (err) {
    setError("import-error", String(err));
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
      setView("screen-set-passphrase");
    } else {
      document.getElementById("confirm-error").hidden = false;
    }
  } catch (err) {
    setError("confirm-error", String(err));
  }
});

// ---------- Schermata: imposta la passphrase locale ----------

document.getElementById("btn-save-passphrase").addEventListener("click", async (e) => {
  setError("set-passphrase-error", null);
  const passphrase = document.getElementById("set-passphrase").value;
  const confirmPassphrase = document.getElementById("set-passphrase-confirm").value;

  if (passphrase.length < 8) {
    setError("set-passphrase-error", "La passphrase deve avere almeno 8 caratteri.");
    return;
  }
  if (passphrase !== confirmPassphrase) {
    setError("set-passphrase-error", "Le due passphrase non coincidono.");
    return;
  }

  try {
    await withLoading(e.currentTarget, () =>
      invoke("save_identity_to_disk", { passphrase })
    );
    document.getElementById("set-passphrase").value = "";
    document.getElementById("set-passphrase-confirm").value = "";
    setView("screen-main");
  } catch (err) {
    setError("set-passphrase-error", String(err));
  }
});

// ---------- Tabs (sezioni della app operativa) ----------

for (const btn of document.querySelectorAll(".tab-btn")) {
  btn.addEventListener("click", () => {
    for (const b of document.querySelectorAll(".tab-btn")) b.classList.remove("active");
    for (const p of document.querySelectorAll(".tab-panel")) p.classList.remove("active");
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
}

// ---------- Rubrica ----------

document.getElementById("btn-add-contact").addEventListener("click", async (e) => {
  setError("contact-error", null);
  const name = document.getElementById("contact-name").value.trim();
  const key = document.getElementById("contact-key").value.trim();
  if (!name || !key) {
    setError("contact-error", "Inserisci sia il nome che la chiave pubblica.");
    return;
  }
  try {
    const view = await withLoading(e.currentTarget, () =>
      invoke("add_contact", { name, armoredPublicKey: key })
    );
    contacts.push({
      name: view.name,
      key: view.key,
      fingerprintHex: view.fingerprint_hex,
      fingerprintWords: view.fingerprint_words,
    });
    renderContactList();

    const hintPanel = document.getElementById("contact-added-hint");
    hintPanel.querySelector("p:first-child").textContent =
      `${name} aggiunto/a. Per essere sicuro che sia davvero ${name} (e non qualcuno che finge di esserlo), leggi a voce queste parole a ${name} e verifica che corrispondano a quelle che vede anche ${name}:`;
    hintPanel.querySelector(".fingerprint-words").textContent = view.fingerprint_words.join("  ");
    hintPanel.hidden = false;

    document.getElementById("contact-name").value = "";
    document.getElementById("contact-key").value = "";
  } catch (err) {
    setError("contact-error", String(err));
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

document.getElementById("btn-encrypt").addEventListener("click", async (e) => {
  setError("encrypt-error", null);
  document.getElementById("encrypt-result").hidden = true;
  document.getElementById("encrypt-image-result").hidden = true;

  const selected = [...document.querySelectorAll('#recipient-list input[type="checkbox"]:checked')]
    .map((el) => contacts[Number(el.value)].key);
  const plaintext = document.getElementById("message-text").value;
  const sign = document.getElementById("sign-message").checked;

  if (selected.length === 0) {
    setError("encrypt-error", "Seleziona almeno un destinatario.");
    return;
  }
  if (!plaintext && !attachedImagePath) {
    setError("encrypt-error", "Scrivi un messaggio o allega un'immagine prima di cifrare.");
    return;
  }

  try {
    await withLoading(e.currentTarget, async () => {
      let textDone = false;
      let imageDone = false;

      if (plaintext) {
        const ciphertext = await invoke("encrypt_message", {
          recipientsArmored: selected,
          plaintext,
          sign,
        });
        document.getElementById("ciphertext-out").value = ciphertext;
        document.getElementById("encrypt-result").hidden = false;
        textDone = true;
      }

      if (attachedImagePath) {
        const sourceName = attachedImagePath.split(/[\\/]/).pop();
        const ext = currentImageFormat === "gpg" ? "gpg" : "asc";
        const outputPath = await save({
          defaultPath: `${sourceName}.${ext}`,
          filters: [{ name: "Immagine cifrata", extensions: [ext] }],
        });
        if (outputPath) {
          await invoke("encrypt_image", {
            recipientsArmored: selected,
            sourcePath: attachedImagePath,
            outputPath,
            sign,
          });
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
        clearAttachedImage();
      }
      if (textDone || imageDone) {
        for (const checkbox of document.querySelectorAll(
          '#recipient-list input[type="checkbox"]:checked'
        )) {
          checkbox.checked = false;
        }
        document.getElementById("sign-message").checked = false;
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

function renderDecryptResult(result) {
  lastDecrypted = null;

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
  const imageBlock = document.getElementById("decrypt-result-image");
  const fileBlock = document.getElementById("decrypt-result-file");
  textBlock.hidden = true;
  imageBlock.hidden = true;
  fileBlock.hidden = true;

  if (result.kind === "testo") {
    document.getElementById("plaintext-out").value = result.plaintext;
    textBlock.hidden = false;
  } else if (result.kind === "immagine") {
    const bytes = base64ToBytes(result.image_data_base64);
    lastDecrypted = { bytes, filename: result.filename };

    const img = document.getElementById("decrypt-image-preview");
    const unsupported = document.getElementById("decrypt-image-unsupported");
    img.onload = () => {
      img.hidden = false;
      unsupported.hidden = true;
    };
    img.onerror = () => {
      img.hidden = true;
      unsupported.hidden = false;
    };
    img.src = `data:${result.image_mime};base64,${result.image_data_base64}`;
    imageBlock.hidden = false;
  } else {
    lastDecrypted = { bytes: base64ToBytes(result.image_data_base64), filename: result.filename };
    fileBlock.hidden = false;
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

  try {
    const result = await withLoading(button, () =>
      invoke("decrypt_file", { contactsArmored: contacts.map((c) => c.key), path })
    );
    renderDecryptResult(result);
  } catch (err) {
    setError("decrypt-error", String(err));
  }
});

document.getElementById("btn-decrypt").addEventListener("click", async (e) => {
  setError("decrypt-error", null);
  document.getElementById("decrypt-result").hidden = true;

  const ciphertext = document.getElementById("ciphertext-in").value;
  if (!ciphertext) {
    setError("decrypt-error", "Incolla o apri prima un messaggio cifrato.");
    return;
  }

  try {
    const result = await withLoading(e.currentTarget, () =>
      invoke("decrypt_message", { contactsArmored: contacts.map((c) => c.key), ciphertext })
    );
    renderDecryptResult(result);
  } catch (err) {
    setError("decrypt-error", String(err));
  }
});

async function saveLastDecrypted(defaultName) {
  if (!lastDecrypted) return;
  const suggested = lastDecrypted.filename || defaultName;
  const path = await save({ defaultPath: suggested });
  if (path) await writeFile(path, lastDecrypted.bytes);
}

document.getElementById("btn-save-decrypted-image").addEventListener("click", () => {
  saveLastDecrypted("immagine-decifrata");
});

document.getElementById("btn-save-decrypted-file").addEventListener("click", () => {
  saveLastDecrypted("file-decifrato");
});

// ---------- Identita ----------

document.getElementById("btn-copy-pubkey").addEventListener("click", async () => {
  await writeText(document.getElementById("my-public-key").value);
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
  document.getElementById("adv-my-fingerprint-hex").textContent =
    currentIdentity ? currentIdentity.fingerprint_hex : "";

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

init();
