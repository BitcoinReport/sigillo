const { invoke } = window.__TAURI__.core;
const { save, open } = window.__TAURI__.dialog;
const { writeTextFile, readTextFile } = window.__TAURI__.fs;
const { writeText } = window.__TAURI__.clipboardManager;

/** @type {{name: string, key: string, fingerprintHex: string, fingerprintWords: string[]}[]} */
const contacts = [];
let currentIdentity = null;
let pendingSeedWords = [];

// ---------- Stato applicativo: una sola vista visibile alla volta ----------
//
// setView() e l'UNICO modo per cambiare schermata: aggiunge/rimuove la
// classe "active" (mai display:none via l'attributo hidden, vedi il
// commento in styles.css sul perche). Ogni bottone che fa avanzare il
// flusso chiama setView con l'id della vista successiva; nessuna vista e
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
 * uno spinner finche' la chiamata non e' finita, cosi ogni azione asincrona
 * (generare chiavi, cifrare, sbloccare...) da un feedback immediato invece
 * di sembrare "morta" per uno o due secondi.
 */
async function withLoading(button, action) {
  button.disabled = true;
  button.classList.add("is-loading");
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.classList.remove("is-loading");
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

function renderIdentity(view) {
  currentIdentity = view;
  document.getElementById("my-name").textContent = view.display_name;
  document.getElementById("my-fingerprint-words").textContent =
    view.fingerprint_words.join("  ");
  document.getElementById("my-public-key").value = view.public_key_armored;
  document.getElementById("btn-open-advanced").hidden = false;
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
      '<p class="hint">Nessun contatto in rubrica. Aggiungine uno dalla scheda "Rubrica".</p>';
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
  document.getElementById("btn-open-advanced").hidden = true;
  document.getElementById("display-name").value = "";
  document.getElementById("import-display-name").value = "";
  document.getElementById("import-phrase").value = "";
  document.getElementById("my-public-key").value = "";
  document.getElementById("ciphertext-in").value = "";
  document.getElementById("ciphertext-out").value = "";
  document.getElementById("message-text").value = "";
}

// ---------- Avvio: identita gia presente su questo dispositivo? ----------

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
    renderIdentity(view);
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

// ---------- Schermata: crea nuova identita ----------

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
    renderIdentity(view);
    pendingSeedWords = view.seed_words;
    renderSeedGrid(pendingSeedWords);
    setView("screen-seed");
  } catch (err) {
    setError("setup-error", String(err));
  }
});

// ---------- Schermata: ho gia un'identita (import) ----------

document.getElementById("btn-import").addEventListener("click", async (e) => {
  setError("import-error", null);
  const displayName = document.getElementById("import-display-name").value;
  const phrase = document.getElementById("import-phrase").value;
  try {
    const view = await withLoading(e.currentTarget, () =>
      invoke("import_identity", { phrase, displayName })
    );
    renderIdentity(view);
    // Chi reinserisce una seed phrase la conosce gia: non c'e bisogno di
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
    const fp = await withLoading(e.currentTarget, () =>
      invoke("contact_fingerprint_words", { armoredPublicKey: key })
    );
    contacts.push({
      name,
      key,
      fingerprintHex: fp.fingerprint_hex,
      fingerprintWords: fp.fingerprint_words,
    });
    renderContactList();
    document.getElementById("contact-name").value = "";
    document.getElementById("contact-key").value = "";
  } catch (err) {
    setError("contact-error", String(err));
  }
});

// ---------- Scrivi / cifra ----------

document.getElementById("btn-encrypt").addEventListener("click", async (e) => {
  setError("encrypt-error", null);
  document.getElementById("encrypt-result").hidden = true;

  const selected = [...document.querySelectorAll('#recipient-list input[type="checkbox"]:checked')]
    .map((el) => contacts[Number(el.value)].key);
  const plaintext = document.getElementById("message-text").value;
  const sign = document.getElementById("sign-message").checked;

  if (selected.length === 0) {
    setError("encrypt-error", "Seleziona almeno un destinatario.");
    return;
  }
  if (!plaintext) {
    setError("encrypt-error", "Scrivi un messaggio prima di cifrarlo.");
    return;
  }

  try {
    const ciphertext = await withLoading(e.currentTarget, () =>
      invoke("encrypt_message", { recipientsArmored: selected, plaintext, sign })
    );
    document.getElementById("ciphertext-out").value = ciphertext;
    document.getElementById("encrypt-result").hidden = false;
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

document.getElementById("btn-load-file").addEventListener("click", async () => {
  const path = await open({
    multiple: false,
    filters: [{ name: "Messaggio cifrato", extensions: ["asc", "pgp", "txt"] }],
  });
  if (path) {
    const contents = await readTextFile(path);
    document.getElementById("ciphertext-in").value = contents;
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
    document.getElementById("plaintext-out").value = result.plaintext;

    const statusEl = document.getElementById("signature-status");
    statusEl.className = "signature-status";
    if (result.signature_status === "verificata") {
      const known = contacts.find((c) => c.fingerprintHex === result.signer_fingerprint);
      statusEl.textContent = known
        ? `Firma verificata: e di ${known.name}.`
        : `Firma verificata (${result.signer_fingerprint}), ma questo contatto non e in rubrica.`;
      statusEl.classList.add("verified");
    } else if (result.signature_status === "non_verificabile") {
      statusEl.textContent =
        "Il messaggio e firmato, ma non conosci ancora la chiave di chi l'ha firmato: aggiungilo in rubrica per verificarlo.";
      statusEl.classList.add("unverifiable");
    } else {
      statusEl.textContent = "Messaggio non firmato.";
      statusEl.classList.add("unsigned");
    }

    document.getElementById("decrypt-result").hidden = false;
  } catch (err) {
    setError("decrypt-error", String(err));
  }
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

  const contactsContainer = document.getElementById("adv-contacts");
  contactsContainer.innerHTML = "";
  if (contacts.length === 0) {
    contactsContainer.innerHTML = '<p class="hint">Nessun contatto in rubrica.</p>';
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
