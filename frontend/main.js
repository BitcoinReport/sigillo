const { invoke } = window.__TAURI__.core;
const { save, open } = window.__TAURI__.dialog;
const { writeTextFile, readTextFile } = window.__TAURI__.fs;
const { writeText } = window.__TAURI__.clipboardManager;

/** @type {{name: string, key: string, fingerprintHex: string, fingerprintWords: string[]}[]} */
const contacts = [];
let currentIdentity = null;
let pendingSeedWords = [];

function show(id) {
  for (const el of document.querySelectorAll(".screen")) {
    el.hidden = el.id !== id;
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
  document.getElementById("my-fingerprint-hex").textContent = view.fingerprint_hex;
  document.getElementById("my-public-key").value = view.public_key_armored;
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

// ---------- Schermata 1: creazione/import identita ----------

document.getElementById("btn-generate").addEventListener("click", async () => {
  setError("setup-error", null);
  const displayName = document.getElementById("display-name").value;
  const wordCount = Number(
    document.querySelector('input[name="word-count"]:checked').value
  );
  try {
    const view = await invoke("generate_identity", {
      wordCount,
      displayName,
    });
    renderIdentity(view);
    pendingSeedWords = view.seed_words;
    renderSeedGrid(pendingSeedWords);
    show("screen-seed");
  } catch (err) {
    setError("setup-error", String(err));
  }
});

document.getElementById("btn-import").addEventListener("click", async () => {
  setError("setup-error", null);
  const displayName = document.getElementById("display-name").value;
  const phrase = document.getElementById("import-phrase").value;
  try {
    const view = await invoke("import_identity", { phrase, displayName });
    renderIdentity(view);
    show("screen-main");
  } catch (err) {
    setError("setup-error", String(err));
  }
});

// ---------- Schermata 2: mostra seed phrase ----------

document.getElementById("btn-seed-written").addEventListener("click", () => {
  const positions = pickConfirmationPositions(pendingSeedWords.length);
  renderConfirmFields(positions);
  show("screen-confirm");
});

// ---------- Schermata 3: conferma seed phrase ----------

document.getElementById("btn-confirm-check").addEventListener("click", async () => {
  setError("confirm-error", null);
  const inputs = [...document.querySelectorAll("#confirm-fields input")];
  const positionsAndWords = inputs.map((input) => [
    Number(input.dataset.position),
    input.value,
  ]);
  try {
    const ok = await invoke("confirm_seed_words", { positionsAndWords });
    if (ok) {
      show("screen-main");
    } else {
      document.getElementById("confirm-error").hidden = false;
    }
  } catch (err) {
    setError("confirm-error", String(err));
  }
});

// ---------- Tabs ----------

for (const btn of document.querySelectorAll(".tab-btn")) {
  btn.addEventListener("click", () => {
    for (const b of document.querySelectorAll(".tab-btn")) b.classList.remove("active");
    for (const p of document.querySelectorAll(".tab-panel")) p.classList.remove("active");
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
}

// ---------- Rubrica ----------

document.getElementById("btn-add-contact").addEventListener("click", async () => {
  setError("contact-error", null);
  const name = document.getElementById("contact-name").value.trim();
  const key = document.getElementById("contact-key").value.trim();
  if (!name || !key) {
    setError("contact-error", "Inserisci sia il nome che la chiave pubblica.");
    return;
  }
  try {
    const fp = await invoke("contact_fingerprint_words", {
      armoredPublicKey: key,
    });
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

document.getElementById("btn-encrypt").addEventListener("click", async () => {
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
    const ciphertext = await invoke("encrypt_message", {
      recipientsArmored: selected,
      plaintext,
      sign,
    });
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

document.getElementById("btn-decrypt").addEventListener("click", async () => {
  setError("decrypt-error", null);
  document.getElementById("decrypt-result").hidden = true;

  const ciphertext = document.getElementById("ciphertext-in").value;
  if (!ciphertext) {
    setError("decrypt-error", "Incolla o apri prima un messaggio cifrato.");
    return;
  }

  try {
    const result = await invoke("decrypt_message", {
      contactsArmored: contacts.map((c) => c.key),
      ciphertext,
    });
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

show("screen-setup");
