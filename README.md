# Sigillo

Cifratura OpenPGP end-to-end per persone senza competenze tecniche. Scrivi un
messaggio, lo cifri con la chiave pubblica del destinatario, e lo invii con
qualsiasi app tu già usi (WhatsApp, Telegram, email...) come allegato `.asc`.

Nessun server, nessun account, nessuna telemetria. La tua identità è una
frase di 12 o 24 parole (come un wallet Bitcoin), da cui viene derivata in
modo deterministico una coppia di chiavi OpenPGP Ed25519/X25519 tramite
[Sequoia-PGP](https://sequoia-pgp.org/).

## Perché una seed phrase invece di una password

Reinserendo la stessa frase su un altro dispositivo si rigenera **esattamente
la stessa identità** (stesso fingerprint): puoi continuare a leggere i vecchi
messaggi e i tuoi contatti continuano a riconoscerti, senza bisogno di un
account o di un backup su un server. La derivazione è illustrata e testata in
[`sigillo-core/src/identity.rs`](sigillo-core/src/identity.rs).

## Struttura del progetto

```
Sigillo/
├── Cargo.toml               # workspace Rust
├── sigillo-core/             # core crittografico, indipendente dalla UI
│   ├── src/
│   │   ├── identity.rs       # seed BIP39 -> chiavi OpenPGP Ed25519/X25519
│   │   ├── message.rs        # cifra / decifra (+ firma / verifica)
│   │   ├── contacts.rs       # import chiave pubblica, fingerprint a parole
│   │   ├── storage.rs        # identita cifrata a riposo sul dispositivo (vault)
│   │   ├── keyinfo.rs        # dettagli tecnici di una chiave (sezione avanzate)
│   │   └── lib.rs
│   └── tests/end_to_end.rs   # test di integrazione (cifra->decifra, ecc.)
├── src-tauri/                 # applicazione desktop (Tauri + Rust)
│   ├── src/lib.rs             # comandi Tauri che espongono sigillo-core
│   ├── tauri.conf.json
│   └── Cargo.toml
├── frontend/                  # UI: HTML/CSS/JS puri, nessun framework
│   ├── index.html
│   ├── main.js
│   └── styles.css
└── package.json
```

`sigillo-core` non dipende da Tauri: è testabile e riutilizzabile da riga di
comando (`cargo test`), separato nettamente dall'interfaccia. Le funzioni che
toccano materiale segreto sono in `identity.rs` e sono le uniche a manipolare
byte di chiave privata; usano [`zeroize`](https://docs.rs/zeroize) per
azzerare quei buffer non appena non servono più.

## Persistenza dell'identita sul dispositivo

Al primo avvio, dopo aver generato o importato l'identita, l'app chiede di
scegliere una **passphrase locale** (almeno 8 caratteri) e salva
l'identita cifrata a riposo nella cartella dati dell'app (via
[`app_data_dir`](https://docs.rs/tauri/latest/tauri/path/struct.PathResolver.html#method.app_data_dir)
di Tauri: su macOS `~/Library/Application Support/org.sigillo.app/`, su
Linux `~/.local/share/org.sigillo.app/`, su Windows
`%APPDATA%\org.sigillo.app\`).

Agli avvii successivi l'app rileva il file gia presente e chiede solo
quella passphrase locale, non piu la seed phrase. La passphrase locale e
**diversa** dalla seed phrase: sblocca l'identita solo su questo
dispositivo, non permette di rigenerarla altrove (per quello serve sempre
la seed phrase).

Il file (`identity.sigillo`) non contiene mai la seed phrase in chiaro:
e cifrato con Argon2id (derivazione della chiave dalla passphrase,
resistente a attacchi a forza bruta) + AES-256-GCM (cifratura
autenticata). I dettagli e i test — incluso un test che scandisce
byte-per-byte il file salvato per assicurarsi che nessuna parola della
seed phrase compaia mai in chiaro — sono in
[`sigillo-core/src/storage.rs`](sigillo-core/src/storage.rs).

Dalla sezione **Avanzate** (icona ⚙ in alto a destra, una volta sbloccata
l'app) si puo rimuovere l'identita salvata su questo computer: da quel
momento l'app torna a comportarsi come al primo avvio, e per riusarla su
questo dispositivo serve reimportare la seed phrase. La stessa opzione e
disponibile anche dalla schermata di sblocco, per chi ha dimenticato la
passphrase locale (la seed phrase resta l'unico vero backup: se si perde
anche quella, l'identita non e recuperabile).

## Sezione "Avanzate"

Per restare comprensibile a chi non ha competenze tecniche, il resto
dell'interfaccia (editor, rubrica, cifra/decifra) non usa mai termini come
"chiave asimmetrica" o "fingerprint esadecimale". Chi vuole verificare i
dettagli tecnici li trova tutti in un unico posto, dietro l'icona ⚙:

- fingerprint completo (esadecimale) della propria identita e di ogni
  contatto in rubrica;
- algoritmo, data di creazione ed eventuale scadenza di ogni chiave
  (`sigillo-core/src/keyinfo.rs`);
- export della chiave privata come file OpenPGP classico, protetto da
  password (l'alternativa "meno consigliata" alla seed phrase: un file
  digitale e una superficie di attacco in piu rispetto a una frase scritta
  su carta);
- rimozione dell'identita da questo computer (vedi sopra).

## Scelte tecniche rilevanti

- **Core crittografico**: [Sequoia-PGP](https://sequoia-pgp.org/), non
  GnuPG — nessuna dipendenza da `gpg` installato sul sistema, tutto è
  compilato dentro il binario.
- **Backend crittografico**: `crypto-openssl` con OpenSSL *vendored*
  (compilato da sorgente e linkato staticamente). La build ufficiale di
  Sequoia userebbe `nettle` di default, ma richiede che l'utente finale
  abbia le librerie di sistema installate; l'alternativa pura-Rust
  (`crypto-rust`) esiste ma Sequoia stessa la marca come "non production
  ready". OpenSSL vendored dà un binario autosufficiente su Windows/Mac/Linux
  senza compromessi sulla maturità del backend.
- **Chiavi**: Ed25519 (firma) + X25519/Cv25519 (cifratura), non RSA.
- **Seed phrase**: BIP39, sempre e solo wordlist inglese, per coerenza con
  l'ecosistema dei wallet Bitcoin.
- **Framework applicativo**: [Tauri](https://tauri.app/) 2.x — webview di
  sistema (WebView2/WebKit/WebKitGTK), non Chromium incluso come in Electron:
  binari molto più piccoli e superficie di attacco minore.
- **Frontend**: HTML/CSS/JS puri, senza framework — la UI di questo MVP è
  volutamente semplice da leggere e auditare per intero.

## Licenza: GPLv3

Il progetto è distribuito sotto **GNU GPLv3 (or later)**. Per uno strumento
che promette "zero telemetria" e "nessuna chiave privata mai in chiaro", la
licenza copyleft è una garanzia in più per chi lo usa: chiunque distribuisca
una versione modificata di Sigillo (per esempio con un tracker aggiunto, o
con una backdoor) è legalmente obbligato a pubblicarne il codice sorgente.
Con una licenza permissiva (MIT/Apache) questo non sarebbe garantito. Tutte
le dipendenze dirette sono compatibili con GPLv3 (Sequoia-PGP è
LGPL-2.0-or-later, Tauri è Apache-2.0/MIT, bip39 è CC0).

Se in futuro si vuole favorire il riuso di `sigillo-core` in altri progetti
(per esempio un binding mobile), si può valutare di rilasciare quel solo
crate anche sotto una licenza più permissiva (dual-licensing), lasciando
l'applicazione desktop completa sotto GPLv3.

## Prerequisiti

- **Rust** stabile (via [rustup](https://rustup.rs/)) — versione usata in
  sviluppo: 1.97.
- **Node.js** 18+ e npm (serve solo per la CLI di Tauri, la UI non ha build
  step).
- Un compilatore C e Perl nel `PATH` (servono per compilare OpenSSL da
  sorgente al primo build): su macOS bastano gli Xcode Command Line Tools
  (`xcode-select --install`), su Linux `build-essential` + `perl`, su
  Windows i Build Tools di Visual Studio + [Strawberry
  Perl](https://strawberryperl.com/).
- I [prerequisiti di sistema di
  Tauri](https://tauri.app/start/prerequisites/) per il tuo sistema
  operativo (WebView2 già incluso in Windows 10/11 aggiornati; WebKitGTK su
  Linux).

### macOS

```bash
xcode-select --install          # se non già installati
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
brew install node
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential perl curl libwebkit2gtk-4.1-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev nodejs npm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Windows

1. Installa [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   con il carico di lavoro "Sviluppo di applicazioni desktop con C++".
2. Installa [Strawberry Perl](https://strawberryperl.com/) (serve solo per
   compilare OpenSSL da sorgente).
3. Installa Rust da [rustup.rs](https://rustup.rs/).
4. Installa [Node.js](https://nodejs.org/).

## Build ed esecuzione

Dalla cartella `Sigillo/`:

```bash
npm install                 # una tantum: scarica la CLI di Tauri
npm run tauri dev           # avvia l'app in modalità sviluppo
```

Il primo build compila anche OpenSSL da sorgente e può richiedere alcuni
minuti; i successivi sono incrementali e molto più veloci.

Per creare un pacchetto installabile per il tuo sistema operativo (`.app`/
`.dmg` su macOS, `.msi`/`.exe` su Windows, `.deb`/`.AppImage` su Linux):

```bash
npm run tauri build
```

I pacchetti finiti si trovano in `src-tauri/target/release/bundle/`.

## Testare solo il core crittografico (senza aprire l'app)

Il core è pensato per essere verificabile da riga di comando, indipendentemente dalla UI:

```bash
cargo test -p sigillo-core
```

I test coprono, tra l'altro:

- che rigenerare l'identità dalla stessa seed phrase produca sempre lo
  stesso fingerprint (anche su un "altro dispositivo" simulato);
- un ciclo completo cifra → decifra, con e senza firma;
- che un messaggio firmato risulti "non verificabile" finché il mittente
  non è in rubrica, e "verificato" una volta aggiunto;
- cifratura verso più destinatari contemporaneamente;
- che un destinatario sbagliato non riesca a decifrare;
- che un file corrotto o non-OpenPGP dia un errore comprensibile;
- che non sia possibile importare per sbaglio una chiave privata come se
  fosse quella pubblica di un contatto;
- che il file dell'identita salvata su disco non contenga mai, in nessun
  punto, la seed phrase in chiaro;
- che una passphrase locale sbagliata venga rifiutata, e che dopo
  "rimuovi identita" il file sparisca davvero;
- che il file esportato dalla sezione avanzate (chiave privata classica)
  sia protetto da password e non utilizzabile senza.

## Stato del progetto / cosa manca ancora

Questo è l'MVP richiesto dal brief: identità persistita e cifrata sul
dispositivo, cifratura, decifratura, import di un contatto, sezione
avanzate separata dal resto dell'interfaccia, e una UI minimale che copre
l'intero flusso (genera identità → mostra e conferma la seed phrase →
imposta una passphrase locale → scrivi → cifra → salva come `.asc`; più
decifratura, rubrica di base, e sblocco ai riavvii successivi).
Consapevolmente **non** ancora implementati:

- persistenza cifrata su disco della rubrica (oggi i contatti vivono solo
  in memoria per la durata della sessione — la struttura in
  `sigillo-core/src/contacts.rs` è pronta per essere collegata a uno
  storage cifrato a riposo, con lo stesso meccanismo di `storage.rs`);
- import di un contatto via QR code (oggi solo incollando testo/`.asc`);
- indicatore di robustezza reale (entropia stimata) della passphrase
  locale — oggi si applica solo un requisito minimo di 8 caratteri;
- pacchettizzazione mobile.

## Nota sulla sicurezza di questo MVP

Il codice non ha ancora ricevuto un audit di sicurezza esterno. La
separazione tra `sigillo-core` (Rust puro, senza Tauri) e l'interfaccia è
intenzionale proprio per rendere più semplice un audit mirato del solo
codice che tocca le chiavi.
