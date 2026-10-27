//! Ricerca di una chiave pubblica per fingerprint sul keyserver
//! keys.openpgp.org (interfaccia VKS: `GET /vks/v1/by-fingerprint/<FPR>`).
//!
//! Regole di sicurezza, in ordine di importanza:
//!
//! 1. **Il server non e' una fonte di verita'.** Cio' che arriva si
//!    accetta solo se il fingerprint della chiave ricevuta e' ESATTAMENTE
//!    quello richiesto (vedi [`fetch_verified_key`]): altrimenti si scarta
//!    tutto. Le altre chiavi eventualmente presenti nella risposta si
//!    ignorano.
//! 2. **Mai una connessione diretta se Tor e' attivo.** Con Tor attivo la
//!    richiesta passa dal proxy SOCKS5 configurato; se il proxy non
//!    risponde e' un errore, non un ripiego su una connessione diretta
//!    (rivelerebbe al server e alla rete chi si sta cercando).
//! 3. Nessun reindirizzamento seguito, dimensione della risposta limitata,
//!    timeout espliciti.

use std::io::Read;
use std::time::Duration;

use sigillo_core::contact_import;

use sequoia_openpgp::Cert;

pub const KEYSERVER_BASE: &str = "https://keys.openpgp.org";

/// Una chiave pubblica pesa pochi KB; oltre questa soglia la risposta
/// non e' una chiave.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Da dove far partire la richiesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Connessione diretta (Tor non attivo).
    Direct,
    /// Tramite il proxy SOCKS5 di un client Tor gia' in esecuzione.
    Tor { host: String, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyserverError {
    /// Il server non ha quella chiave.
    NotFound,
    /// Nessuna connessione / il server non si raggiunge.
    Offline(String),
    /// Tor e' attivo ma non si riesce a usarlo.
    TorUnavailable { host: String, port: u16 },
    Timeout,
    TorTimeout,
    RateLimited,
    Server(u16),
    /// Risposta troppo grande o che non e' una chiave.
    BadResponse,
    /// Il server ha risposto con una chiave che NON ha il fingerprint
    /// richiesto: scartata.
    FingerprintMismatch,
}

impl KeyserverError {
    /// Messaggio per l'utente, in italiano semplice, che suggerisce sempre
    /// un'alternativa quando la ricerca non e' possibile.
    pub fn user_message(&self) -> String {
        match self {
            KeyserverError::NotFound => "Questa chiave non risulta pubblicata. Chiedi a chi te l'ha data il file .asc oppure il testo della chiave.".to_string(),
            KeyserverError::Offline(_) => "Non riesco a collegarmi a keys.openpgp.org: controlla la connessione a Internet. Puoi comunque aggiungere il contatto con il file .asc o incollando il testo della chiave.".to_string(),
            KeyserverError::TorUnavailable { host, port } => format!(
                "Tor è attivo, ma non riesco a usarlo su {host}:{port}. Controlla che Tor sia in esecuzione: finché è attivo Sigillo non cerca mai senza Tor, per non rivelare chi stai cercando. Puoi comunque aggiungere il contatto con il file .asc o incollando il testo della chiave."
            ),
            KeyserverError::Timeout => "Il server non ha risposto in tempo. Riprova tra poco, oppure usa il file .asc o incolla il testo della chiave.".to_string(),
            KeyserverError::TorTimeout => "La ricerca tramite Tor non ha risposto in tempo: il primo collegamento può richiedere più di un minuto. Riprova tra poco, oppure usa il file .asc o incolla il testo della chiave.".to_string(),
            KeyserverError::RateLimited => "Il server ha ricevuto troppe richieste. Riprova tra qualche minuto, oppure usa il file .asc o incolla il testo della chiave.".to_string(),
            KeyserverError::Server(code) => format!("Il server ha risposto con un errore (codice {code}). Riprova più tardi, oppure usa il file .asc o incolla il testo della chiave."),
            KeyserverError::BadResponse => "La risposta del server non è una chiave valida. Usa il file .asc o incolla il testo della chiave.".to_string(),
            KeyserverError::FingerprintMismatch => "Il server ha risposto con una chiave diversa da quella richiesta: l'ho scartata per sicurezza. Controlla di aver scritto bene il fingerprint, oppure usa il file .asc.".to_string(),
        }
    }
}

/// Scarica la risposta grezza per `fingerprint_plain` (40 caratteri
/// esadecimali maiuscoli). Non verifica nulla sul contenuto: per quello
/// c'e' [`fetch_verified_key`].
pub fn fetch_by_fingerprint(
    base_url: &str,
    fingerprint_plain: &str,
    route: &Route,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<Vec<u8>, KeyserverError> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(total_timeout)
        .connect_timeout(connect_timeout)
        // Niente reindirizzamenti: il server non ha motivo di rimandare
        // altrove, e seguirli renderebbe meno chiaro con chi si parla.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Sigillo");

    if let Route::Tor { host, port } = route {
        // "socks5h": il nome del server si risolve dal lato del proxy,
        // cosi' nemmeno il DNS rivela cosa si sta facendo.
        let proxy_url = format!("socks5h://{host}:{port}");
        let proxy = reqwest::Proxy::all(&proxy_url).map_err(|_| KeyserverError::TorUnavailable {
            host: host.clone(),
            port: *port,
        })?;
        builder = builder.proxy(proxy);
    }

    let client = builder
        .build()
        .map_err(|e| KeyserverError::Offline(e.to_string()))?;

    let url = format!("{base_url}/vks/v1/by-fingerprint/{fingerprint_plain}");
    let response = client.get(&url).send().map_err(|e| {
        eprintln!("[sigillo/keyserver] richiesta fallita (route={route:?}): {e:?}");
        match route {
            Route::Tor { host, port } => {
                if e.is_timeout() {
                    KeyserverError::TorTimeout
                } else {
                    KeyserverError::TorUnavailable {
                        host: host.clone(),
                        port: *port,
                    }
                }
            }
            Route::Direct => {
                if e.is_timeout() {
                    KeyserverError::Timeout
                } else {
                    KeyserverError::Offline(e.to_string())
                }
            }
        }
    })?;

    match response.status().as_u16() {
        200 => {}
        404 => return Err(KeyserverError::NotFound),
        429 => return Err(KeyserverError::RateLimited),
        code => return Err(KeyserverError::Server(code)),
    }

    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| KeyserverError::BadResponse)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(KeyserverError::BadResponse);
    }
    Ok(body)
}

/// Cerca `fingerprint_plain` e restituisce la chiave SOLO se il suo
/// fingerprint e' quello richiesto. Una chiave diversa (server
/// compromesso, errore, risposta manipolata) viene scartata.
pub fn fetch_verified_key(
    base_url: &str,
    fingerprint_plain: &str,
    route: &Route,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<Cert, KeyserverError> {
    let body = fetch_by_fingerprint(base_url, fingerprint_plain, route, connect_timeout, total_timeout)?;
    let parsed = contact_import::parse_keys(&body).map_err(|_| KeyserverError::BadResponse)?;
    if parsed.found_private {
        // Un keyserver non ha motivo di mandare una chiave privata.
        return Err(KeyserverError::BadResponse);
    }
    parsed
        .public
        .into_iter()
        .find(|cert| contact_import::fingerprint_matches(cert, fingerprint_plain))
        .ok_or(KeyserverError::FingerprintMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::SerializeInto;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn short() -> (Duration, Duration) {
        (Duration::from_secs(5), Duration::from_secs(10))
    }

    fn make_cert(userid: &str) -> Cert {
        CertBuilder::new()
            .add_userid(userid)
            .add_transport_encryption_subkey()
            .generate()
            .unwrap()
            .0
    }

    fn armored(cert: &Cert) -> Vec<u8> {
        cert.armored().to_vec().unwrap()
    }

    struct TestServer {
        base: String,
        port: u16,
        hits: Arc<AtomicUsize>,
        paths: Arc<Mutex<Vec<String>>>,
    }

    /// Un piccolo server HTTP locale: risponde a ogni richiesta con
    /// `responses[path]` (status, corpo), 404 se il percorso non c'e'.
    fn spawn_server(responses: HashMap<String, (u16, Vec<u8>)>) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (h, p) = (hits.clone(), paths.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                h.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                p.lock().unwrap().push(path.clone());
                let (status, body) = responses
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, b"No key found".to_vec()));
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/pgp-keys\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        TestServer {
            base: format!("http://127.0.0.1:{port}"),
            port,
            hits,
            paths,
        }
    }

    fn path_for(fpr: &str) -> String {
        format!("/vks/v1/by-fingerprint/{fpr}")
    }

    // ---------- risposta giusta, risposte sbagliate ----------

    #[test]
    fn the_right_key_is_found_and_the_request_uses_the_documented_path() {
        let cert = make_cert("Giulia <giulia@esempio.it>");
        let fpr = cert.fingerprint().to_hex();
        let server = spawn_server(HashMap::from([(path_for(&fpr), (200, armored(&cert)))]));

        let (c, t) = short();
        let found = fetch_verified_key(&server.base, &fpr, &Route::Direct, c, t).unwrap();
        assert_eq!(found.fingerprint(), cert.fingerprint());
        assert_eq!(server.paths.lock().unwrap().as_slice(), [path_for(&fpr)]);
        // Il fingerprint nell'URL e' in maiuscolo, come da documentazione.
        assert_eq!(fpr, fpr.to_ascii_uppercase());
    }

    #[test]
    fn a_different_key_from_the_server_is_discarded() {
        // Il test chiave: il server (o chi sta in mezzo) risponde con la
        // chiave di un'altra persona.
        let wanted = make_cert("Voluta <v@esempio.it>");
        let imposter = make_cert("Impostore <i@esempio.it>");
        let fpr = wanted.fingerprint().to_hex();
        let server = spawn_server(HashMap::from([(path_for(&fpr), (200, armored(&imposter)))]));

        let (c, t) = short();
        let err = fetch_verified_key(&server.base, &fpr, &Route::Direct, c, t).unwrap_err();
        assert_eq!(err, KeyserverError::FingerprintMismatch);
    }

    #[test]
    fn a_key_hidden_among_others_is_found_but_the_others_are_ignored() {
        let wanted = make_cert("Voluta <v@esempio.it>");
        let other = make_cert("Altra <a@esempio.it>");
        let fpr = wanted.fingerprint().to_hex();
        let mut body = armored(&other);
        body.extend_from_slice(&armored(&wanted));
        let server = spawn_server(HashMap::from([(path_for(&fpr), (200, body))]));

        let (c, t) = short();
        let found = fetch_verified_key(&server.base, &fpr, &Route::Direct, c, t).unwrap();
        assert_eq!(found.fingerprint(), wanted.fingerprint());
    }

    #[test]
    fn a_private_key_in_the_response_is_never_accepted() {
        let cert = make_cert("Segreta <s@esempio.it>");
        let fpr = cert.fingerprint().to_hex();
        let body = cert.as_tsk().armored().to_vec().unwrap();
        let server = spawn_server(HashMap::from([(path_for(&fpr), (200, body))]));
        let (c, t) = short();
        assert_eq!(
            fetch_verified_key(&server.base, &fpr, &Route::Direct, c, t).unwrap_err(),
            KeyserverError::BadResponse
        );
    }

    #[test]
    fn an_unknown_fingerprint_is_reported_as_not_found() {
        let server = spawn_server(HashMap::new());
        let (c, t) = short();
        let err = fetch_verified_key(&server.base, &"A".repeat(40), &Route::Direct, c, t).unwrap_err();
        assert_eq!(err, KeyserverError::NotFound);
        assert!(err.user_message().contains("Questa chiave non risulta pubblicata"));
        assert!(err.user_message().contains(".asc"));
    }

    #[test]
    fn junk_oversized_and_error_responses_are_handled() {
        let fpr = "B".repeat(40);
        let server = spawn_server(HashMap::from([
            (path_for(&fpr), (200, b"<html>non sono una chiave</html>".to_vec())),
            (path_for(&"C".repeat(40)), (200, vec![b'x'; 2 * 1024 * 1024])),
            (path_for(&"D".repeat(40)), (429, b"slow down".to_vec())),
            (path_for(&"E".repeat(40)), (500, b"boom".to_vec())),
            (path_for(&"F".repeat(40)), (302, b"".to_vec())),
        ]));
        let (c, t) = short();
        let route = Route::Direct;
        assert_eq!(fetch_verified_key(&server.base, &fpr, &route, c, t).unwrap_err(), KeyserverError::BadResponse);
        assert_eq!(fetch_verified_key(&server.base, &"C".repeat(40), &route, c, t).unwrap_err(), KeyserverError::BadResponse);
        assert_eq!(fetch_verified_key(&server.base, &"D".repeat(40), &route, c, t).unwrap_err(), KeyserverError::RateLimited);
        assert_eq!(fetch_verified_key(&server.base, &"E".repeat(40), &route, c, t).unwrap_err(), KeyserverError::Server(500));
        // Un reindirizzamento non si segue: e' un errore del server.
        assert_eq!(fetch_verified_key(&server.base, &"F".repeat(40), &route, c, t).unwrap_err(), KeyserverError::Server(302));
    }

    #[test]
    fn no_connection_is_a_clear_error_that_points_to_the_file() {
        // Nessuno ascolta su questa porta.
        let (c, t) = (Duration::from_secs(2), Duration::from_secs(3));
        let err = fetch_verified_key("http://127.0.0.1:1", &"A".repeat(40), &Route::Direct, c, t).unwrap_err();
        assert!(matches!(err, KeyserverError::Offline(_)), "{err:?}");
        assert!(err.user_message().contains("file .asc"));
        assert!(err.user_message().contains("connessione"));
    }

    // ---------- Tor ----------

    /// Un proxy SOCKS5 minimo (senza autenticazione) che registra a chi
    /// ci si vuole collegare e inoltra tutto al server di prova: serve a
    /// verificare che con Tor attivo la richiesta passi DAVVERO dal proxy.
    fn spawn_socks_proxy(forward_to: u16) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requested = Arc::new(Mutex::new(Vec::new()));
        let r = requested.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { break };
                let r = r.clone();
                std::thread::spawn(move || {
                    let mut greeting = [0u8; 2];
                    if client.read_exact(&mut greeting).is_err() || greeting[0] != 5 {
                        return;
                    }
                    let mut methods = vec![0u8; greeting[1] as usize];
                    let _ = client.read_exact(&mut methods);
                    let _ = client.write_all(&[5, 0]);

                    let mut head = [0u8; 4];
                    if client.read_exact(&mut head).is_err() {
                        return;
                    }
                    let host = match head[3] {
                        1 => {
                            let mut ip = [0u8; 4];
                            let _ = client.read_exact(&mut ip);
                            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                        }
                        3 => {
                            let mut len = [0u8; 1];
                            let _ = client.read_exact(&mut len);
                            let mut name = vec![0u8; len[0] as usize];
                            let _ = client.read_exact(&mut name);
                            String::from_utf8_lossy(&name).to_string()
                        }
                        _ => return,
                    };
                    let mut port_bytes = [0u8; 2];
                    let _ = client.read_exact(&mut port_bytes);
                    r.lock().unwrap().push(format!("{host}:{}", u16::from_be_bytes(port_bytes)));
                    let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

                    let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", forward_to)) else { return };
                    let mut client_r = client.try_clone().unwrap();
                    let mut upstream_w = upstream.try_clone().unwrap();
                    let t = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut client_r, &mut upstream_w);
                    });
                    let _ = std::io::copy(&mut upstream, &mut client);
                    let _ = t.join();
                });
            }
        });
        (port, requested)
    }

    #[test]
    fn with_tor_active_the_request_goes_through_the_proxy() {
        let cert = make_cert("Giulia <giulia@esempio.it>");
        let fpr = cert.fingerprint().to_hex();
        let server = spawn_server(HashMap::from([(path_for(&fpr), (200, armored(&cert)))]));
        let (proxy_port, requested) = spawn_socks_proxy(server.port);

        let route = Route::Tor {
            host: "127.0.0.1".to_string(),
            port: proxy_port,
        };
        let (c, t) = short();
        let found = fetch_verified_key("http://ricerca.esempio.test", &fpr, &route, c, t).unwrap();
        assert_eq!(found.fingerprint(), cert.fingerprint());
        // Il nome del server e' arrivato al proxy (socks5h): niente DNS locale.
        assert_eq!(requested.lock().unwrap().as_slice(), ["ricerca.esempio.test:80"]);
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn with_tor_active_and_unreachable_there_is_no_direct_connection() {
        // Il server di prova e' raggiungibile direttamente, ma il proxy
        // Tor no: la ricerca deve FALLIRE senza mai toccare il server.
        let cert = make_cert("Giulia <giulia@esempio.it>");
        let fpr = cert.fingerprint().to_hex();
        let server = spawn_server(HashMap::from([(path_for(&fpr), (200, armored(&cert)))]));

        let route = Route::Tor {
            host: "127.0.0.1".to_string(),
            port: 1, // nessun proxy qui
        };
        let (c, t) = (Duration::from_secs(2), Duration::from_secs(4));
        let err = fetch_verified_key(&server.base, &fpr, &route, c, t).unwrap_err();
        assert!(
            matches!(err, KeyserverError::TorUnavailable { .. } | KeyserverError::TorTimeout),
            "{err:?}"
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 0, "nessuna connessione diretta con Tor attivo");
        assert!(err.user_message().contains("Tor"));
    }

    #[test]
    fn a_proxy_that_never_answers_is_a_tor_timeout() {
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in silent.incoming().flatten() {
                std::thread::sleep(Duration::from_secs(5));
                drop(s);
            }
        });
        let route = Route::Tor { host: "127.0.0.1".into(), port };
        let err = fetch_verified_key(
            "http://ricerca.esempio.test",
            &"A".repeat(40),
            &route,
            Duration::from_millis(400),
            Duration::from_millis(600),
        )
        .unwrap_err();
        assert!(
            matches!(err, KeyserverError::TorTimeout | KeyserverError::TorUnavailable { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn every_error_message_is_in_plain_italian_and_offers_an_alternative_when_useful() {
        let all = [
            KeyserverError::NotFound,
            KeyserverError::Offline("x".into()),
            KeyserverError::TorUnavailable { host: "127.0.0.1".into(), port: 9050 },
            KeyserverError::Timeout,
            KeyserverError::TorTimeout,
            KeyserverError::RateLimited,
            KeyserverError::Server(503),
            KeyserverError::BadResponse,
            KeyserverError::FingerprintMismatch,
        ];
        for e in all {
            let m = e.user_message();
            assert!(!m.is_empty());
            assert!(!m.contains("reqwest") && !m.contains("Error {") && !m.contains("hyper"), "{m}");
            assert!(m.contains(".asc"), "{m}");
        }
    }

    // ---------- il vero keys.openpgp.org ----------

    #[test]
    #[ignore = "richiede Internet: contatta davvero keys.openpgp.org (esegui con `cargo test -- --ignored`)"]
    fn the_real_keyserver_answers_as_expected() {
        let (c, t) = (Duration::from_secs(20), Duration::from_secs(20));
        // La chiave di firma di Sigillo e' pubblicata: si trova, e ha il fingerprint richiesto.
        let fpr = "1382C05E9772233CC957CA7AFF68AF59F8CEC835";
        let cert = fetch_verified_key(KEYSERVER_BASE, fpr, &Route::Direct, c, t).unwrap();
        assert!(contact_import::fingerprint_matches(&cert, fpr));
        let summary = contact_import::summarize(&cert, std::time::SystemTime::now());
        assert_eq!(summary.fingerprint_plain, fpr);

        // Un fingerprint che non esiste: "non trovata".
        let err = fetch_verified_key(KEYSERVER_BASE, &"0".repeat(40), &Route::Direct, c, t).unwrap_err();
        assert_eq!(err, KeyserverError::NotFound);
    }

    #[test]
    #[ignore = "richiede Internet e un demone Tor in ascolto su 127.0.0.1:9050: esegui con `cargo test -- --ignored`"]
    fn the_real_keyserver_answers_through_a_real_tor_daemon() {
        let route = Route::Tor { host: "127.0.0.1".into(), port: 9050 };
        let (c, t) = (Duration::from_secs(90), Duration::from_secs(120));
        let fpr = "1382C05E9772233CC957CA7AFF68AF59F8CEC835";
        let cert = fetch_verified_key(KEYSERVER_BASE, fpr, &route, c, t).unwrap();
        assert!(contact_import::fingerprint_matches(&cert, fpr));
    }
}
