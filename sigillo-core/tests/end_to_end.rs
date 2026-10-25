use std::io::Read;

use sigillo_core::{attachment, composite, contacts, identity, message};

fn alice() -> identity::Identity {
    identity::generate(identity::SeedWordCount::TwentyFour, "Alice").unwrap()
}

fn bob() -> identity::Identity {
    identity::generate(identity::SeedWordCount::TwentyFour, "Bob").unwrap()
}

#[test]
fn encrypt_then_decrypt_round_trip_unsigned() {
    let alice = alice();
    let bob = bob();

    let ciphertext = message::encrypt(&alice.cert, &[bob.cert.clone()], "Ciao Bob!", false).unwrap();
    assert!(ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"));

    let decrypted = message::decrypt(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.plaintext, "Ciao Bob!");
    assert_eq!(decrypted.signature, message::SignatureStatus::Unsigned);
}

#[test]
fn encrypt_then_decrypt_round_trip_signed_and_verified() {
    let alice = alice();
    let bob = bob();

    let ciphertext =
        message::encrypt(&alice.cert, &[bob.cert.clone()], "Messaggio firmato", true).unwrap();

    // Bob conosce la chiave pubblica di Alice (e in rubrica).
    let alice_public = alice.cert.clone().strip_secret_key_material();
    let decrypted = message::decrypt(&bob.cert, &[alice_public], &ciphertext).unwrap();

    assert_eq!(decrypted.plaintext, "Messaggio firmato");
    match decrypted.signature {
        message::SignatureStatus::Verified(fp) => assert_eq!(fp, alice.cert.fingerprint()),
        other => panic!("firma non verificata: {other:?}"),
    }
}

#[test]
fn signed_message_without_sender_in_contacts_is_unverifiable() {
    let alice = alice();
    let bob = bob();

    let ciphertext =
        message::encrypt(&alice.cert, &[bob.cert.clone()], "Chi ha scritto questo?", true).unwrap();

    // Bob NON ha la chiave pubblica di Alice in rubrica.
    let decrypted = message::decrypt(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.plaintext, "Chi ha scritto questo?");
    assert_eq!(decrypted.signature, message::SignatureStatus::Unverifiable);
}

#[test]
fn multi_recipient_encryption_every_recipient_can_decrypt() {
    let alice = alice();
    let bob = bob();
    let carol = identity::generate(identity::SeedWordCount::Twelve, "Carol").unwrap();

    let ciphertext = message::encrypt(
        &alice.cert,
        &[bob.cert.clone(), carol.cert.clone()],
        "Messaggio di gruppo",
        false,
    )
    .unwrap();

    assert_eq!(
        message::decrypt(&bob.cert, &[], &ciphertext).unwrap().plaintext,
        "Messaggio di gruppo"
    );
    assert_eq!(
        message::decrypt(&carol.cert, &[], &ciphertext)
            .unwrap()
            .plaintext,
        "Messaggio di gruppo"
    );
}

#[test]
fn wrong_recipient_cannot_decrypt() {
    let alice = alice();
    let bob = bob();
    let mallory = identity::generate(identity::SeedWordCount::Twelve, "Mallory").unwrap();

    let ciphertext =
        message::encrypt(&alice.cert, &[bob.cert.clone()], "Solo per Bob", false).unwrap();

    let err = message::decrypt(&mallory.cert, &[], &ciphertext).unwrap_err();
    assert!(err.to_string().contains("non e indirizzato a te") || err.to_string().contains("non è indirizzato a te"));
}

#[test]
fn corrupted_ciphertext_is_reported_as_invalid() {
    let bob = bob();
    let err = message::decrypt(&bob.cert, &[], "questo non e un messaggio pgp").unwrap_err();
    assert!(err.to_string().contains("non") );
}

#[test]
fn contact_import_round_trip_via_armored_public_key() {
    let alice = alice();
    let exported =
        sequoia_openpgp::serialize::SerializeInto::to_vec(&alice.cert.armored()).unwrap();

    let imported = contacts::import_public_key(&exported).unwrap();
    assert_eq!(imported.fingerprint(), alice.cert.fingerprint());

    let words = contacts::fingerprint_to_words(&imported.fingerprint());
    assert_eq!(words.len(), 15);
}

// Non serve un vero file JPEG/PNG: sigillo-core cifra e decifra byte
// grezzi senza sapere (ne dover sapere) che si tratta di un'immagine -
// quella distinzione la fa il frontend, sui byte gia decifrati.
fn fake_image_bytes() -> Vec<u8> {
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0]; // firma JPEG
    data.extend((0..2000u32).map(|i| (i % 256) as u8));
    data
}

#[test]
fn encrypt_bytes_then_decrypt_bytes_round_trip_armored() {
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let ciphertext = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &image,
        Some("foto.jpg"),
        false,
        true,
    )
    .unwrap();
    assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

    let decrypted = message::decrypt_bytes(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.data, image);
    assert_eq!(decrypted.filename.as_deref(), Some("foto.jpg"));
    assert_eq!(decrypted.signature, message::SignatureStatus::Unsigned);
}

#[test]
fn encrypt_bytes_then_decrypt_bytes_round_trip_binary_gpg() {
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let ciphertext = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &image,
        Some("foto.png"),
        false,
        false,
    )
    .unwrap();
    // Formato binario: non deve iniziare col marcatore ASCII armored.
    assert!(!ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

    let decrypted = message::decrypt_bytes(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.data, image);
    assert_eq!(decrypted.filename.as_deref(), Some("foto.png"));
}

#[test]
fn encrypt_bytes_signed_image_is_verified() {
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let ciphertext = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &image,
        Some("foto.jpg"),
        true,
        true,
    )
    .unwrap();

    let alice_public = alice.cert.clone().strip_secret_key_material();
    let decrypted = message::decrypt_bytes(&bob.cert, &[alice_public], &ciphertext).unwrap();

    assert_eq!(decrypted.data, image);
    match decrypted.signature {
        message::SignatureStatus::Verified(fp) => assert_eq!(fp, alice.cert.fingerprint()),
        other => panic!("firma non verificata: {other:?}"),
    }
}

#[test]
fn encrypt_bytes_without_filename_has_no_filename_on_decrypt() {
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let ciphertext =
        message::encrypt_bytes(&alice.cert, &[bob.cert.clone()], &image, None, false, true)
            .unwrap();
    let decrypted = message::decrypt_bytes(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.data, image);
    assert_eq!(decrypted.filename, None);
}

#[test]
fn text_encrypt_is_unaffected_by_image_support() {
    // Garanzia di non-regressione: il percorso testo esistente (usato da
    // ogni test sopra) continua a passare da encrypt_bytes internamente
    // con armor=true, filename=None; qui verifichiamo esplicitamente che
    // il testo prodotto sia identico a un normale messaggio armato.
    let alice = alice();
    let bob = bob();
    let ciphertext = message::encrypt(&alice.cert, &[bob.cert.clone()], "Ciao", false).unwrap();
    let decrypted = message::decrypt(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.plaintext, "Ciao");
}

#[test]
fn combined_text_and_image_round_trip_unsigned() {
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let combined =
        composite::encode("ciao Bob, guarda qui!", Some("foto.jpg"), "image/jpeg", &image).unwrap();
    let ciphertext = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &combined,
        None,
        false,
        true,
    )
    .unwrap();

    let decrypted = message::decrypt_bytes(&bob.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.signature, message::SignatureStatus::Unsigned);

    let unpacked = composite::decode(&decrypted.data).unwrap();
    assert_eq!(unpacked.text, "ciao Bob, guarda qui!");
    assert_eq!(unpacked.attachment_filename.as_deref(), Some("foto.jpg"));
    assert_eq!(unpacked.attachment_mime, "image/jpeg");
    assert_eq!(unpacked.attachment_data, image);
}

#[test]
fn combined_text_and_image_round_trip_signed_and_verified() {
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let combined =
        composite::encode("messaggio firmato con foto", Some("foto.png"), "image/png", &image).unwrap();
    let ciphertext = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &combined,
        None,
        true,
        true,
    )
    .unwrap();

    let alice_public = alice.cert.clone().strip_secret_key_material();
    let decrypted = message::decrypt_bytes(&bob.cert, &[alice_public], &ciphertext).unwrap();
    match decrypted.signature {
        message::SignatureStatus::Verified(fp) => assert_eq!(fp, alice.cert.fingerprint()),
        other => panic!("firma non verificata: {other:?}"),
    }

    let unpacked = composite::decode(&decrypted.data).unwrap();
    assert_eq!(unpacked.text, "messaggio firmato con foto");
    assert_eq!(unpacked.attachment_data, image);
}

#[test]
fn large_payload_encrypts_and_decrypts_within_a_reasonable_time() {
    // Simula un video di circa 80 MB: verifica che cifrare/decifrare un
    // file pesante non richieda un tempo spropositato (l'interfaccia si
    // affiderebbe a questo stesso percorso, fuori dal thread della UI).
    let alice = alice();
    let bob = bob();
    let data = vec![0xABu8; 80 * 1024 * 1024];

    let start = std::time::Instant::now();
    let ciphertext = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &data,
        Some("video.mp4"),
        false,
        false, // binario, non armato: piu' realistico per un file cosi' grande
    )
    .unwrap();
    let decrypted = message::decrypt_bytes(&bob.cert, &[], &ciphertext).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(decrypted.data, data);
    assert!(
        elapsed.as_secs() < 15,
        "cifratura+decifratura di 80 MB troppo lenta: {elapsed:?}"
    );
}

#[test]
fn reimported_identity_can_still_decrypt_old_messages() {
    let alice = alice();
    let ciphertext =
        message::encrypt(&alice.cert, &[alice.cert.clone()], "Nota per me stesso", false).unwrap();

    // Simula: Alice reinstalla Sigillo su un altro dispositivo e reinserisce
    // la stessa seed phrase.
    let alice_again = identity::import(&alice.seed_phrase().unwrap(), "Alice").unwrap();
    assert_eq!(alice.cert.fingerprint(), alice_again.cert.fingerprint());

    let decrypted = message::decrypt(&alice_again.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.plaintext, "Nota per me stesso");
}


// ---------- Allegati generici, cifratura/decifratura "a flusso" ----------

/// Byte pseudo-casuali ma riproducibili (niente dipendenze in piu').
fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Cifra "a flusso" un messaggio combinato (testo + file) in `out_path`,
/// leggendo il file da `source_path`, esattamente come fanno i comandi
/// dell'app: l'intestazione si scrive prima, poi il file si copia a pezzi.
fn encrypt_combined_to_file(
    sender: &identity::Identity,
    recipient: &identity::Identity,
    text: &str,
    source_path: &std::path::Path,
    attachment_name: &str,
    sign: bool,
    armor: bool,
    out_path: &std::path::Path,
) {
    let len = std::fs::metadata(source_path).unwrap().len();
    let mut head = vec![0u8; 16];
    let read = std::fs::File::open(source_path).unwrap().read(&mut head).unwrap();
    head.truncate(read);
    let mime = attachment::resolve_mime(&head, Some(attachment_name));

    let header = composite::encode_header(text, Some(attachment_name), mime, len).unwrap();
    let out = std::io::BufWriter::new(std::fs::File::create(out_path).unwrap());
    message::encrypt_to_writer(
        &sender.cert,
        &[recipient.cert.clone()],
        None,
        sign,
        armor,
        out,
        |w| {
            w.write_all(&header)?;
            let mut src = std::io::BufReader::new(std::fs::File::open(source_path)?);
            std::io::copy(&mut src, w)?;
            Ok(())
        },
    )
    .unwrap();
}

/// Decifra "a flusso" `cipher_path`, interpreta l'intestazione combinata
/// e copia il file in `dest_path`: restituisce (intestazione, firma).
fn decrypt_combined_from_file(
    recipient: &identity::Identity,
    contacts: &[sequoia_openpgp::Cert],
    cipher_path: &std::path::Path,
    dest_path: &std::path::Path,
) -> (composite::CompositeHeader, message::SignatureStatus) {
    let input = std::fs::File::open(cipher_path).unwrap();
    let outcome = message::decrypt_streaming(&recipient.cert, contacts, input, |plain, _name| {
        let header = composite::read_header(&mut *plain)?;
        let mut dest = std::fs::File::create(dest_path)?;
        let copied = std::io::copy(&mut plain.take(header.attachment_len), &mut dest)?;
        assert_eq!(copied, header.attachment_len);
        Ok(header)
    })
    .unwrap();
    (outcome.value, outcome.signature)
}

#[test]
fn streaming_round_trip_of_many_file_types_keeps_name_size_and_bytes() {
    let alice = alice();
    let bob = bob();
    let dir = tempfile::tempdir().unwrap();

    // (nome, contenuto): PDF, Office, LibreOffice, testo, CSV, ZIP, audio,
    // estensione sconosciuta, nome con caratteri non ASCII.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("relazione.pdf", [b"%PDF-1.7\n".to_vec(), pseudo_random_bytes(300_000, 1)].concat()),
        ("bilancio.docx", [b"PK\x03\x04".to_vec(), pseudo_random_bytes(120_000, 2)].concat()),
        ("conti.xlsx", [b"PK\x03\x04".to_vec(), pseudo_random_bytes(80_000, 3)].concat()),
        ("slide.pptx", [b"PK\x03\x04".to_vec(), pseudo_random_bytes(200_000, 4)].concat()),
        ("lettera.odt", [b"PK\x03\x04".to_vec(), pseudo_random_bytes(50_000, 5)].concat()),
        ("note.txt", "riga uno\nriga due è accentata\n".as_bytes().to_vec()),
        ("tabella.csv", "a;b;c\n1;2;3\n".as_bytes().to_vec()),
        ("archivio.zip", [b"PK\x03\x04".to_vec(), pseudo_random_bytes(500_000, 6)].concat()),
        ("canzone.mp3", [b"ID3\x03".to_vec(), pseudo_random_bytes(400_000, 7)].concat()),
        ("dati.xyz", pseudo_random_bytes(1234, 8)),
        ("Documento è finale (v2).pdf", [b"%PDF-1.4".to_vec(), pseudo_random_bytes(10_000, 9)].concat()),
        ("vuoto.bin", Vec::new()),
    ];

    for (index, (name, content)) in cases.iter().enumerate() {
        for (armor, sign) in [(true, false), (false, true)] {
            let source = dir.path().join(format!("sorgente-{index}"));
            std::fs::write(&source, content).unwrap();
            let cipher = dir.path().join(format!("cifrato-{index}-{armor}"));
            let plain = dir.path().join(format!("decifrato-{index}-{armor}"));

            encrypt_combined_to_file(&alice, &bob, "testo di accompagnamento", &source, name, sign, armor, &cipher);
            let alice_public = alice.cert.clone().strip_secret_key_material();
            let (header, signature) = decrypt_combined_from_file(&bob, &[alice_public], &cipher, &plain);

            assert_eq!(header.text, "testo di accompagnamento", "{name}");
            assert_eq!(header.attachment_filename.as_deref(), Some(*name), "{name}");
            assert_eq!(header.attachment_len, content.len() as u64, "{name}");
            assert_eq!(std::fs::read(&plain).unwrap(), *content, "{name}: byte diversi");
            if sign {
                assert!(matches!(signature, message::SignatureStatus::Verified(_)), "{name}");
            } else {
                assert_eq!(signature, message::SignatureStatus::Unsigned, "{name}");
            }
        }
    }
}

#[test]
fn streaming_handles_a_large_attachment_without_changing_a_byte() {
    // 40 MB: abbastanza da far girare piu' blocchi interni di Sequoia.
    let alice = alice();
    let bob = bob();
    let dir = tempfile::tempdir().unwrap();
    let content = pseudo_random_bytes(40 * 1024 * 1024, 42);
    let source = dir.path().join("grande.zip");
    std::fs::write(&source, &content).unwrap();
    let cipher = dir.path().join("grande.zip.gpg");
    let plain = dir.path().join("grande-decifrato.zip");

    encrypt_combined_to_file(&alice, &bob, "", &source, "grande.zip", false, false, &cipher);
    let (header, _) = decrypt_combined_from_file(&bob, &[], &cipher, &plain);

    assert_eq!(header.attachment_len, content.len() as u64);
    assert_eq!(std::fs::metadata(&plain).unwrap().len(), content.len() as u64);
    assert!(std::fs::read(&plain).unwrap() == content, "il file decifrato differisce");
}

#[test]
fn streaming_decryption_reads_messages_made_by_the_in_memory_encryptor() {
    // Retrocompatibilita': un messaggio prodotto dalle versioni precedenti
    // (encrypt_bytes, tutto in memoria) si decifra anche a flusso.
    let alice = alice();
    let bob = bob();
    let image = fake_image_bytes();

    let old_style = message::encrypt_bytes(
        &alice.cert,
        &[bob.cert.clone()],
        &image,
        Some("foto.jpg"),
        false,
        true,
    )
    .unwrap();

    let outcome = message::decrypt_streaming(&bob.cert, &[], std::io::Cursor::new(old_style), |plain, name| {
        let mut data = Vec::new();
        plain.read_to_end(&mut data)?;
        assert_eq!(name().as_deref(), Some("foto.jpg"));
        Ok(data)
    })
    .unwrap();
    assert_eq!(outcome.value, image);
    assert_eq!(outcome.filename.as_deref(), Some("foto.jpg"));
}

#[test]
fn streaming_encryptor_output_is_readable_by_the_in_memory_decryptor() {
    // E viceversa: cio' che produce la cifratura a flusso lo leggono
    // anche gli altri percorsi (e, per estensione, altri programmi
    // OpenPGP che seguono lo standard).
    let alice = alice();
    let bob = bob();
    let content = pseudo_random_bytes(70_000, 11);

    let mut sink = Vec::new();
    message::encrypt_to_writer(
        &alice.cert,
        &[bob.cert.clone()],
        Some("scheda.pdf"),
        false,
        true,
        &mut sink,
        |w| {
            w.write_all(&content)?;
            Ok(())
        },
    )
    .unwrap();

    assert!(sink.starts_with(b"-----BEGIN PGP MESSAGE-----"));
    let decrypted = message::decrypt_bytes(&bob.cert, &[], &sink).unwrap();
    assert_eq!(decrypted.data, content);
    assert_eq!(decrypted.filename.as_deref(), Some("scheda.pdf"));
}

#[test]
fn streaming_decryption_rejects_a_truncated_message() {
    let alice = alice();
    let bob = bob();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.bin");
    std::fs::write(&source, pseudo_random_bytes(200_000, 5)).unwrap();
    let cipher = dir.path().join("a.bin.gpg");
    encrypt_combined_to_file(&alice, &bob, "", &source, "a.bin", false, false, &cipher);

    let full = std::fs::read(&cipher).unwrap();
    // Tagliato a un terzo: niente deve risultare "decifrato con successo".
    let truncated = full[..full.len() / 3].to_vec();

    let result = message::decrypt_streaming(&bob.cert, &[], std::io::Cursor::new(truncated), |plain, _| {
        let header = composite::read_header(&mut *plain)?;
        let mut sink = Vec::new();
        plain.take(header.attachment_len).read_to_end(&mut sink)?;
        Ok(sink.len())
    });
    assert!(result.is_err(), "un messaggio troncato non deve risultare valido");
}

#[test]
fn streaming_decryption_rejects_a_tampered_message() {
    let alice = alice();
    let bob = bob();
    let content = pseudo_random_bytes(100_000, 77);
    let mut sink = Vec::new();
    message::encrypt_to_writer(&alice.cert, &[bob.cert.clone()], Some("x.bin"), false, false, &mut sink, |w| {
        w.write_all(&content)?;
        Ok(())
    })
    .unwrap();

    // Un bit cambiato nel mezzo del contenuto cifrato.
    let mid = sink.len() / 2;
    sink[mid] ^= 0x01;

    let result = message::decrypt_streaming(&bob.cert, &[], std::io::Cursor::new(sink), |plain, _| {
        let mut data = Vec::new();
        plain.read_to_end(&mut data)?;
        Ok(data)
    });
    assert!(result.is_err(), "un messaggio manomesso non deve risultare valido");
}

#[test]
fn streaming_decryption_by_the_wrong_recipient_is_refused_before_any_content() {
    let alice = alice();
    let bob = bob();
    let mallory = identity::generate(identity::SeedWordCount::Twelve, "Mallory").unwrap();
    let mut sink = Vec::new();
    message::encrypt_to_writer(&alice.cert, &[bob.cert.clone()], None, false, true, &mut sink, |w| {
        w.write_all(b"solo per Bob")?;
        Ok(())
    })
    .unwrap();

    let mut consumed = false;
    let result = message::decrypt_streaming(&mallory.cert, &[], std::io::Cursor::new(sink), |_plain, _| {
        consumed = true;
        Ok(())
    });
    assert!(result.is_err());
    assert!(!consumed, "il contenuto non deve essere consegnato a chi non e' il destinatario");
}
