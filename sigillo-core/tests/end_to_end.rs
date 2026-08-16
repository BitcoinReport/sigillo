use sigillo_core::{contacts, identity, message};

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

#[test]
fn reimported_identity_can_still_decrypt_old_messages() {
    let alice = alice();
    let ciphertext =
        message::encrypt(&alice.cert, &[alice.cert.clone()], "Nota per me stesso", false).unwrap();

    // Simula: Alice reinstalla Sigillo su un altro dispositivo e reinserisce
    // la stessa seed phrase.
    let alice_again = identity::import(&alice.seed_phrase(), "Alice").unwrap();
    assert_eq!(alice.cert.fingerprint(), alice_again.cert.fingerprint());

    let decrypted = message::decrypt(&alice_again.cert, &[], &ciphertext).unwrap();
    assert_eq!(decrypted.plaintext, "Nota per me stesso");
}
