//! Solo per test manuali: cifra uno o più file su un'identità Sigillo e
//! scrive i .asc. Con "new" come primo argomento genera un'identità
//! usa-e-getta e ne stampa la seed phrase; altrimenti il primo argomento
//! è una seed phrase esistente su cui cifrare.
//!
//!   cargo run -p sigillo-core --example make_test_asc -- new  in1 out1 [in2 out2 ...]
//!   cargo run -p sigillo-core --example make_test_asc -- "parola1 parola2 ..." in out

use sigillo_core::{identity, message};

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let first = args.remove(0);

    let id = if first == "new" {
        let id = identity::generate(identity::SeedWordCount::Twelve, "Test")?;
        println!("SEED_PHRASE={}", id.seed_phrase().unwrap());
        id
    } else {
        identity::import(&first, "Test")?
    };

    for pair in args.chunks(2) {
        let (in_path, out_path) = (&pair[0], &pair[1]);
        let data = std::fs::read(in_path)?;
        let filename = std::path::Path::new(in_path)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned());
        let asc = message::encrypt_bytes(
            &id.cert,
            std::slice::from_ref(&id.cert),
            &data,
            filename.as_deref(),
            false,
            true,
        )?;
        std::fs::write(out_path, &asc)?;
        println!("OUT={out_path} ({} byte)", asc.len());
    }
    Ok(())
}
