//! The maintainer's tool for the indicator list. Not part of the app.
//!
//!   cargo run -p lookfirst-core --example sign -- keygen KEYFILE   makes a private key, prints the public one
//!   cargo run -p lookfirst-core --example sign -- sign KEYFILE     signs crates/core/data/indicators.json

use ed25519_dalek::{Signer, SigningKey};
use std::{env, fs, io::Read};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (Some(cmd), Some(keyfile)) = (args.first(), args.get(1)) else { panic!("usage: sign keygen|sign KEYFILE") };
    let list = concat!(env!("CARGO_MANIFEST_DIR"), "/data/indicators.json");
    match cmd.as_str() {
        "keygen" => {
            assert!(!std::path::Path::new(keyfile).exists(), "{keyfile} already exists");
            let mut seed = [0u8; 32];
            fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap(); // macOS and Linux
            fs::write(keyfile, hex(&seed)).unwrap();
            println!("public key: {}", hex(SigningKey::from_bytes(&seed).verifying_key().as_bytes()));
        }
        "sign" => {
            let seed: [u8; 32] = (0..32)
                .map(|i| {
                    u8::from_str_radix(&fs::read_to_string(keyfile).unwrap().trim()[i * 2..i * 2 + 2], 16).unwrap()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let signature = SigningKey::from_bytes(&seed).sign(&fs::read(list).unwrap());
            fs::write(format!("{list}.sig"), hex(&signature.to_bytes())).unwrap();
            println!("signed {list}");
        }
        _ => panic!("usage: sign keygen|sign KEYFILE"),
    }
}
