use std::env;
use std::fs;
use std::process::exit;
use tritrpc_v1::{avroenc, envelope};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    let mut out = Vec::new();
    let mut it = s.as_bytes().chunks(2);
    for ch in it {
        let hh = std::str::from_utf8(ch).unwrap();
        out.push(u8::from_str_radix(hh, 16).unwrap());
    }
    out
}

fn usage() {
    eprintln!("trpc pack --service S --method M --json path.json --nonce HEX --key HEX");
    eprintln!("trpc verify --fixtures fixtures/vectors_hex_unary_rich.txt --nonces fixtures/vectors_hex_unary_rich.txt.nonces");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        exit(1);
    }
    match args[1].as_str() {
        "pack" => {
            let mut svc = String::new();
            let mut m = String::new();
            let mut jsonp = String::new();
            let mut nonce_hex = String::new();
            let mut key_hex = String::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--service" => {
                        i += 1;
                        svc = args[i].clone();
                    }
                    "--method" => {
                        i += 1;
                        m = args[i].clone();
                    }
                    "--json" => {
                        i += 1;
                        jsonp = args[i].clone();
                    }
                    "--nonce" => {
                        i += 1;
                        nonce_hex = args[i].clone();
                    }
                    "--key" => {
                        i += 1;
                        key_hex = args[i].clone();
                    }
                    _ => {}
                }
                i += 1;
            }
            if svc.is_empty()
                || m.is_empty()
                || jsonp.is_empty()
                || nonce_hex.is_empty()
                || key_hex.is_empty()
            {
                usage();
                exit(2);
            }
            let js = fs::read_to_string(&jsonp).expect("read json");
            let v: serde_json::Value = serde_json::from_str(&js).expect("json");
            let payload = if m.ends_with(".REQ") || m.ends_with(".Req") || m.ends_with(".Request") {
                avroenc::enc_HGRequest(&v)
            } else if m.ends_with(".RSP") || m.ends_with(".Resp") || m.ends_with(".Response") {
                avroenc::enc_HGResponse_json(&v)
            } else {
                // raw: assume request
                avroenc::enc_HGRequest(&v)
            };
            let keyb = hex_to_bytes(&key_hex);
            let nonceb = hex_to_bytes(&nonce_hex);
            let mut key = [0u8; 32];
            key.copy_from_slice(&keyb[..32]);
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonceb[..24]);
            let (frame, _tag) = envelope::envelope_with_tag(&svc, &m, &payload, None, &key, &nonce);
            println!("{}", hex::encode(frame));
        }
        "verify" => {
            let mut fixtures = String::new();
            let mut nonces = String::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--fixtures" => {
                        i += 1;
                        fixtures = args[i].clone();
                    }
                    "--nonces" => {
                        i += 1;
                        nonces = args[i].clone();
                    }
                    _ => {}
                }
                i += 1;
            }
            if fixtures.is_empty() || nonces.is_empty() {
                usage();
                exit(3);
            }
            let out = tritrpc_v1_tests::verify_file(&fixtures, &nonces);
            println!("{}", out);
        }
        _ => {
            usage();
            exit(4);
        }
    }
}
