use eth_stealth_addresses::{
    generate_stealth_meta_address,
    generate_stealth_address,
    decode_priv,
    get_pubkey_from_priv,
    encode_stealth_meta_address,
    compute_stealth_key,
    encode_pubkey,
    check_stealth_address_fast,
};

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::prelude::*;
use serde_json;
use serde::{Deserialize, Serialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use std::io::{self, Write};

const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Serialize, Deserialize)]
struct EncryptedKeyfile {
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct DecryptedKeys {
    spending_key: [u8; 32],
    viewing_key: [u8; 32],
}

#[derive(Deserialize)]
struct FullStealthAddress {
    stealth_address: String,
    ephemeral_pubkey: String,
    view_tag: u8
}

#[derive(Deserialize)]
struct ScannableList {
    announcements: Vec<FullStealthAddress>,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// generates a new stealth meta address and stores the encrypted private keys
    Keygen {
        /// specify custom path to keyfile (defaults to ./keys.enc)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// generates a new stealth address for a target stealth meta address receiver
    StealthAddress {
        /// 0x prefixed hex encoded 66 byte stealth meta address
        #[arg(short, long, required=true, value_name="HEX")]
        receiver: Option<String>,
    },
    /// computes and reveals the private key of a stealth address (if keyfile unmasks it)
    RevealStealthKey {
        /// path to keyfile containing stealth meta address private keys
        #[arg(short, long, required=true, value_name = "FILE")]
        keyfile: Option<PathBuf>,
        /// 0x prefixed 20 byte hex encoded ethereum stealth address
        #[arg(short, long, required=true, value_name = "HEX")]
        stealthaddr: Option<String>,
        /// 0x prefixed 33 byte hex encoded secp256k1 ephemeral pubkey
        #[arg(short, long, required=true, value_name = "HEX")]
        ephemeralpub: Option<String>,
    },
    /// scan announced stealth addresses for payments to your stealth meta address
    Scan {
        /// path to keyfile containing stealth meta address private keys
        #[arg(short, long, required=true, value_name = "FILE")]
        keyfile: Option<PathBuf>,
        /// path to scanfile (see README here: https://github.com/kassandraoftroy/stealthereum-cli#scan)
        #[arg(short, long, required=true, value_name = "FILE")]
        scanfile: Option<PathBuf>,
    },
    /// show stealth meta address corresponding to a keyfile
    ShowMetaAddress {
        /// path to keyfile containing stealth meta address private keys
        #[arg(short, long, required=true, value_name = "FILE")]
        keyfile: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Keygen { output }) => {
            match output {
                Some(output) => { let _ = keygen(output); }
                None => { 
                    let mut path = PathBuf::new();
                    path.push("stealthereum-keystore.enc");
                    let _ = keygen(&path);
                }
            }
        }
        Some(Commands::StealthAddress { receiver }) => {
            match receiver {
                Some(receiver) => new_stealth_address(receiver),
                None => panic!("missing required --receiver argument (-r)"),
            }
        }
        Some(Commands::RevealStealthKey { keyfile, stealthaddr, ephemeralpub }) => {
            let kf = match keyfile {
                Some(keyfile) => keyfile,
                None => panic!("missing required --keyfile argument (-k)"),
            };
            let sa = match stealthaddr {
                Some(stealthaddr) => stealthaddr,
                None => panic!("missing required --stealthaddr argument (-s)"),
            };
            let ep = match ephemeralpub {
                Some(ephemeralpub) => ephemeralpub,
                None => panic!("missing required --ephemeralpub argument (-e)"),
            };

            reveal_stealth_key(kf, sa, ep);
        }
        Some(Commands::Scan { keyfile, scanfile }) => {
            let kf = match keyfile {
                Some(keyfile) => keyfile,
                None => panic!("missing required --keyfile argument (-k)"),
            };
            let sf = match scanfile {
                Some(scanfile) => scanfile,
                None => panic!("missing required --scanfile argument (-s)"),
            };

            scan_for_payments(kf, sf);
        }
        Some(Commands::ShowMetaAddress { keyfile }) => {
            match keyfile {
                Some(keyfile) => show_meta_address(keyfile),
                None => panic!("missing required --keyfile argument (-k)"),
            }
        }
        None => {}
    }
}

fn get_password(confirm: bool) -> String {
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    
    if confirm {
        print!("Confirm password: ");
        io::stdout().flush().unwrap();
        let confirm_password = read_password().unwrap();
        
        if password != confirm_password {
            panic!("Passwords do not match!");
        }
    }
    
    password
}

fn keygen(path: &PathBuf) -> std::io::Result<()> {
    if path.exists() {
        panic!("keyfile already exists (pass custom output filepath with -o)");
    }

    let (sma, sk, vk) = generate_stealth_meta_address();
    let keys = DecryptedKeys {
        spending_key: sk,
        viewing_key: vk,
    };

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let password = get_password(true);
    
    let key = pbkdf2_hmac_array::<Sha256, 32>(&password.as_bytes(), &salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    let plaintext = bincode::serialize(&keys).unwrap();
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");

    let encrypted_file = EncryptedKeyfile {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };

    let json = serde_json::to_string(&encrypted_file)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    println!("------ STEALTH META ADDRESS ------\n{}", hexlify(&sma));
    Ok(())
}

fn show_meta_address(keyfile: &PathBuf) {
    let (sk, vk) = extract_keys_from_keyfile(keyfile);
    let stealth_meta_address = encode_stealth_meta_address(
        get_pubkey_from_priv(decode_priv(&sk)),
        get_pubkey_from_priv(decode_priv(&vk)),
    );

    println!("------ STEALTH META ADDRESS ------\n{}", hexlify(&stealth_meta_address));
}

fn reveal_stealth_key(keyfile: &PathBuf, stealth_addr: &String, ephem_pub: &String) {
    let (sk, vk) = extract_keys_from_keyfile(keyfile);
    let key = compute_stealth_key(
        unhexlify(stealth_addr).as_slice().try_into().unwrap(),
        unhexlify(ephem_pub).as_slice().try_into().unwrap(),
        &vk,
        &sk
    );
    println!("------ STEALTH ADDRESS PRIVATE KEY ------\n{}", hexlify(&key));
}

fn scan_for_payments(keyfile: &PathBuf, scanfile: &PathBuf) {
    let file_result = read_file(scanfile);
    let string_file = match file_result {
        Ok(val) => val,
        Err(error) => panic!("error reading scanfile: {:?}", error),
    };
    
    let sl_result = parse_scannable_list(&string_file);

    let sl = match sl_result {
        Ok(val) => val,
        Err(error) => panic!("error parsing scanfile: {:?}", error),
    };

    let (sk, vk) = extract_keys_from_keyfile(keyfile);

    let spending_pubkey = encode_pubkey(get_pubkey_from_priv(decode_priv(&sk)));

    for v in sl.announcements.iter() {
        let check = check_stealth_address_fast(
            unhexlify(&v.stealth_address).as_slice().try_into().unwrap(),
            unhexlify(&v.ephemeral_pubkey).as_slice().try_into().unwrap(),
            &vk,
            &spending_pubkey,
            v.view_tag,
        );
        if check {
            println!(
                "------ PAYMENT FOUND ------\nstealth address: {}\nephemeral pubkey: {}",
                v.stealth_address,
                v.ephemeral_pubkey,
            );
        }
    }
    println!("\nscan complete");
}

fn new_stealth_address(receiver: &String) {
    let (stealth_address, ephemeral_pubkey, view_tag) = generate_stealth_address(
        unhexlify(&receiver).as_slice().try_into().unwrap()
    );

    println!(
        "------ STEALTH ADDRESS ------\nschemeId: {}\nstealth address: {}\nephepmeral pubkey: {}\nview tag: {}",
        1,
        hexlify(&stealth_address),
        hexlify(&ephemeral_pubkey),
        view_tag
    );
}

fn extract_keys_from_keyfile(keyfile: &PathBuf) -> ([u8; 32], [u8; 32]) {
    let file_result = read_file(keyfile);
    let string_file = match file_result {
        Ok(val) => val,
        Err(error) => panic!("error reading keyfile: {:?}", error),
    };
    
    let encrypted_file: EncryptedKeyfile = serde_json::from_str(&string_file)
        .expect("Failed to parse encrypted keyfile");

    let salt = hex::decode(&encrypted_file.salt).expect("Invalid salt hex");
    let nonce_bytes = hex::decode(&encrypted_file.nonce).expect("Invalid nonce hex");
    let ciphertext = hex::decode(&encrypted_file.ciphertext).expect("Invalid ciphertext hex");

    let password = get_password(false);
    
    let key = pbkdf2_hmac_array::<Sha256, 32>(&password.as_bytes(), &salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    let keys: DecryptedKeys = bincode::deserialize(&plaintext)
        .expect("Failed to deserialize decrypted keys");

    (keys.spending_key, keys.viewing_key)
}

fn read_file(path: &PathBuf) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn parse_scannable_list(contents: &String) -> serde_json::Result<ScannableList> {
    let sl: ScannableList = serde_json::from_str(contents)?;
    Ok(sl)
}

fn hexlify(a: &[u8]) -> String {
    let mut output = "0x".to_owned();
    output.push_str(&hex::encode(a));
    output
}

fn unhexlify(h: &String) -> Vec<u8> {
    let mut prefix = h.to_owned();
    let s = prefix.split_off(2);
    let result = hex::decode(&s);
    let out = match result {
        Ok(val) => val,
        Err(error) => panic!("error decoding hex: {:?}", error),
    };
    out
}
