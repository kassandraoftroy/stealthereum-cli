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

use num_traits::Num;
use num_bigint;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::prelude::*;
use serde_json;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Keyfile {
    spending_key: String,
    viewing_key: String,
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
    /// generates a new stealth meta address and stores key material
    Keygen {
        /// specify custom path to keyfile (defaults to ./keys.json)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// show stealth meta address corresponding to a keyfile
    ShowMetaAddr {
        /// path to keyfile containing stealth meta address keys
        #[arg(short, long, required=true, value_name = "FILE")]
        keyfile: Option<PathBuf>,
    },
    /// generates all required data for steath transfers to a target receiver
    StealthTx {
        /// 0x prefixed hex encoded 66 byte stealth meta address
        #[arg(short, long, required=true, value_name="HEX")]
        receiver: Option<String>,
        /// amount of network token to forward (in wei, decimal)
        #[arg(short, long, value_name="UINT")]
        msgvalue: Option<String>,
        /// ERC20/ERC721 0x prefixed hex encoded 20 byte token addresses
        #[arg(short, long, num_args=0.., value_name="HEX")]
        tokens: Vec<String>,
        /// amounts of ERC20 tokens or Ids of ERC721 tokens to transfer (in wei, decimal)
        #[arg(short, long, num_args=0.., value_name="UINT")]
        amounts: Vec<String>,
    },
    /// computes and reveals the private key of a stealth address
    RevealStealthKey {
        /// path to keyfile containing stealth meta address keys
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
        /// path to keyfile containing stealth meta address keys
        #[arg(short, long, required=true, value_name = "FILE")]
        keyfile: Option<PathBuf>,
        /// path to scanfile containing a ScannableList JSON e.g. {announcements: [{stealth_address:, ephemeral_pubkey:, view_tag:}]} (see README for more info)
        #[arg(short, long, required=true, value_name = "FILE")]
        scanfile: Option<PathBuf>,
    },
    /// generates a new stealth address for a target receiver
    StealthAddr {
        /// 0x prefixed hex encoded 66 byte stealth meta address
        #[arg(short, long, required=true, value_name="HEX")]
        receiver: Option<String>,
    },
    /// encodes metadata from view tag and desired transfers
    FmtMetadata {
        /// receiver stealth address view tag, uint 0-255
        #[arg(short, long, required=true, value_name="UINT")]
        viewtag: Option<u8>,
        /// amount of network token to forward (in wei, decimal)
        #[arg(short, long, value_name="UINT")]
        msgvalue: Option<String>,
        /// ERC20/ERC721 0x prefixed hex encoded 20 byte token addresses
        #[arg(short, long, num_args=0.., value_name="HEX")]
        tokens: Vec<String>,
        /// amounts of ERC20 tokens or Ids of ERC721 tokens to transfer (in wei, decimal)
        #[arg(short, long, num_args=0.., value_name="UINT")]
        amounts: Vec<String>,
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
                    path.push("keys.json");
                    let _ = keygen(&path);
                }
            }
        }
        Some(Commands::ShowMetaAddr { keyfile }) => {
            match keyfile {
                Some(keyfile) => show_meta_address(keyfile),
                None => panic!("missing required --keyfile argument (-k)"),
            }
        }
        Some(Commands::StealthTx { receiver, msgvalue, tokens, amounts }) => {
            let r = match receiver {
                Some(receiver) => receiver,
                None => panic!("missing required --receiver argument (-r)"),
            };
            let zero = String::from("0");
            let mv = match msgvalue {
                Some(msgvalue) => msgvalue,
                None => &zero,
            };
            new_stealth_tx(r, mv, tokens, amounts);
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
        Some(Commands::StealthAddr { receiver }) => {
            match receiver {
                Some(receiver) => new_stealth_address(receiver),
                None => panic!("missing required --receiver argument (-r)"),
            }
        }
        Some(Commands::FmtMetadata {viewtag, msgvalue, tokens, amounts}) => {
            let vt = match viewtag {
                Some(viewtag) => *viewtag,
                None => panic!("missing required --viewtag argument (-v)"),
            };
            let zero = String::from("0");
            let mv = match msgvalue {
                Some(msgvalue) => msgvalue,
                None => &zero,
            };

            show_metadata(vt, mv, tokens, amounts);
        }
        None => {}
    }
}

fn keygen(path: &PathBuf) -> std::io::Result<()> {
    if path.exists() {
        panic!("keyfile already exists (pass custom output filepath with -o)");
    }

    let (sma, sk, vk) = generate_stealth_meta_address();
    let kf = Keyfile {
        spending_key: hexlify(&sk),
        viewing_key: hexlify(&vk),
    };


    let json = serde_json::to_string(&kf)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    println!("------ STEALTH META ADDRESS ------\n{}", hexlify(&sma));
    Ok(())
}

fn show_meta_address(keyfile: &PathBuf) {
    let (sk, vk) = extract_keys_from_keyfile(keyfile);
    let stealth_meta_address= encode_stealth_meta_address(
        get_pubkey_from_priv(decode_priv(&sk)),
        get_pubkey_from_priv(decode_priv(&vk)),
    );

    println!("------ STEALTH META ADDRESS ------\n{}", hexlify(&stealth_meta_address));
}

fn new_stealth_tx(receiver: &String,  msgvalue: &String, tokens: &Vec<String>, amounts: &Vec<String>) {
    let (stealth_address, ephemeral_pubkey, view_tag) = generate_stealth_address(
        unhexlify(&receiver).as_slice().try_into().unwrap()
    );

    let metadata = encode_metadata(view_tag, msgvalue, tokens, amounts);
    println!(
        "------ STEALTH TX ------\nschemeId: {}\nstealth address: {}\nephepmeral pubkey: {}\nmetadata: {}",
        0,
        hexlify(&stealth_address),
        hexlify(&ephemeral_pubkey),
        metadata
    );
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
        0,
        hexlify(&stealth_address),
        hexlify(&ephemeral_pubkey),
        view_tag
    );
}

fn show_metadata(view_tag: u8, msgvalue: &String, tokens: &Vec<String>, amounts: &Vec<String>) {
    let s = encode_metadata(view_tag, msgvalue, tokens, amounts);

    println!("------ TX METADATA ------\n{}", s);
}

fn extract_keys_from_keyfile(keyfile: &PathBuf) -> ([u8; 32], [u8; 32]) {
    let file_result = read_file(keyfile);
    let string_file = match file_result {
        Ok(val) => val,
        Err(error) => panic!("error reading keyfile: {:?}", error),
    };
    
    let kf_result = parse_keyfile(&string_file);

    let kf = match kf_result {
        Ok(val) => val,
        Err(error) => panic!("error parsing keyfile: {:?}", error),
    };

    let sk = unhexlify(&kf.spending_key).as_slice().try_into().unwrap();
    let vk = unhexlify(&kf.viewing_key).as_slice().try_into().unwrap();

    (sk, vk)
}

fn encode_metadata(view_tag: u8, msgvalue: &String, tokens: &Vec<String>, amounts: &Vec<String>) -> String {
    let len = tokens.len();
    if len != amounts.len() {
        panic!("length mismatch for --tokens and --amounts");
    }
    let mut v = vec![view_tag];
    if msgvalue != &String::from("0") {
        let mut mv = parse_uint256_from_string(msgvalue);
        let mut es = vec![0xee; 24];
        v.append(&mut es);
        v.append(&mut mv);
    }
    for i in 0..len {
        let mut prefix = vec![0x23, 0xb8, 0x72, 0xdd];
        let mut token = unhexlify(&tokens[i]);
        let mut value = parse_uint256_from_string(&amounts[i]);
        v.append(&mut prefix);
        v.append(&mut token);
        v.append(&mut value);
    }

    return hexlify(v.as_slice());
}

fn read_file(path: &PathBuf) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn parse_keyfile(contents: &String) -> serde_json::Result<Keyfile> {
    let kf: Keyfile = serde_json::from_str(contents)?;
    Ok(kf)
}

fn parse_scannable_list(contents: &String) -> serde_json::Result<ScannableList> {
    let sl: ScannableList = serde_json::from_str(contents)?;
    Ok(sl)
}

fn parse_uint256_from_string(s: &String) -> Vec<u8> {
    let result = num_bigint::BigUint::from_str_radix(s, 10);
    let mut v = match result {
        Ok(result) => result.to_bytes_be(),
        Err(error) => panic!("error parsing msgvalue: {:?}", error),
    };
    while v.len() < 32 {
        v.insert(0, 0x00);
    }

    v
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
