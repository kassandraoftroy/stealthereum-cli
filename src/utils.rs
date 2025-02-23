use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    hex,
    json_abi::JsonAbi,
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use dirs;
use eth_stealth_addresses::{
    check_stealth_address_fast, compute_stealth_key, decode_priv, encode_pubkey,
    encode_stealth_meta_address, generate_stealth_address, get_pubkey_from_priv,
};
use pbkdf2::pbkdf2_hmac_array;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use crate::constants::{
    ENCRYPTED_LOGS_FILENAME, PUBLIC_ACCT_FILENAME, SECRET_KEY_FILENAME, VIEWING_KEY_FILENAME,
};

sol! {
    #[sol(rpc)]
    interface IAnnouncer {
        event Announcement(
            uint256 indexed schemeId,
            address indexed stealthAddress,
            address indexed caller,
            bytes ephemeral_pubkeyKey,
            bytes metadata
        );
    }
}

const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedLogfile {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Logfile {
    pub logs: Vec<Payment>,
    pub latest_block: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransferInfo {
    pub token: Address,
    pub value: U256,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Payment {
    pub stealth_address: Address,
    pub ephemeral_pubkey: Bytes,
    pub view_tag: u8,
    pub parsed_transfers: Vec<TransferInfo>,
    pub block_number: u64,
    pub raw_metadata: Bytes,
}

pub fn get_stealth_meta_address(sk: [u8; 32], vk: [u8; 32]) -> [u8; 66] {
    encode_stealth_meta_address(
        get_pubkey_from_priv(decode_priv(&sk)),
        get_pubkey_from_priv(decode_priv(&vk)),
    )
}

pub fn get_stealth_key(
    stealth_addr: Address,
    ephem_pub: Bytes,
    sk: [u8; 32],
    vk: [u8; 32],
) -> [u8; 32] {
    let key = compute_stealth_key(
        stealth_addr.as_slice().try_into().unwrap(),
        ephem_pub.as_ref().try_into().unwrap(),
        &vk,
        &sk,
    );
    key
}

pub fn new_stealth_address(receiver_meta_address: &[u8; 66]) -> ([u8; 20], [u8; 33], u8) {
    let (stealth_address, ephemeral_pubkey, view_tag) =
        generate_stealth_address(receiver_meta_address);

    (stealth_address, ephemeral_pubkey, view_tag)
}

pub async fn new_stealth_address_from_registry(
    address: &String,
    rpc: &String,
    contract: &String,
) -> ([u8; 20], [u8; 33], u8) {
    let stealth_meta_address = get_stealth_meta_address_from_registry(address, rpc, contract).await;
    if stealth_meta_address.is_empty() {
        panic!(
            "stealth meta address not found in registry for address: {}",
            address
        );
    }

    new_stealth_address(&stealth_meta_address)
}

pub async fn scan_for_payments(
    rpc: &String,
    contract: &String,
    start_block: &u64,
    sk: [u8; 32],
    vk: [u8; 32],
) -> (Vec<Payment>, u64) {
    let spending_pubkey = encode_pubkey(get_pubkey_from_priv(decode_priv(&sk)));

    let provider = ProviderBuilder::new().on_http(rpc.parse().unwrap());
    let contract_address = Address::from_str(contract).unwrap();

    let current_block = provider.get_block_number().await.unwrap();
    let mut current_end_block = current_block;
    let mut payments = Vec::new();
    while *start_block < current_end_block {
        let current_start_block = if current_end_block >= 49999 {
            if current_end_block - 49999 < *start_block {
                *start_block
            } else {
                current_end_block - 49999
            }
        } else {
            *start_block
        };

        let filter = Filter::new()
            .address(vec![contract_address])
            .event_signature(IAnnouncer::Announcement::SIGNATURE_HASH)
            .from_block(current_start_block)
            .to_block(current_end_block);

        let logs = provider.get_logs(&filter).await.unwrap();
        for log in logs {
            if let Ok(decoded) = log.log_decode::<IAnnouncer::Announcement>() {
                let check = check_stealth_address_fast(
                    unhexlify(&decoded.inner.stealthAddress.to_string())
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    unhexlify(&hex::encode(&decoded.inner.ephemeral_pubkeyKey))
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    &vk,
                    &spending_pubkey,
                    decoded.inner.metadata[0] as u8,
                );
                if check {
                    let parsed = decode_metadata(decoded.inner.metadata.to_vec());
                    payments.push(Payment {
                        stealth_address: decoded.inner.stealthAddress,
                        ephemeral_pubkey: decoded.inner.ephemeral_pubkeyKey.clone(),
                        view_tag: decoded.inner.metadata[0] as u8,
                        parsed_transfers: parsed,
                        block_number: log.block_number.unwrap(),
                        raw_metadata: decoded.inner.metadata.clone(),
                    });
                }
            }
        }

        current_end_block = current_start_block;
    }

    (payments, current_block)
}

pub fn decode_metadata(metadata: Vec<u8>) -> Vec<TransferInfo> {
    let len = (metadata.len() - 1) / 56;
    let mut res = Vec::new();
    for i in 0..len {
        let fsig_bytes = metadata[1 + 56 * i..5 + 56 * i].to_vec();
        let fsig = "0x".to_owned() + &hex::encode(fsig_bytes);
        if fsig.to_lowercase() == "0xeeeeeeee" || fsig.to_lowercase() == "0x23b872dd" {
            let token_bytes = metadata[5 + 56 * i..25 + 56 * i].to_vec();
            let value_bytes = metadata[25 + 56 * i..57 + 56 * i].to_vec();
            let token = "0x".to_owned() + &hex::encode(token_bytes);
            let value = U256::from_str_radix(&hex::encode(value_bytes), 16).unwrap();
            res.push(TransferInfo {
                token: Address::from_str(&token).unwrap(),
                value: value,
            });
        } else {
            break;
        }
    }

    res
}

pub async fn get_stealth_meta_address_from_registry(
    address: &String,
    rpc: &String,
    contract: &String,
) -> [u8; 66] {
    let provider = ProviderBuilder::new().on_http(rpc.parse().unwrap());
    let abi = JsonAbi::parse([
        "function stealthMetaAddressOf(address, uint256) external view returns (bytes memory)",
    ])
    .expect("Failed to parse ABI");

    let registry = ContractInstance::new(
        Address::from_str(contract).unwrap(),
        provider.clone(),
        Interface::new(abi),
    );

    let sma_val = registry
        .function(
            "stealthMetaAddressOf",
            &[
                DynSolValue::Address(Address::from_str(address).unwrap()),
                DynSolValue::Uint(U256::from(1u64), 256),
            ],
        )
        .expect("Failed to create method call")
        .call()
        .await
        .expect("Failed to call stealthMetaAddressOf");
    let stealth_meta_address: [u8; 66] = sma_val[0]
        .as_bytes()
        .expect("Expected bytes output")
        .try_into()
        .unwrap_or([0; 66]);

    stealth_meta_address
}

pub fn store_encrypted_logfile(password: &String, keystore: &PathBuf, logfile: &Logfile) {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = pbkdf2_hmac_array::<Sha256, 32>(&password.as_bytes(), &salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let plaintext = serde_json::to_vec(&logfile).expect("Failed to serialize logfile");
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");

    let encrypted_file = EncryptedLogfile {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };
    let json = serde_json::to_string(&encrypted_file).unwrap();

    fs::create_dir_all(keystore.clone()).expect("failed to create keystore directory");
    let path = keystore.join(ENCRYPTED_LOGS_FILENAME);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

pub fn load_encrypted_logfile(password: &String, keystore: &PathBuf) -> Logfile {
    let path = keystore.join(ENCRYPTED_LOGS_FILENAME);
    let file_result = read_file(&path);
    let string_file = match file_result {
        Ok(val) => val,
        Err(error) => panic!("error reading keyfile: {:?}", error),
    };
    let encrypted_file: EncryptedLogfile =
        serde_json::from_str(&string_file).expect("Failed to parse encrypted keyfile");

    let salt = hex::decode(&encrypted_file.salt).expect("Invalid salt hex");
    let nonce_bytes = hex::decode(&encrypted_file.nonce).expect("Invalid nonce hex");
    let ciphertext = hex::decode(&encrypted_file.ciphertext).expect("Invalid ciphertext hex");

    let key = pbkdf2_hmac_array::<Sha256, 32>(&password.as_bytes(), &salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    let logfile: Logfile =
        serde_json::from_slice(&plaintext).expect("Failed to deserialize logfile");
    logfile
}

pub fn create_stealth_meta_keys(keystore: &PathBuf, password: &String, sk: [u8; 32], vk: [u8; 32]) {
    fs::create_dir_all(keystore.clone()).expect("failed to create keystore directory");

    PrivateKeySigner::encrypt_keystore(
        keystore.clone(),
        &mut OsRng,
        &sk,
        password.clone(),
        Some(SECRET_KEY_FILENAME),
    )
    .unwrap();
    PrivateKeySigner::encrypt_keystore(
        keystore.clone(),
        &mut OsRng,
        &vk,
        password,
        Some(VIEWING_KEY_FILENAME),
    )
    .unwrap();
}

pub fn load_stealth_keys(keystore: &PathBuf, password: &String) -> ([u8; 32], [u8; 32]) {
    let sk = PrivateKeySigner::decrypt_keystore(&keystore.join(SECRET_KEY_FILENAME), password)
        .expect("failed to unlock keystore");
    let vk = PrivateKeySigner::decrypt_keystore(&keystore.join(VIEWING_KEY_FILENAME), password)
        .expect("failed to unlock keystore");
    (
        sk.to_bytes().as_slice().try_into().unwrap(),
        vk.to_bytes().as_slice().try_into().unwrap(),
    )
}

pub fn copy_public_account(
    account: &String,
    keystore: &PathBuf,
    password: &String,
    old_pwd: &String,
) {
    // TODO: get private key from account file
    let sk = PrivateKeySigner::decrypt_keystore(account, old_pwd)
        .expect("failed to unlock original keystore");
    create_public_account(&sk.to_bytes().as_slice(), keystore, password);
}

pub fn create_public_account(privkey: &[u8], keystore: &PathBuf, password: &String) {
    fs::create_dir_all(keystore).expect("failed to create keystore directory");
    PrivateKeySigner::encrypt_keystore(
        keystore,
        &mut OsRng,
        &privkey,
        password,
        Some(PUBLIC_ACCT_FILENAME),
    )
    .unwrap();
}

pub fn load_wallet_from_priv_or_account(
    private_key: &Option<String>,
    account: &Option<String>,
    password: &String,
    keystore: &PathBuf,
) -> (EthereumWallet, Address) {
    if private_key.is_some() && account.is_some() {
        panic!("Only one of private key or account path can be provided");
    }
    let account = match account {
        Some(account) => account,
        None => {
            let mut default_path = dirs::home_dir().expect("Could not find home directory");
            default_path.push(keystore);
            default_path.push(PUBLIC_ACCT_FILENAME);
            &default_path.to_string_lossy().to_string()
        }
    };
    // Set up the provider and wallet
    let eth_signer = if let Some(private_key) = private_key {
        private_key.parse().expect("Failed to parse private key")
    } else {
        if !std::fs::exists(&account).unwrap() {
            panic!("Account file does not exist");
        };
        PrivateKeySigner::decrypt_keystore(account, password).expect("failed to unlock keystore")
    };

    (
        EthereumWallet::new(eth_signer.clone()),
        eth_signer.address(),
    )
}

fn read_file(path: &PathBuf) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}
pub fn hexlify(a: &[u8]) -> String {
    let mut output = "0x".to_owned();
    output.push_str(&hex::encode(a));
    output
}

pub fn unhexlify(h: &String) -> Vec<u8> {
    let mut prefix = h.to_owned();
    let s = match prefix.get(..2) {
        Some("0x") => prefix.split_off(2),
        _ => prefix,
    };
    let result = hex::decode(&s);
    let out = match result {
        Ok(val) => val,
        Err(error) => panic!("error decoding hex: {:?}", error),
    };
    out
}

pub fn format_u256_as_decimal(value: U256, decimals: u8) -> String {
    let ten = U256::from(10);
    let divisor = ten.pow(U256::from(decimals));

    let integer_part = value / divisor;
    let fractional_part = value % divisor;

    if decimals == 0 {
        return integer_part.to_string(); // No decimal places needed
    }

    // Convert fractional part to a zero-padded string
    let fractional_str = format!("{:0>width$}", fractional_part, width = decimals as usize);

    // Trim trailing zeroes for better readability
    let fractional_str_trimmed = fractional_str.trim_end_matches('0');

    if fractional_str_trimmed.is_empty() {
        integer_part.to_string() // No need for ".0" if fractional part is zero
    } else {
        format!("{}.{}", integer_part, fractional_str_trimmed)
    }
}
