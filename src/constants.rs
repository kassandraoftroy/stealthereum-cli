/// Address of the stealth registry contract
pub const REGISTRY_ADDRESS: &str = "0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538";

/// Address of the announcement contract
pub const ANNOUNCER_ADDRESS: &str = "0x55649E01B5Df198D18D95b5cc5051630cfD45564";

/// Filename for encrypted stealth meta secret key
pub const SECRET_KEY_FILENAME: &str = "stealth_meta_secret_key.enc";

/// Filename for encrypted stealth meta viewing key
pub const VIEWING_KEY_FILENAME: &str = "stealth_meta_viewing_key.enc";

/// Default directory for storing keystore files
pub const DEFAULT_KEYSTORE_DIR: &str = ".stealthereum/keystore";

/// Filename for the encrypted public account key
pub const PUBLIC_ACCT_FILENAME: &str = "public_account_key.enc";

/// Filename for the encrypted logfile
pub const ENCRYPTED_LOGS_FILENAME: &str = "encrypted_stealth_logs.enc";

/// Ethereum chain-specific default RPC endpoints
pub fn get_default_rpc(chain_id: &u64) -> String {
    match chain_id {
        17000 => "https://ethereum-holesky.publicnode.com".to_string(),
        11155111 => "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
        1 => "https://eth.llamarpc.com".to_string(),
        _ => panic!("Unsupported chain ID: {}", chain_id),
    }
}

/// Returns the stealthereum contract address for a given chain
pub fn get_stealthereum_address(chain_id: &u64) -> String {
    match chain_id {
        17000 => "0x2129EEc72F4b42ED0666a1025A019d51E1820d9A".to_string(),
        11155111 => "0x36d1fe257d1283aebBF7747e749B13258CC43c0b".to_string(),
        1 => "0x2f259C4ceB80E1383384BF7704F694Fb6f638dDC".to_string(),
        _ => panic!("Unsupported chain ID: {}", chain_id),
    }
}

pub fn get_default_starting_block(chain_id: &u64) -> u64 {
    match chain_id {
        17000 => 3397378,
        11155111 => 7875486,
        1 => 21903199,
        _ => panic!("Unsupported chain ID: {}", chain_id),
    }
}

pub fn get_default_chain_id() -> u64 {
    return 11155111;
}
