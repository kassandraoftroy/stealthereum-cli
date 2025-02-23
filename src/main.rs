mod commands;
mod utils;
mod constants;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
    },
    ImportPublicAccount {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'p', long = "private-key", value_name = "HEX")]
        private_key: Option<String>,
        #[arg(short = 'a', long = "account", value_name = "FILE")]
        account: Option<String>,
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,
    },
    Register {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'm', long = "meta-address", value_name = "HEX")]
        meta_address: Option<String>,
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'a', long = "account", value_name = "FILE")]
        account: Option<String>,
        #[arg(short = 'p', long = "private-key", value_name = "HEX")]
        private_key: Option<String>,
        #[arg(short = 'o', long = "overwrite")]
        overwrite: bool,
    },
    NewStealthAddress {
        #[arg(short = 'r', long = "receiver", value_name = "HEX")]
        receiver: Option<String>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        #[arg(short = 'm', long = "meta-address", value_name = "HEX")]
        meta_address: Option<String>,
    },
    StealthTransfer {
        #[arg(short = 'r', long = "receiver", value_name = "HEX")]
        receiver: Option<String>,
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        #[arg(short = 'a', long = "account", value_name = "FILE")]
        account: Option<String>,
        #[arg(short = 'm', long = "meta-address", value_name = "HEX")]
        meta_address: Option<String>,
        #[arg(short = 't', long = "token", value_name = "HEX")]
        token: Option<String>,
        #[arg(short = 'v', long = "value", value_name = "HEX")]
        value: Option<String>,
        #[arg(short = 'p', long = "private-key", value_name = "HEX")]
        private_key: Option<String>,
    },
    ExportStealthKey {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'a', long = "address", value_name = "HEX")]
        address: Option<String>,
        #[arg(short = 's', long = "stealthaddr", required = true, value_name = "HEX")]
        stealthaddr: Option<String>,
        #[arg(short = 'e', long = "ephemeralpub", required = true, value_name = "HEX")]
        ephemeralpub: Option<String>,
    },
    Sync {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
    },
    ShowBalances {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        #[arg(short = 'i', long = "itemized")]
        itemized: bool,
    },
    ShowMetaAddress {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
    },
    ShowStealthAddresses {
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { keystore, chain_id } => commands::keygen::run(keystore, chain_id)?,
        Commands::ImportPublicAccount {
            keystore,
            chain_id,
            private_key,
            account,
            interactive,
        } => commands::import_public_account::run(keystore, chain_id, private_key, account, interactive)?,
        Commands::Register {
            keystore,
            meta_address,
            rpc,
            chain_id,
            account,
            private_key,
            overwrite,
        } => commands::register::run(keystore, meta_address, rpc, chain_id, account, private_key, overwrite).await?,
        Commands::NewStealthAddress {
            receiver,
            chain_id,
            rpc,
            meta_address,
        } => commands::new_stealth_address::run(receiver, chain_id, rpc, meta_address).await?,
        Commands::StealthTransfer {
            receiver,
            keystore,
            chain_id,
            rpc,
            account,
            meta_address,
            token,
            value,
            private_key,
        } => commands::stealth_transfer::run(receiver, keystore, chain_id, rpc, account, meta_address, token, value, private_key).await?,
        Commands::ExportStealthKey {
            keystore,
            chain_id,
            address,
            stealthaddr,
            ephemeralpub,
        } => commands::export_stealth_key::run(keystore, chain_id, address, stealthaddr, ephemeralpub)?,
        Commands::Sync {
            keystore,
            chain_id,
            rpc,
        } => commands::sync::run(keystore, chain_id, rpc).await?,
        Commands::ShowBalances {
            keystore,
            chain_id,
            rpc,
            itemized,
        } => commands::show_balances::run(keystore, chain_id, rpc, itemized).await?,
        Commands::ShowMetaAddress { keystore, chain_id } => commands::show_meta_address::run(keystore, chain_id)?,
        Commands::ShowStealthAddresses { keystore, chain_id } => commands::show_stealth_addresses::run(keystore, chain_id)?,
    }

    Ok(())
}
