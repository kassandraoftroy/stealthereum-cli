mod commands;
mod constants;
mod utils;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// generates a new stealth meta address and stores the encrypted private keys
    Keygen {
        /// path to custom keystore directory
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
    },
    /// import a public account from a private key or encrypted account file
    ImportPublicAccount {
        /// path to custom keystore directory
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// 0x prefixed hex encoded private key of sender
        #[arg(short = 'p', long = "private-key", value_name = "HEX")]
        private_key: Option<String>,
        /// path to encrypted account file of sender
        #[arg(short = 'a', long = "account", value_name = "FILE")]
        account: Option<String>,
        /// use interactive mode for input
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,
    },
    /// register stealth meta address on the registry contract
    Register {
        /// path to custom keystore directory
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// 0x prefixed hex encoded 66 byte stealth meta address
        #[arg(short = 'm', long = "meta-address", value_name = "HEX")]
        meta_address: Option<String>,
        /// RPC URL to connect to
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// path to encrypted account file of registrant
        #[arg(short = 'a', long = "account", value_name = "FILE")]
        account: Option<String>,
        /// 0x prefixed hex encoded private key of registrant
        #[arg(short = 'p', long = "private-key", value_name = "HEX")]
        private_key: Option<String>,
        /// overwrite existing registration if one exists
        #[arg(short = 'o', long = "overwrite")]
        overwrite: bool,
    },
    /// generates a new stealth address for a target receiver
    NewStealthAddress {
        /// 0x prefixed hex encoded ethereum address (to lookup on registry contract)
        #[arg(short = 'r', long = "receiver", value_name = "HEX")]
        receiver: Option<String>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// RPC URL to connect to
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        /// 0x prefixed hex encoded 66 byte stealth meta address
        #[arg(short = 'm', long = "meta-address", value_name = "HEX")]
        meta_address: Option<String>,
    },
    /// sends a stealth transfer to a receiver
    StealthTransfer {
        /// 0x prefixed hex encoded ethereum address (to check on registry contract)
        #[arg(short = 'r', long = "receiver", value_name = "HEX")]
        receiver: Option<String>,
        /// path to custom keystore directory
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// RPC URL to connect to
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        /// path to encrypted account file of sender
        #[arg(short = 'a', long = "account", value_name = "FILE")]
        account: Option<String>,
        /// 0x prefixed hex encoded 66 byte stealth meta address
        #[arg(short = 'm', long = "meta-address", value_name = "HEX")]
        meta_address: Option<String>,
        /// token address (for ERC20 or ERC721 transfers)
        #[arg(short = 't', long = "token", value_name = "HEX")]
        token: Option<String>,
        /// amount to send in wei / tokenId to send
        #[arg(short = 'v', long = "value", value_name = "HEX")]
        value: Option<String>,
        /// 0x prefixed hex encoded private key of sender
        #[arg(short = 'p', long = "private-key", value_name = "HEX")]
        private_key: Option<String>,
        /// skip approval step (already approved contract)
        #[arg(short = 's', long = "skip-approval")]
        skip_approval: bool,
    },
    /// export the private key of a stealth address
    ExportStealthKey {
        /// 0x prefixed hex encoded stealth address
        #[arg(short = 'a', long = "address", required = true, value_name = "HEX")]
        address: Option<String>,
        /// path to custom keystore directory
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// 0x prefixed 33 byte hex encoded ephemeral public key
        #[arg(short = 'e', long = "ephemeral-pubkey", value_name = "HEX")]
        ephemeral_pubkey: Option<String>,
    },
    /// sync stealth keystore with the chain
    Sync {
        /// path to keystore directory containing stealth keys
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// RPC URL to connect to
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
    },
    /// show balances of stealth addresses
    ShowBalances {
        /// path to keystore directory containing stealth keys
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
        /// RPC URL to connect to
        #[arg(short = 'u', long = "rpc-url", value_name = "URL")]
        rpc: Option<String>,
        /// show itemized balance breakdown
        #[arg(short = 'i', long = "itemized")]
        itemized: bool,
    },
    /// show stealth meta address from keystore
    ShowMetaAddress {
        /// path to keystore directory containing stealth keys
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
    },
    /// show all stealth addresses in keystore
    ShowStealthAddresses {
        /// path to keystore directory containing stealth keys
        #[arg(short = 'k', long = "keystore", value_name = "FILE")]
        keystore: Option<std::path::PathBuf>,
        /// chain id (1 = mainnet, 17000 = holesky)
        #[arg(short = 'c', long = "chain-id", value_name = "INT")]
        chain_id: Option<u64>,
    },
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
        } => commands::import_public_account::run(
            keystore,
            chain_id,
            private_key,
            account,
            interactive,
        )?,
        Commands::Register {
            keystore,
            meta_address,
            rpc,
            chain_id,
            account,
            private_key,
            overwrite,
        } => {
            commands::register::run(
                keystore,
                meta_address,
                rpc,
                chain_id,
                account,
                private_key,
                overwrite,
            )
            .await?
        }
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
            skip_approval,
        } => {
            commands::stealth_transfer::run(
                receiver,
                keystore,
                chain_id,
                rpc,
                account,
                meta_address,
                token,
                value,
                private_key,
                skip_approval,
            )
            .await?
        }
        Commands::ExportStealthKey {
            keystore,
            chain_id,
            address,
            ephemeral_pubkey,
        } => commands::export_stealth_key::run(
            keystore,
            chain_id,
            address,
            ephemeral_pubkey,
        )?,
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
        Commands::ShowMetaAddress { keystore, chain_id } => {
            commands::show_meta_address::run(keystore, chain_id)?
        }
        Commands::ShowStealthAddresses { keystore, chain_id } => {
            commands::show_stealth_addresses::run(keystore, chain_id)?
        }
    }

    Ok(())
}
