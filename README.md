# stealthereum-cli

This is a bare bones CLI written in rust for ERC-5564 and ERC-6538 compliant stealth address management on evm chains

It's currently the easiest way to interact with the [eth-stealth-addresses](https://github.com/kassandraoftroy/eth-stealth-addresses) rust library which implements the basic cryptographic operations necessary for a stealth addresses scheme over the secp256k1 curve (with view tags) as outlined [here](https://eips.ethereum.org/EIPS/eip-5564)

For now it's extremely rough! More improvements soon

NOT AUDITED - HOMEROLLED CRYPTO - USE AT YOUR OWN RISK

## Installation

```
cargo install stealthereum-cli
```

Make sure you add `$HOME/.cargo/bin` to your PATH

## Usage

Below is the list of basic commands and arguments for the CLI.

NOTE: for now the default chain id is 11155111 (sepolia testnet). For ethereum mainnet you can use `--chain-id 1` flag.

#### keygen

generate a stealth meta address and store the keys in a keystore directory

```bash
stealthereum keygen
```

pass a custom keystore directory and change target chain

```bash
stealthereum keygen --keystore path/to/custom/dir --chain-id 1
```

#### import-public-account

import a public account from a private key or an encrypted account file and attach this account to the (encrypted) stealthereum keystore

```bash
stealthereum import-public-account --interactive
```

here it is with more parameters:

```bash
stealthereum import-public-account --keystore path/to/custom/dir --chain-id 1 --account path/to/existing/account/file
```

see all optional parameters with:

```bash
stealthereum import-public-account --help
```

#### register

register stealth meta address on the registry contract

```bash
stealthereum register
```

use a custom keystore directory and change target chain

```bash
stealthereum register --keystore path/to/custom/dir --chain-id 1 --rpc-url http://localhost:8545
```

don't use the keystore at all and directly pass a hex encoded stealth meta address and a private key

```bash
stealthereum register --meta-address 0xReceiverStealthMetaAddress --private-key 0xYourPrivateKeyHex --chain-id 1 --rpc-url http://localhost:8545
```

see all optional parameters with:

```bash
stealthereum register --help
```

#### sync

sync your stealthereum keystore with the tip of the chain

```bash
stealthereum sync
```

see all optional parameters with:

```bash
stealthereum sync --help
```

#### show-balances

show balances of your stealth addresses

```bash
stealthereum show-balances --itemized
```
