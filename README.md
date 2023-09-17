# stealthereum-cli

This is a bare bones CLI written in rust for ERC-5564 compliant stealth address management on evm chains

It's currently the easiest way to interact with the [eth-stealth-addresses](https://github.com/kassandraoftroy/eth-stealth-addresses) rust library which implements the basic cryptographic operations necessary for a stealth addresses scheme over the secp256k1 curve (with view tags) as outlined [here](https://eips.ethereum.org/assets/eip-5564/scheme_ids)

For now it's extremely rough and low level! More improvements soon

## Installation

```
cargo install stealthereum-cli
```

Make sure you add `$HOME/.cargo/bin` to your PATH

## Usage

generate a stealth meta address and store the keys

```bash
stealthereum keygen -o path/to/keyfile.json
```

recompute your stealth meta address from keyfile

```bash
stealthereum show-meta-addr -k path/to/keyfile.json
```

with the stealth meta address of a receiver generate all the components of a stealth transaction as defined in ERC-5564

```bash
stealthereum stealth-tx -r 0xReceiverStealthMetaAddres --msgvalue 1000000000000000000 --tokens 0x12970E6868f88f6557B76120662c1B3E50A646bf 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --amounts 1 100000000
```

the above will output:
1. a stealth address
2. an ephemeral public key and 
3. metadata for stealthily transferring 1 ETH, a Milady (tokenId=1), and 100 USDC to the owner of the stealth meta address.

compute private key for a stealth address you control

```bash
stealthereum reveal-stealth-key -k path/to/keyfile.json -s 0xSomeStealthAddress -e 0xSomeEpmheralPubkey
```

note that no scanning functionality yet in place, so you'd have to manually scan by passing all announced `[stealth address, ephemeral pubkey]` pairs into this command and waiting until one outputs a private key isntead of panicking, which it does when you are not the intended recipient)

