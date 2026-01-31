use crate::vault::VaultClient;
use alloy::primitives::B256;
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use coins_bip32::path::DerivationPath;
use coins_bip32::prelude::{SigningKey, XPriv};
use coins_bip39::{English, Mnemonic};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use zeroize::Zeroize;

use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Address(String);

impl Address {
    pub fn new(addr: String) -> Self {
        Self(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Address {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Network {
    Ethereum,
    Tron,
    Solana,
    Ton,
}

impl Network {
    pub fn derivation_path(&self, index: u32) -> String {
        match self {
            Network::Ethereum => format!("m/44'/60'/0'/0/{}", index),
            Network::Tron => format!("m/44'/195'/0'/0/{}", index),
            Network::Solana => format!("m/44'/501'/0'/0/{}", index),
            Network::Ton => format!("m/44'/607'/0'/0/{}", index),
        }
    }
}

pub struct WalletManager {
    vault: VaultClient,
}

impl WalletManager {
    pub fn new(vault: VaultClient) -> Self {
        Self { vault }
    }

    pub fn generate_mnemonic(length: usize) -> anyhow::Result<String> {
        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, length)?;
        Ok(mnemonic.to_phrase())
    }

    pub async fn get_address(
        &self,
        encrypted_seed: &str,
        network: Network,
        index: u32,
    ) -> anyhow::Result<Address> {
        let mut seed_bytes = self.vault.decrypt(encrypted_seed).await?;
        let mnemonic =
            Mnemonic::<English>::new_from_phrase(&String::from_utf8(seed_bytes.clone())?)?;
        seed_bytes.zeroize();

        Self::derive_address_from_mnemonic(&mnemonic, network, index)
    }

    // Extracted for testing without Vault
    pub fn derive_address_from_mnemonic(
        mnemonic: &Mnemonic<English>,
        network: Network,
        index: u32,
    ) -> anyhow::Result<Address> {
        let path_str = network.derivation_path(index);
        let path = DerivationPath::from_str(&path_str)?;

        let seed = mnemonic.to_seed(None)?;
        let xpriv = XPriv::root_from_seed(&seed, None)?;
        let derived_xpriv = xpriv.derive_path(&path)?;

        match network {
            Network::Ethereum => {
                let signing_key: &SigningKey = derived_xpriv.as_ref();
                let signer = PrivateKeySigner::from_bytes(&B256::from_slice(
                    signing_key.to_bytes().as_ref(),
                ))?;
                let address = signer.address();
                Ok(Address::new(address.to_string()))
            }
            Network::Tron => {
                let signing_key: &SigningKey = derived_xpriv.as_ref();
                let signer = PrivateKeySigner::from_bytes(&B256::from_slice(
                    signing_key.to_bytes().as_ref(),
                ))?;
                let eth_address = signer.address();

                // Tron Address: 0x41 + Last 20 bytes of Keccak256(PubKey) (which is eth_address)
                let mut raw = Vec::with_capacity(21);
                raw.push(0x41);
                raw.extend_from_slice(eth_address.as_slice());

                // Double SHA256 for checksum
                use sha2::{Digest, Sha256};
                let hash1 = Sha256::digest(&raw);
                let hash2 = Sha256::digest(&hash1);

                let mut address_bytes = raw;
                address_bytes.extend_from_slice(&hash2[0..4]);

                Ok(Address::new(bs58::encode(address_bytes).into_string()))
            }
            Network::Solana => {
                let signing_key_bip32: &SigningKey = derived_xpriv.as_ref();
                let seed_32: [u8; 32] =
                    <[u8; 32]>::try_from(signing_key_bip32.to_bytes().as_ref())?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_32);
                let public_key = signing_key.verifying_key();
                Ok(Address::new(
                    bs58::encode(public_key.as_bytes()).into_string(),
                ))
            }
            Network::Ton => {
                let signing_key_bip32: &SigningKey = derived_xpriv.as_ref();
                let seed_32: [u8; 32] =
                    <[u8; 32]>::try_from(signing_key_bip32.to_bytes().as_ref())?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_32);
                let public_key = signing_key.verifying_key();

                // TON Wallet v4r2 (standard) construction usually requires state init.
                use sha2::{Digest, Sha256};
                let account_id = Sha256::digest(public_key.as_bytes()); // Approximation!

                let mut data = Vec::with_capacity(36);
                data.push(0x11); // Tag: bounceable
                data.push(0x00); // Workchain: 0
                data.extend_from_slice(&account_id);

                // CRC16-CCITT (XMODEM)
                let crc = crc16::State::<crc16::XMODEM>::calculate(&data);
                data.extend_from_slice(&crc.to_be_bytes());

                use base64::Engine;
                Ok(Address::new(
                    base64::engine::general_purpose::URL_SAFE.encode(data),
                ))
            }
        }
    }

    pub async fn sign_tx(
        &self,
        encrypted_seed: &str,
        network: Network,
        index: u32,
        unsigned_tx: &str,
    ) -> anyhow::Result<String> {
        let mut seed_bytes = self.vault.decrypt(encrypted_seed).await?;
        let mnemonic =
            Mnemonic::<English>::new_from_phrase(&String::from_utf8(seed_bytes.clone())?)?;
        seed_bytes.zeroize();

        let path_str = network.derivation_path(index);
        let path = DerivationPath::from_str(&path_str)?;
        let seed = mnemonic.to_seed(None)?;
        let xpriv = XPriv::root_from_seed(&seed, None)?;
        let derived_xpriv = xpriv.derive_path(&path)?;

        // Validate transaction format before signing
        let tx_bytes = validate_transaction_format(network, unsigned_tx)?;

        match network {
            Network::Ethereum | Network::Tron => {
                let signing_key: &SigningKey = derived_xpriv.as_ref();
                let signer = PrivateKeySigner::from_bytes(&B256::from_slice(
                    signing_key.to_bytes().as_ref(),
                ))?;
                let signature = signer.sign_message(&tx_bytes).await?;
                Ok(format!("0x{}", hex::encode(signature.as_bytes())))
            }
            Network::Solana | Network::Ton => {
                let signing_key_bip32: &SigningKey = derived_xpriv.as_ref();
                let seed_32: [u8; 32] =
                    <[u8; 32]>::try_from(signing_key_bip32.to_bytes().as_ref())?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_32);
                let signature = ed25519_dalek::Signer::sign(&signing_key, &tx_bytes);
                Ok(hex::encode(signature.to_bytes()))
            }
        }
    }
}

/// Validates transaction format for the given network
/// Returns decoded bytes or an error if format is invalid
fn validate_transaction_format(network: Network, unsigned_tx: &str) -> anyhow::Result<Vec<u8>> {
    // Remove optional 0x prefix
    let hex_str = unsigned_tx.trim_start_matches("0x");
    
    // Basic hex validation
    if hex_str.is_empty() {
        anyhow::bail!("Transaction data is empty");
    }
    if hex_str.len() % 2 != 0 {
        anyhow::bail!("Invalid hex string: odd length");
    }
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid hex string: contains non-hex characters");
    }
    
    let bytes = hex::decode(hex_str)?;
    
    // Network-specific validation
    match network {
        Network::Ethereum => {
            // Ethereum transaction should be at least:
            // - Legacy: nonce (1+) + gasPrice (1+) + gasLimit (1+) + to (20) + value (1+) + data (0+) + v (1+) + r (32) + s (32)
            // - EIP-1559: type (0x02) + rlp encoded fields
            if bytes.is_empty() {
                anyhow::bail!("Ethereum transaction is empty");
            }
            // Check for valid transaction type prefix (EIP-2718)
            // Typed transactions start with 0x01, 0x02, etc. (values 0x00-0x7f)
            // Legacy transactions start with RLP list prefix (0xc0 and above)
            let first_byte = bytes[0];
            if first_byte < 0x7f && first_byte != 0 {
                // Typed transaction (EIP-2718)
                match first_byte {
                    0x01 => { /* EIP-2930 */ }
                    0x02 => { /* EIP-1559 */ }
                    _ => anyhow::bail!("Unknown Ethereum transaction type: 0x{:02x}", first_byte),
                }
            } else {
                // Legacy transaction - must be valid RLP
                // RLP list prefix for small lists (0xc0-0xf7) or large lists (0xf8+)
                // Minimum legacy tx: ~45 bytes for a simple transfer
                if bytes.len() < 45 {
                    anyhow::bail!("Legacy Ethereum transaction too short");
                }
            }
        }
        Network::Tron => {
            // Tron uses protobuf-encoded transactions
            // At minimum should have some protobuf structure
            if bytes.len() < 10 {
                anyhow::bail!("Tron transaction too short for protobuf");
            }
        }
        Network::Solana => {
            // Solana transaction is a serialized Message or VersionedTransaction
            // Minimum size is around 128 bytes for a simple transfer
            if bytes.len() < 64 {
                anyhow::bail!("Solana transaction too short (minimum ~64 bytes)");
            }
        }
        Network::Ton => {
            // TON transactions are typically base64-encoded cells
            // But since we accept hex, we just check reasonable bounds
            if bytes.len() < 10 {
                anyhow::bail!("TON transaction too short");
            }
        }
    }
    
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = WalletManager::generate_mnemonic(12).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_derivation_paths() {
        assert_eq!(Network::Ethereum.derivation_path(0), "m/44'/60'/0'/0/0");
        assert_eq!(Network::Tron.derivation_path(1), "m/44'/195'/0'/0/1");
        assert_eq!(Network::Solana.derivation_path(0), "m/44'/501'/0'/0/0");
        assert_eq!(Network::Ton.derivation_path(0), "m/44'/607'/0'/0/0");
    }

    #[test]
    fn test_address_newtype() {
        let addr = Address::new("0x123".to_string());
        assert_eq!(addr.to_string(), "0x123");
    }

    #[test]
    fn test_address_derivation_formats() {
        // Test mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        // This is a standard test vector mnemonic.
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_str).unwrap();

        // 1. Ethereum
        // Path: m/44'/60'/0'/0/0
        // Expected Addr: 0x9858Effd232B4033E42d90030DCa8d0F1C717Cd4 (Mixed case per checksum usually, but here we just check value)
        let eth_addr =
            WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        println!("Eth: {}", eth_addr);
        assert!(eth_addr.to_string().to_lowercase().starts_with("0x"));
        assert_eq!(eth_addr.to_string().len(), 42);

        // 2. Tron
        // Path: m/44'/195'/0'/0/0
        // Should start with 'T' and be Base58.
        let tron_addr =
            WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Tron, 0).unwrap();
        println!("Tron: {}", tron_addr);
        assert!(tron_addr.to_string().starts_with("T"));
        // Decode base58 to check if it's valid
        let decoded = bs58::decode(tron_addr.to_string()).into_vec().unwrap();
        assert_eq!(decoded.len(), 25); // 1 byte type + 20 bytes data + 4 bytes checksum
        assert_eq!(decoded[0], 0x41);

        // 3. TON
        // Path: m/44'/607'/0'/0/0
        // Should be Base64Url encoded.
        let ton_addr =
            WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ton, 0).unwrap();
        println!("Ton: {}", ton_addr);
        // Should validly decode as Base64Url
        use base64::Engine;
        let decoded_ton = base64::engine::general_purpose::URL_SAFE
            .decode(ton_addr.to_string())
            .unwrap();
        assert_eq!(decoded_ton.len(), 36); // 1 flags + 1 workchain + 32 hash + 2 crc
        assert_eq!(decoded_ton[0], 0x11);
        assert_eq!(decoded_ton[1], 0x00);
    }
}
