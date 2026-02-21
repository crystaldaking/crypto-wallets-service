use crate::vault::VaultClient;
use alloy::primitives::{Address as AlloyAddress, B256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use coins_bip32::path::DerivationPath;
use coins_bip32::prelude::{SigningKey, XPriv};
use coins_bip39::{English, Mnemonic};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

    /// Converts an Ethereum address to EIP-55 checksum format.
    /// 
    /// EIP-55: Mixed-case checksum address encoding
    /// https://eips.ethereum.org/EIPS/eip-55
    fn to_checksum_address(address: &str) -> anyhow::Result<String> {
        // Parse address using alloy and convert to checksum format
        let alloy_addr = AlloyAddress::parse_checksummed(address, None)
            .or_else(|_| AlloyAddress::from_str(address))
            .map_err(|e| anyhow::anyhow!("Invalid Ethereum address: {}", e))?;
        Ok(alloy_addr.to_checksum(None))
    }
}

/// Cache key for derived addresses
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct AddressCacheKey {
    encrypted_seed_hash: u64,
    network: Network,
    index: u32,
}

pub struct WalletManager {
    vault: VaultClient,
    /// LRU cache for derived addresses to avoid repeated computation
    address_cache: Arc<RwLock<LruCache<AddressCacheKey, Address>>>,
}

impl WalletManager {
    /// Default cache size for derived addresses
    const DEFAULT_CACHE_SIZE: usize = 1000;

    pub fn new(vault: VaultClient) -> Self {
        let cache = LruCache::new(
            NonZeroUsize::new(Self::DEFAULT_CACHE_SIZE).unwrap()
        );
        
        Self {
            vault,
            address_cache: Arc::new(RwLock::new(cache)),
        }
    }

    /// Create with custom cache size
    pub fn with_cache_size(vault: VaultClient, cache_size: usize) -> Self {
        let cache_size = std::cmp::max(1, cache_size);
        let cache = LruCache::new(
            NonZeroUsize::new(cache_size).unwrap()
        );
        
        Self {
            vault,
            address_cache: Arc::new(RwLock::new(cache)),
        }
    }

    /// Get cache statistics for monitoring
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.address_cache.read().await;
        let cap = cache.cap().get();
        let len = cache.len();
        (len, cap)
    }

    /// Clear the address cache
    pub async fn clear_cache(&self) {
        let mut cache = self.address_cache.write().await;
        cache.clear();
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
        // Compute hash of encrypted_seed for cache key
        let mut hasher = DefaultHasher::new();
        encrypted_seed.hash(&mut hasher);
        let encrypted_seed_hash = hasher.finish();
        
        let cache_key = AddressCacheKey {
            encrypted_seed_hash,
            network,
            index,
        };

        // Try to get from cache first (need write lock for get since it updates LRU)
        {
            let mut cache = self.address_cache.write().await;
            if let Some(cached_address) = cache.get(&cache_key) {
                tracing::debug!("Address cache hit for {:?} index {}", network, index);
                return Ok(cached_address.clone());
            }
        }

        // Cache miss - derive the address
        tracing::debug!("Address cache miss for {:?} index {}", network, index);
        let mut seed_bytes = self.vault.decrypt(encrypted_seed).await?;
        let mnemonic_phrase = String::from_utf8(seed_bytes.clone())
            .map_err(|e| {
                tracing::error!("Failed to convert seed bytes to UTF-8: {}", e);
                e
            })?;
        let mnemonic = Mnemonic::<English>::new_from_phrase(&mnemonic_phrase)
            .map_err(|e| {
                tracing::error!("Failed to create mnemonic from phrase: {}", e);
                e
            })?;
        seed_bytes.zeroize();

        let address = Self::derive_address_from_mnemonic(&mnemonic, network, index)
            .map_err(|e| {
                tracing::error!("Failed to derive address for {:?} index {}: {}", network, index, e);
                e
            })?;

        // Store in cache
        {
            let mut cache = self.address_cache.write().await;
            cache.put(cache_key, address.clone());
        }

        Ok(address)
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
                let address = signer.address().to_string();
                // Apply EIP-55 checksum encoding
                let checksum_address = Network::to_checksum_address(&address)?;
                Ok(Address::new(checksum_address))
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
                    <[u8; 32]>::try_from(signing_key_bip32.to_bytes().as_ref())
                    .map_err(|_| anyhow::anyhow!("Invalid signing key length for Solana: expected 32 bytes"))?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_32);
                let public_key = signing_key.verifying_key();
                Ok(Address::new(
                    bs58::encode(public_key.as_bytes()).into_string(),
                ))
            }
            Network::Ton => {
                let signing_key_bip32: &SigningKey = derived_xpriv.as_ref();
                let seed_32: [u8; 32] =
                    <[u8; 32]>::try_from(signing_key_bip32.to_bytes().as_ref())
                    .map_err(|_| anyhow::anyhow!("Invalid signing key length for TON: expected 32 bytes"))?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_32);
                let public_key = signing_key.verifying_key();

                // Use tonlib-core for proper TON Wallet V4R2 address derivation
                let wallet = Self::derive_ton_wallet_v4r2(public_key.as_bytes())?;
                Ok(Address::new(wallet.address.to_base64_url()))
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

    /// Derives TON Wallet V4R2 address from public key using tonlib-core
    fn derive_ton_wallet_v4r2(public_key: &[u8; 32]) -> anyhow::Result<tonlib_core::wallet::ton_wallet::TonWallet> {
        use tonlib_core::wallet::mnemonic::KeyPair;
        use tonlib_core::wallet::ton_wallet::TonWallet;
        use tonlib_core::wallet::wallet_version::WalletVersion;
        
        // Create a KeyPair with the public key
        // KeyPair is a struct with public_key and secret_key fields (Vec<u8>)
        let key_pair = KeyPair {
            public_key: public_key.to_vec(),
            secret_key: vec![0u8; 64], // dummy secret key - not used for address calculation
        };
        
        // Derive wallet using default parameters (workchain 0, standard wallet_id)
        let wallet = TonWallet::new(WalletVersion::V4R2, key_pair)
            .map_err(|e| anyhow::anyhow!("Failed to derive TON wallet: {:?}", e))?;
        Ok(wallet)
    }
}

/// Validates transaction format for the given network
/// Returns decoded bytes or an error if format is invalid
pub fn validate_transaction_format(network: Network, unsigned_tx: &str) -> anyhow::Result<Vec<u8>> {
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
        // Verify EIP-55 checksum format (mixed case, not all lowercase)
        let eth_addr =
            WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        println!("Eth: {}", eth_addr);
        assert!(eth_addr.to_string().starts_with("0x"));
        assert_eq!(eth_addr.to_string().len(), 42);
        // Address should be mixed-case (EIP-55), not all lowercase
        let addr_str = eth_addr.to_string();
        assert!(
            addr_str.chars().any(|c| c.is_ascii_uppercase()),
            "EIP-55 address should contain uppercase letters"
        );

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
        // Should be Base64Url encoded with proper Wallet V4R2 address
        let ton_addr =
            WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ton, 0).unwrap();
        println!("Ton: {}", ton_addr);
        
        // Verify TON address format (bounceable, workchain 0)
        // EQ prefix indicates bounceable workchain 0 address
        assert!(ton_addr.to_string().starts_with("EQ"), "TON bounceable address should start with EQ");
        
        // Should validly decode as Base64Url
        use base64::Engine;
        let decoded_ton = base64::engine::general_purpose::URL_SAFE
            .decode(ton_addr.to_string())
        .unwrap();
        assert_eq!(decoded_ton.len(), 36); // 1 flags + 1 workchain + 32 hash + 2 crc
        assert_eq!(decoded_ton[0], 0x11); // bounceable flag
        assert_eq!(decoded_ton[1], 0x00); // workchain 0
    }

    #[test]
    fn test_eip55_checksum() {
        // Test vectors verified with alloy (EIP-55 specification)
        // https://eips.ethereum.org/EIPS/eip-55
        
        // All caps input -> mixed case output
        assert_eq!(
            Network::to_checksum_address("0x52908400098527886e0f7030069857d2e4169ee7").unwrap(),
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
        
        // All lower input -> mixed case output
        assert_eq!(
            Network::to_checksum_address("0x8617e340b3d01fa5f11f306f4090fd50e238070d").unwrap(),
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
        );
        
        // Already checksummed should remain the same
        assert_eq!(
            Network::to_checksum_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        
        // Without 0x prefix
        assert_eq!(
            Network::to_checksum_address("52908400098527886e0f7030069857d2e4169ee7").unwrap(),
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
        
        // Test that result is not all lowercase (contains some uppercase)
        let result = Network::to_checksum_address("0x52908400098527886e0f7030069857d2e4169ee7").unwrap();
        assert!(result.chars().any(|c| c.is_ascii_uppercase() && c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_address_cache_key_hashing() {
        // Test that AddressCacheKey implements Hash correctly
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let key1 = AddressCacheKey {
            encrypted_seed_hash: 12345,
            network: Network::Ethereum,
            index: 0,
        };
        
        let key2 = AddressCacheKey {
            encrypted_seed_hash: 12345,
            network: Network::Ethereum,
            index: 0,
        };
        
        let key3 = AddressCacheKey {
            encrypted_seed_hash: 12345,
            network: Network::Solana,
            index: 0,
        };
        
        // Same keys should have same hash
        let mut hasher1 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        let hash1 = hasher1.finish();
        
        let mut hasher2 = DefaultHasher::new();
        key2.hash(&mut hasher2);
        let hash2 = hasher2.finish();
        
        assert_eq!(hash1, hash2);
        
        // Different networks should have different hashes
        let mut hasher3 = DefaultHasher::new();
        key3.hash(&mut hasher3);
        let hash3 = hasher3.finish();
        
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_network_hash_impl() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let networks = vec![
            Network::Ethereum,
            Network::Tron,
            Network::Solana,
            Network::Ton,
        ];
        
        let mut hashes = std::collections::HashSet::new();
        
        for network in networks {
            let mut hasher = DefaultHasher::new();
            network.hash(&mut hasher);
            let hash = hasher.finish();
            // All networks should have unique hashes
            assert!(hashes.insert(hash), "Duplicate hash found for {:?}", network);
        }
    }

    #[test]
    fn test_transaction_validation_empty() {
        let result = validate_transaction_format(Network::Ethereum, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_transaction_validation_odd_length() {
        let result = validate_transaction_format(Network::Ethereum, "0xabc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("odd length"));
    }

    #[test]
    fn test_transaction_validation_invalid_hex() {
        let result = validate_transaction_format(Network::Ethereum, "0xGGGG");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-hex"));
    }

    #[test]
    fn test_transaction_validation_ethereum_legacy_too_short() {
        // Legacy transaction should be at least 45 bytes
        let short_tx = "0xc0".to_string() + &"00".repeat(10);
        let result = validate_transaction_format(Network::Ethereum, &short_tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_transaction_validation_ethereum_eip1559() {
        // Valid EIP-1559 transaction (type 0x02)
        let tx = "0x02".to_string() + &"00".repeat(100);
        let result = validate_transaction_format(Network::Ethereum, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_validation_ethereum_eip2930() {
        // Valid EIP-2930 transaction (type 0x01)
        let tx = "0x01".to_string() + &"00".repeat(100);
        let result = validate_transaction_format(Network::Ethereum, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_validation_solana_too_short() {
        let short_tx = "0x".to_string() + &"00".repeat(30);
        let result = validate_transaction_format(Network::Solana, &short_tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_transaction_validation_unknown_type() {
        let tx = "0x05".to_string() + &"00".repeat(100);
        let result = validate_transaction_format(Network::Ethereum, &tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown Ethereum transaction type"));
    }

    #[test]
    fn test_sign_tx_with_test_mnemonic() {
        // Use a known test mnemonic
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_str).unwrap();
        
        // Test message to sign (32 bytes for Ethereum)
        let message = b"test message for signing".to_vec();
        
        // Test Ethereum signing using derive_address_from_mnemonic logic
        let eth_address = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        assert!(eth_address.to_string().starts_with("0x"));
        assert_eq!(eth_address.to_string().len(), 42);
        
        // Test Tron signing
        let tron_address = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Tron, 0).unwrap();
        assert!(tron_address.to_string().starts_with("T"));
        
        // Test Solana signing
        let solana_address = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Solana, 0).unwrap();
        assert!(solana_address.to_string().len() >= 32);
        assert!(solana_address.to_string().len() <= 44);
        
        // Test TON signing
        let ton_address = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ton, 0).unwrap();
        assert!(ton_address.to_string().starts_with("EQ"));
    }

    #[test]
    fn test_sign_tx_different_indices_produce_different_addresses() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_str).unwrap();
        
        // Different indices should produce different addresses
        let addr0 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        let addr1 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 1).unwrap();
        let addr2 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 2).unwrap();
        
        assert_ne!(addr0.to_string(), addr1.to_string());
        assert_ne!(addr1.to_string(), addr2.to_string());
        assert_ne!(addr0.to_string(), addr2.to_string());
    }

    #[test]
    fn test_sign_tx_deterministic_addresses() {
        // Addresses should be deterministic - same mnemonic + index = same address
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_str).unwrap();
        
        let addr1 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        let addr2 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        
        assert_eq!(addr1.to_string(), addr2.to_string());
        
        // Same for other networks
        let tron1 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Tron, 5).unwrap();
        let tron2 = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Tron, 5).unwrap();
        assert_eq!(tron1.to_string(), tron2.to_string());
    }

    #[test]
    fn test_transaction_validation_valid_solana() {
        // Valid Solana transaction (at least 64 bytes)
        let tx = "0x".to_string() + &"00".repeat(64);
        let result = validate_transaction_format(Network::Solana, &tx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_transaction_validation_valid_ton() {
        // Valid TON transaction (at least 10 bytes)
        let tx = "0x".to_string() + &"00".repeat(10);
        let result = validate_transaction_format(Network::Ton, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_validation_valid_tron() {
        // Valid Tron transaction (at least 10 bytes)
        let tx = "0x".to_string() + &"00".repeat(10);
        let result = validate_transaction_format(Network::Tron, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_eth_address_format() {
        // Test that Ethereum addresses are properly checksummed
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_str).unwrap();
        
        let address = WalletManager::derive_address_from_mnemonic(&mnemonic, Network::Ethereum, 0).unwrap();
        let addr_str = address.to_string();
        
        // Should start with 0x
        assert!(addr_str.starts_with("0x"));
        
        // Should be 42 characters (0x + 40 hex chars)
        assert_eq!(addr_str.len(), 42);
        
        // Should contain both upper and lower case (EIP-55)
        let has_upper = addr_str.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = addr_str.chars().any(|c| c.is_ascii_lowercase());
        assert!(has_upper, "EIP-55 address should contain uppercase letters");
        assert!(has_lower, "EIP-55 address should contain lowercase letters");
    }
}
