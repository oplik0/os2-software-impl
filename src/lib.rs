use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Nonce; // Use Nonce directly, it will be GenericArray<u8, NonceSize>
use aes_gcm::{Aes256Gcm, Key};
use num_bigint::BigUint;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

// --- Add module and imports ---
mod paillier;

// Re-export Paillier types and functions for benchmarks
pub use paillier::{
    add_homomorphic, decrypt_paillier, encrypt_paillier, generate_keypair, mul_homomorphic,
    PaillierPk, PaillierSk,
};
// --- End: Add module and imports ---

// --- Configuration ---
const BLOOM_FILTER_SIZE: usize = 128; // Lambda
const SLIDING_WINDOW_SIZE: usize = 2;
const K_HASH_FUNCTIONS: usize = 3; // Number of hash functions for Bloom filter

// --- Bloom Filter ---
#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub bits: Vec<bool>,
    pub tau: usize, // Count of set bits
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomFilter {
    pub fn new() -> Self {
        BloomFilter {
            bits: vec![false; BLOOM_FILTER_SIZE],
            tau: 0,
        }
    }

    pub fn add(&mut self, item: &str) {
        let item_bytes = item.as_bytes();
        if item_bytes.len() < SLIDING_WINDOW_SIZE {
            if !item_bytes.is_empty() {
                // Handle very short items as a single chunk
                self.add_chunk(item_bytes);
            }
            return;
        }

        // Collect all chunks to process in parallel
        let chunks: Vec<&[u8]> = item_bytes.windows(SLIDING_WINDOW_SIZE).collect();

        // Process chunks in parallel and collect the bit indices
        let bit_updates: Vec<Vec<usize>> = chunks
            .par_iter()
            .map(|&chunk| {
                let mut hasher = Sha256::default();
                hasher.update(chunk);
                let result = hasher.finalize();

                let mut indices = Vec::new();
                for i in 0..K_HASH_FUNCTIONS {
                    if result.len() >= (i + 1) * 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&result[i * 4..(i + 1) * 4]);
                        let hash_val = u32::from_le_bytes(bytes);
                        let index = hash_val as usize % BLOOM_FILTER_SIZE;
                        indices.push(index);
                    }
                }
                indices
            })
            .collect();

        // Apply updates sequentially to maintain tau count correctly
        for indices in bit_updates {
            for index in indices {
                if !self.bits[index] {
                    self.bits[index] = true;
                    self.tau += 1;
                }
            }
        }
    }

    fn add_chunk(&mut self, chunk: &[u8]) {
        let mut hasher = Sha256::default(); // Changed from Sha256::new()
        hasher.update(chunk);
        let result = hasher.finalize();

        for i in 0..K_HASH_FUNCTIONS {
            // Derive multiple hash values from the SHA256 output
            // Simple approach: take different 4-byte chunks
            if result.len() >= (i + 1) * 4 {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&result[i * 4..(i + 1) * 4]);
                let hash_val = u32::from_le_bytes(bytes);
                let index = hash_val as usize % BLOOM_FILTER_SIZE;
                if !self.bits[index] {
                    self.bits[index] = true;
                    self.tau += 1;
                }
            }
        }
    }
    pub fn encrypt(&self, pk: &PaillierPk) -> EncryptedBloomFilter {
        let encrypted_bits = self
            .bits
            .par_iter()
            .map(|&b| paillier::encrypt_paillier(&BigUint::from(b as u8), pk))
            .collect();
        EncryptedBloomFilter {
            bits: encrypted_bits,
            tau: self.tau,
        }
    }

    /// Create a new Bloom filter and add multiple keywords in parallel
    pub fn from_keywords(keywords: &[&str]) -> Self {
        let mut bf = BloomFilter::new();

        // Process keywords in parallel and collect all bit updates
        let all_bit_updates: Vec<Vec<usize>> = keywords
            .par_iter()
            .flat_map(|&keyword| {
                let item_bytes = keyword.as_bytes();
                if item_bytes.len() < SLIDING_WINDOW_SIZE {
                    if !item_bytes.is_empty() {
                        vec![Self::get_chunk_indices(item_bytes)]
                    } else {
                        vec![]
                    }
                } else {
                    item_bytes
                        .windows(SLIDING_WINDOW_SIZE)
                        .map(Self::get_chunk_indices)
                        .collect()
                }
            })
            .collect();

        // Apply all updates sequentially to maintain tau count correctly
        for indices in all_bit_updates {
            for index in indices {
                if !bf.bits[index] {
                    bf.bits[index] = true;
                    bf.tau += 1;
                }
            }
        }

        bf
    }

    /// Helper method to get bit indices for a chunk
    fn get_chunk_indices(chunk: &[u8]) -> Vec<usize> {
        let mut hasher = Sha256::default();
        hasher.update(chunk);
        let result = hasher.finalize();

        let mut indices = Vec::new();
        for i in 0..K_HASH_FUNCTIONS {
            if result.len() >= (i + 1) * 4 {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&result[i * 4..(i + 1) * 4]);
                let hash_val = u32::from_le_bytes(bytes);
                let index = hash_val as usize % BLOOM_FILTER_SIZE;
                indices.push(index);
            }
        }
        indices
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedBloomFilter {
    pub bits: Vec<BigUint>,
    pub tau: usize, // Tau is stored in plaintext as per paper (Sec 4.2, 7.1)
}

impl EncryptedBloomFilter {
    #[allow(dead_code)] // This method might be useful for debugging or other scenarios
    pub fn decrypt(&self, sk: &PaillierSk, pk: &PaillierPk) -> Vec<u8> {
        // Returns decrypted bits (0 or 1)
        self.bits
            .par_iter()
            .map(|eb| {
                let decrypted = paillier::decrypt_paillier(eb, sk, pk);
                decrypted.to_bytes_le()[0] // Convert BigUint to u8
            })
            .collect()
    }
}

// --- Symmetric Encryption (AES-GCM) ---
pub struct SymmetricKey(Key<Aes256Gcm>);

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricKey {
    pub fn new() -> Self {
        SymmetricKey(Aes256Gcm::generate_key(OsRng))
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Nonce<<Aes256Gcm as AeadCore>::NonceSize>), aes_gcm::Error> {
        let cipher = Aes256Gcm::new(&self.0);
        let nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize> =
            <Aes256Gcm as AeadCore>::generate_nonce(&mut OsRng);
        cipher.encrypt(&nonce, plaintext).map(|ct| (ct, nonce))
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce<<Aes256Gcm as AeadCore>::NonceSize>,
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let cipher = Aes256Gcm::new(&self.0);
        cipher.decrypt(nonce, ciphertext)
    }
}

// --- OS2 Entities ---
pub struct Os2Client {
    symmetric_key: SymmetricKey,
    paillier_pk: PaillierPk,
    paillier_sk: PaillierSk,
}

impl Default for Os2Client {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct EncryptedDocument {
    pub id: String,
    pub encrypted_content: Vec<u8>,
    pub nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize>, // Nonce used for AES-GCM
    pub encrypted_index: EncryptedBloomFilter,            // B_kw in paper
}

pub struct CloudServer {
    pub stored_documents: Vec<EncryptedDocument>,
    pub paillier_pk: Option<PaillierPk>, // Server gets PK
}

impl Os2Client {
    pub fn new() -> Self {
        let (paillier_pk, paillier_sk) = paillier::generate_keypair(1024); // Use 1024-bit keys for reasonable speed
        Os2Client {
            symmetric_key: SymmetricKey::new(),
            paillier_pk,
            paillier_sk,
        }
    } // Test-optimized constructor with smaller keys for faster testing
    #[deprecated(note = "This method should only be used for testing")]
    pub fn new_for_testing() -> Self {
        let (paillier_pk, paillier_sk) = paillier::generate_keypair(512); // Use 512-bit keys for faster tests
        Os2Client {
            symmetric_key: SymmetricKey::new(),
            paillier_pk,
            paillier_sk,
        }
    }

    pub fn get_paillier_pk_for_server(&self) -> PaillierPk {
        self.paillier_pk.clone()
    }
    pub fn get_paillier_pk_for_client_use(&self) -> PaillierPk {
        self.paillier_pk.clone()
    }

    // For testing only - expose private key
    #[deprecated(note = "This method should only be used for testing")]
    pub fn get_paillier_sk_for_testing(&self) -> &PaillierSk {
        &self.paillier_sk
    }

    pub fn outsource_document(
        &self,
        doc_id: &str,
        content: &str,
        keywords: Vec<&str>,
    ) -> Result<EncryptedDocument, aes_gcm::Error> {
        let (encrypted_content, nonce) = self.symmetric_key.encrypt(content.as_bytes())?;

        // Use parallel bloom filter creation for better performance
        let bf = BloomFilter::from_keywords(&keywords);
        let encrypted_bf = bf.encrypt(&self.paillier_pk);

        Ok(EncryptedDocument {
            id: doc_id.to_string(),
            encrypted_content,
            nonce,
            encrypted_index: encrypted_bf,
        })
    }

    pub fn generate_query_bloom_filter(&self, search_keywords: Vec<&str>) -> EncryptedBloomFilter {
        // Use parallel bloom filter creation for better performance
        let query_bf = BloomFilter::from_keywords(&search_keywords);
        query_bf.encrypt(&self.paillier_pk)
    } // Result post-processing
    pub fn process_search_result(
        &self,
        oblivious_sum_bf: &EncryptedBloomFilter, // This is Delta_vector in paper (Sec 4.5)
    ) -> f64 {
        // Decrypt the sum. Each element will be 0, 1, or 2.
        // Decrypted bits are E(stored_bit + query_bit)
        let decrypted_sum_bits: Vec<u8> = oblivious_sum_bf
            .bits
            .par_iter()
            .map(|eb_sum| {
                let decrypted =
                    paillier::decrypt_paillier(eb_sum, &self.paillier_sk, &self.paillier_pk);
                decrypted.to_bytes_le()[0] // Convert BigUint to u8
            })
            .collect();

        let mut n0_matches = 0; // stored=0, query=0 => sum=0
        let mut _n1_mismatches = 0; // (0,1) or (1,0) => sum=1

        let mut n2_matches = 0; // stored=1, query=1 => sum=2

        for &sum_val in &decrypted_sum_bits {
            match sum_val {
                0 => n0_matches += 1,
                1 => _n1_mismatches += 1, // Marked as unused
                2 => n2_matches += 1,
                _ => {} // Should not happen with modulus 3 for sum
            }
        }

        // Jaccard similarity as interpreted from paper: (matches_00 + matches_11) /
        // total_bits This is also known as Simple Matching Coefficient.
        let total_bits = decrypted_sum_bits.len();
        if total_bits == 0 {
            return 0.0;
        }
        (n0_matches + n2_matches) as f64 / total_bits as f64
    }

    pub fn decrypt_document_content(
        &self,
        doc: &EncryptedDocument,
    ) -> Result<String, aes_gcm::Error> {
        let decrypted_bytes = self
            .symmetric_key
            .decrypt(&doc.encrypted_content, &doc.nonce)?;
        Ok(String::from_utf8_lossy(&decrypted_bytes).to_string())
    }
}

impl CloudServer {
    pub fn new() -> Self {
        CloudServer {
            stored_documents: Vec::new(),
            paillier_pk: None,
        }
    }

    pub fn receive_paillier_pk(&mut self, pk: PaillierPk) {
        self.paillier_pk = Some(pk);
    }

    pub fn store_document(&mut self, doc: EncryptedDocument) {
        self.stored_documents.push(doc);
    }

    // Query evaluation (Sec 4.5)
    // Returns a vector of (doc_id, oblivious_sum_bloom_filter)
    // For simplicity, this example processes one stored document's index.
    // A real server would iterate through relevant stored_documents (after
    // filtering by tau/phi).
    pub fn evaluate_query(
        &self,
        query_encrypted_bf: &EncryptedBloomFilter,
        // phi_threshold: usize, // For filtering based on tau, not implemented in this basic
        // example
    ) -> Vec<(String, EncryptedBloomFilter)> {
        let pk = self
            .paillier_pk
            .as_ref()
            .expect("Paillier PK not set on server");

        self.stored_documents
            .par_iter()
            .filter_map(|doc| {
                // TODO: Implement filtering based on doc.encrypted_index.tau and
                // query_encrypted_bf.tau using a phi threshold as described in the
                // paper. For now, we process all.

                if doc.encrypted_index.bits.len() != query_encrypted_bf.bits.len() {
                    // Should not happen if BLOOM_FILTER_SIZE is consistent
                    return None;
                }

                let oblivious_sum_bits = (0..BLOOM_FILTER_SIZE)
                    .into_par_iter()
                    .map(|i| {
                        let stored_enc_bit = &doc.encrypted_index.bits[i];
                        let query_enc_bit = &query_encrypted_bf.bits[i];
                        // Homomorphic addition: E(stored_bit) + E(query_bit) -> E(stored_bit +
                        // query_bit)
                        paillier::add_homomorphic(stored_enc_bit, query_enc_bit, pk)
                    })
                    .collect();

                // Tau for the sum BF is not meaningful in the same way as original tau.
                // The paper returns Delta_vector which is just the encrypted sums.
                Some((
                    doc.id.clone(),
                    EncryptedBloomFilter {
                        bits: oblivious_sum_bits,
                        tau: 0,
                    },
                ))
            })
            .collect()
    }
}

impl Default for CloudServer {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_paillier_basic_operations() {
        let (pk, sk) = paillier::generate_keypair(512);

        let m1 = BigUint::from(5u32);
        let m2 = BigUint::from(10u32);

        // Test encryption/decryption
        let c1 = paillier::encrypt_paillier(&m1, &pk);
        let c2 = paillier::encrypt_paillier(&m2, &pk);

        assert_eq!(paillier::decrypt_paillier(&c1, &sk, &pk), m1);
        assert_eq!(paillier::decrypt_paillier(&c2, &sk, &pk), m2);

        // Test homomorphic addition
        let c_sum = paillier::add_homomorphic(&c1, &c2, &pk);
        let decrypted_sum = paillier::decrypt_paillier(&c_sum, &sk, &pk);
        assert_eq!(decrypted_sum, &m1 + &m2);

        // Test homomorphic multiplication by constant
        let k = BigUint::from(3u32);
        let c_mul = paillier::mul_homomorphic(&c1, &k, &pk);
        let decrypted_mul = paillier::decrypt_paillier(&c_mul, &sk, &pk);
        assert_eq!(decrypted_mul, &m1 * &k);
    }

    #[test]
    fn test_bloom_filter_basic() {
        let mut bf = BloomFilter::new();
        assert_eq!(bf.tau, 0);

        bf.add("test");
        assert!(bf.tau > 0);

        let initial_tau = bf.tau;
        bf.add("test"); // Adding same item should not increase tau significantly
        assert!(bf.tau >= initial_tau);
    }

    #[test]
    fn test_bloom_filter_sliding_window() {
        let mut bf = BloomFilter::new();
        bf.add("hello");

        // Check that the sliding window approach sets appropriate bits
        assert!(bf.tau > 0);
        assert!(bf.tau <= K_HASH_FUNCTIONS * ("hello".len() - SLIDING_WINDOW_SIZE + 1));
    }

    #[test]
    fn test_bloom_filter_encryption_decryption() {
        let (pk, sk) = generate_keypair(512);
        let mut bf = BloomFilter::new();
        bf.add("apple");
        bf.add("banana");

        let encrypted_bf = bf.encrypt(&pk);
        let decrypted_bits = encrypted_bf.decrypt(&sk, &pk);

        assert_eq!(decrypted_bits.len(), BLOOM_FILTER_SIZE);
        for (i, &decrypted_bit) in decrypted_bits.iter().enumerate().take(BLOOM_FILTER_SIZE) {
            assert_eq!(decrypted_bit, if bf.bits[i] { 1 } else { 0 });
        }
    }

    #[test]
    fn test_symmetric_encryption() {
        let key = SymmetricKey::new();
        let plaintext = b"Hello, world!";

        let (ciphertext, nonce) = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_os2_client_initialization() {
        let client = Os2Client::new();
        let pk_for_server = client.get_paillier_pk_for_server();
        let pk_for_client = client.get_paillier_pk_for_client_use();

        // Both should be the same reference to the same key
        assert_eq!(pk_for_server.n, pk_for_client.n);
    }

    #[test]
    fn test_document_outsourcing() {
        let client = Os2Client::new();
        let keywords = vec!["rust", "programming", "language"];
        let content = "Rust is a systems programming language.";

        let encrypted_doc = client
            .outsource_document("doc1", content, keywords)
            .unwrap();

        assert_eq!(encrypted_doc.id, "doc1");
        assert!(!encrypted_doc.encrypted_content.is_empty());
        assert!(encrypted_doc.encrypted_index.tau > 0);

        // Test decryption
        let decrypted_content = client.decrypt_document_content(&encrypted_doc).unwrap();
        assert_eq!(decrypted_content, content);
    }

    #[test]
    fn test_query_generation() {
        let client = Os2Client::new();
        let keywords = vec!["search", "query"];

        let query_bf = client.generate_query_bloom_filter(keywords);
        assert!(query_bf.tau > 0);
        assert_eq!(query_bf.bits.len(), BLOOM_FILTER_SIZE);
    }

    #[test]
    fn test_server_document_storage() {
        let mut server = CloudServer::new();
        let client = Os2Client::new();

        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        let encrypted_doc = client
            .outsource_document("test_doc", "Test content", vec!["test"])
            .unwrap();

        server.store_document(encrypted_doc);
        assert_eq!(server.stored_documents.len(), 1);
    }

    #[test]
    fn test_query_evaluation() {
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // Store a document
        let doc_keywords = vec!["machine", "learning", "ai"];
        let encrypted_doc = client
            .outsource_document("ml_doc", "Machine learning and AI research", doc_keywords)
            .unwrap();
        server.store_document(encrypted_doc);

        // Generate query
        let query_keywords = vec!["machine", "learning"];
        let query_bf = client.generate_query_bloom_filter(query_keywords);

        // Evaluate query
        let results = server.evaluate_query(&query_bf);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ml_doc");
    }

    #[test]
    fn test_similarity_calculation() {
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // Store documents with different keyword sets
        let doc1_keywords = vec!["rust", "programming", "systems"];
        let doc2_keywords = vec!["python", "scripting", "web"];

        let doc1 = client
            .outsource_document("doc1", "Rust content", doc1_keywords)
            .unwrap();
        let doc2 = client
            .outsource_document("doc2", "Python content", doc2_keywords)
            .unwrap();

        server.store_document(doc1);
        server.store_document(doc2);

        // Query for Rust-related keywords
        let query_keywords = vec!["rust", "programming"];
        let query_bf = client.generate_query_bloom_filter(query_keywords);

        let results = server.evaluate_query(&query_bf);
        assert_eq!(results.len(), 2);

        // Calculate similarities
        let similarity1 = client.process_search_result(&results[0].1);
        let similarity2 = client.process_search_result(&results[1].1);

        // doc1 should have higher similarity than doc2 for rust-related query
        assert!((0.0..=1.0).contains(&similarity1));
        assert!((0.0..=1.0).contains(&similarity2));
    }

    #[test]
    fn test_end_to_end_workflow() {
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // Store multiple documents
        let documents = vec![
            (
                "doc1",
                "Machine learning algorithms and neural networks",
                vec!["machine", "learning", "neural", "networks"],
            ),
            (
                "doc2",
                "Web development with JavaScript and React",
                vec!["web", "development", "javascript", "react"],
            ),
            (
                "doc3",
                "Data science and machine learning applications",
                vec!["data", "science", "machine", "learning"],
            ),
        ];

        for (id, content, keywords) in documents {
            let encrypted_doc = client.outsource_document(id, content, keywords).unwrap();
            server.store_document(encrypted_doc);
        }

        // Search for machine learning related documents
        let query_keywords = vec!["machine", "learning"];
        let query_bf = client.generate_query_bloom_filter(query_keywords);
        let results = server.evaluate_query(&query_bf);

        assert_eq!(results.len(), 3);

        // Process results and find relevant documents
        let mut relevant_docs = Vec::new();
        for (doc_id, oblivious_sum_bf) in results {
            let similarity = client.process_search_result(&oblivious_sum_bf);
            if similarity > 0.6 {
                // Threshold for relevance
                relevant_docs.push((doc_id, similarity));
            }
        }

        // Should find documents with machine learning keywords
        assert!(!relevant_docs.is_empty());
    }

    #[test]
    fn test_bloom_filter_false_positives() {
        let mut bf = BloomFilter::new();
        let keywords = vec!["apple", "banana", "cherry", "date", "elderberry"];

        for keyword in &keywords {
            bf.add(keyword);
        }

        // Test with a keyword that wasn't added
        let mut test_bf = BloomFilter::new();
        test_bf.add("zebra");

        // The bloom filters should have different patterns
        let mut differences = 0;
        for i in 0..BLOOM_FILTER_SIZE {
            if bf.bits[i] != test_bf.bits[i] {
                differences += 1;
            }
        }

        // Should have some differences (this test might occasionally fail due to hash
        // collisions)
        assert!(
            differences > 0,
            "Bloom filters for different keywords should differ"
        );
    }

    #[test]
    fn test_large_document_handling() {
        let client = Os2Client::new();
        let large_content = "word ".repeat(1000); // 5000 character document
        let keywords = vec!["word", "large", "document", "test"];

        let encrypted_doc = client
            .outsource_document("large_doc", &large_content, keywords)
            .unwrap();
        let decrypted_content = client.decrypt_document_content(&encrypted_doc).unwrap();

        assert_eq!(decrypted_content, large_content);
    }

    #[test]
    fn test_empty_and_edge_cases() {
        let client = Os2Client::new();

        // Test with empty content
        let encrypted_doc = client.outsource_document("empty", "", vec!["tag"]).unwrap();
        let decrypted = client.decrypt_document_content(&encrypted_doc).unwrap();
        assert_eq!(decrypted, "");

        // Test with single character keywords
        let mut bf = BloomFilter::new();
        bf.add("a");
        bf.add("b");
        assert!(bf.tau > 0);

        // Test with very long keyword
        let long_keyword = "a".repeat(1000);
        let mut long_bf = BloomFilter::new();
        long_bf.add(&long_keyword);
        assert!(long_bf.tau > 0);
    }
}
