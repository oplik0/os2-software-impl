use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Nonce; // Use Nonce directly, it will be GenericArray<u8, NonceSize>
use sha2::{Sha256, Digest};
use rand::RngCore;

// --- Configuration ---
const BLOOM_FILTER_SIZE: usize = 128; // Lambda
const SLIDING_WINDOW_SIZE: usize = 2;
const K_HASH_FUNCTIONS: usize = 3; // Number of hash functions for Bloom filter

// --- Mocked Paillier Cryptosystem ---
// In a real scenario, these would be large numbers and proper Paillier operations.
// For this mock, Pk is just a modulus for the sum, Sk is not strictly needed for this mock's decryption.
#[derive(Debug, Clone)]
pub struct PaillierPk {
    modulus_for_sum: u32, // Plaintext space for sum is 0, 1, 2. So this should be > 2.
}
#[derive(Debug, Clone)]
pub struct PaillierSk {
    modulus_for_sum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBit(u32); // Mock: stores (original_bit + random_multiple_of_modulus)

impl PaillierPk {
    fn new() -> Self {
        PaillierPk {
            modulus_for_sum: 3, // To distinguish sums 0, 1, 2
        }
    }
}
impl PaillierSk {
    fn new() -> Self {
        PaillierSk {
            modulus_for_sum: 3,
        }
    }
}

fn encrypt_paillier(bit: u8, pk: &PaillierPk) -> EncryptedBit {
    // Mock encryption: E(b) = b + r * modulus_for_sum
    // 'r' is a small random number for variability.
    let mut rng = OsRng;
    let r = rng.next_u32() % 10; // Small random factor
    EncryptedBit(bit as u32 + r * pk.modulus_for_sum)
}

fn decrypt_paillier(enc_bit: &EncryptedBit, sk: &PaillierSk) -> u8 {
    // Mock decryption: D(E(b)) = E(b) mod modulus_for_sum
    (enc_bit.0 % sk.modulus_for_sum) as u8
}

fn add_homomorphic(eb1: &EncryptedBit, eb2: &EncryptedBit, _pk: &PaillierPk) -> EncryptedBit {
    // Mock homomorphic addition: E(b1) + E(b2) results in E(b1+b2)
    // Our mock E(b1) + E(b2) = (b1 + r1*M) + (b2 + r2*M) = (b1+b2) + (r1+r2)*M
    // This is already in the form E(b1+b2)
    EncryptedBit(eb1.0 + eb2.0)
}

// --- Bloom Filter ---
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<bool>,
    pub tau: usize, // Count of set bits
}

impl BloomFilter {
    fn new() -> Self {
        BloomFilter {
            bits: vec![false; BLOOM_FILTER_SIZE],
            tau: 0,
        }
    }

    fn add(&mut self, item: &str) {
        let item_bytes = item.as_bytes();
        if item_bytes.len() < SLIDING_WINDOW_SIZE {
            if !item_bytes.is_empty() { // Handle very short items as a single chunk
                self.add_chunk(item_bytes);
            }
            return;
        }

        for window in item_bytes.windows(SLIDING_WINDOW_SIZE) {
            self.add_chunk(window);
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
                bytes.copy_from_slice(&result[i*4..(i+1)*4]);
                let hash_val = u32::from_le_bytes(bytes);
                let index = hash_val as usize % BLOOM_FILTER_SIZE;
                if !self.bits[index] {
                    self.bits[index] = true;
                    self.tau += 1;
                }
            }
        }
    }

    fn encrypt(&self, pk: &PaillierPk) -> EncryptedBloomFilter {
        let encrypted_bits = self.bits.iter().map(|&b| encrypt_paillier(b as u8, pk)).collect();
        EncryptedBloomFilter { bits: encrypted_bits, tau: self.tau }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedBloomFilter {
    bits: Vec<EncryptedBit>,
    pub tau: usize, // Tau is stored in plaintext as per paper (Sec 4.2, 7.1)
}

impl EncryptedBloomFilter {
    #[allow(dead_code)] // This method might be useful for debugging or other scenarios
    fn decrypt(&self, sk: &PaillierSk) -> Vec<u8> { // Returns decrypted bits (0 or 1)
        self.bits.iter().map(|eb| decrypt_paillier(eb, sk)).collect()
    }
}


// --- Symmetric Encryption (AES-GCM) ---
pub struct SymmetricKey(Key<Aes256Gcm>);

impl SymmetricKey {
    fn new() -> Self {
        SymmetricKey(Aes256Gcm::generate_key(OsRng))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Nonce<<Aes256Gcm as AeadCore>::NonceSize>), aes_gcm::Error> {
        let cipher = Aes256Gcm::new(&self.0);
        let nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize> = <Aes256Gcm as AeadCore>::generate_nonce(&mut OsRng);
        cipher.encrypt(&nonce, plaintext).map(|ct| (ct, nonce))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &Nonce<<Aes256Gcm as AeadCore>::NonceSize>) -> Result<Vec<u8>, aes_gcm::Error> {
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

#[derive(Debug)]
pub struct EncryptedDocument {
    id: String,
    encrypted_content: Vec<u8>,
    nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize>, // Nonce used for AES-GCM
    encrypted_index: EncryptedBloomFilter, // B_kw in paper
}

pub struct CloudServer {
    stored_documents: Vec<EncryptedDocument>,
    paillier_pk: Option<PaillierPk>, // Server gets PK
}

impl Os2Client {
    pub fn new() -> Self {
        Os2Client {
            symmetric_key: SymmetricKey::new(),
            paillier_pk: PaillierPk::new(),
            paillier_sk: PaillierSk::new(),
        }
    }

    pub fn get_paillier_pk_for_server(&self) -> PaillierPk {
        self.paillier_pk.clone()
    }
    
    pub fn get_paillier_pk_for_client_use(&self) -> PaillierPk {
        self.paillier_pk.clone()
    }

    pub fn outsource_document(&self, doc_id: &str, content: &str, keywords: Vec<&str>) -> Result<EncryptedDocument, aes_gcm::Error> {
        let (encrypted_content, nonce) = self.symmetric_key.encrypt(content.as_bytes())?;

        let mut bf = BloomFilter::new();
        for keyword in keywords {
            bf.add(keyword);
        }
        
        let encrypted_bf = bf.encrypt(&self.paillier_pk);

        Ok(EncryptedDocument {
            id: doc_id.to_string(),
            encrypted_content,
            nonce,
            encrypted_index: encrypted_bf,
        })
    }

    pub fn generate_query_bloom_filter(&self, search_keywords: Vec<&str>) -> EncryptedBloomFilter {
        let mut query_bf = BloomFilter::new();
        for keyword in search_keywords {
            query_bf.add(keyword);
        }
        query_bf.encrypt(&self.paillier_pk)
    }
    
    // Result post-processing
    pub fn process_search_result(
        &self,
        oblivious_sum_bf: &EncryptedBloomFilter, // This is Delta_vector in paper (Sec 4.5)
    ) -> f64 {
        // Decrypt the sum. Each element will be 0, 1, or 2.
        // Decrypted bits are E(stored_bit + query_bit)
        let decrypted_sum_bits: Vec<u8> = oblivious_sum_bf.bits.iter()
            .map(|eb_sum| decrypt_paillier(eb_sum, &self.paillier_sk))
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
        
        // Jaccard similarity as interpreted from paper: (matches_00 + matches_11) / total_bits
        // This is also known as Simple Matching Coefficient.
        let total_bits = decrypted_sum_bits.len();
        if total_bits == 0 {
            return 0.0;
        }
        (n0_matches + n2_matches) as f64 / total_bits as f64
    }

    pub fn decrypt_document_content(&self, doc: &EncryptedDocument) -> Result<String, aes_gcm::Error> {
        let decrypted_bytes = self.symmetric_key.decrypt(&doc.encrypted_content, &doc.nonce)?;
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
    // A real server would iterate through relevant stored_documents (after filtering by tau/phi).
    pub fn evaluate_query(
        &self,
        query_encrypted_bf: &EncryptedBloomFilter,
        // phi_threshold: usize, // For filtering based on tau, not implemented in this basic example
    ) -> Vec<(String, EncryptedBloomFilter)> {
        let pk = self.paillier_pk.as_ref().expect("Paillier PK not set on server");
        let mut results = Vec::new();

        for doc in &self.stored_documents {
            // TODO: Implement filtering based on doc.encrypted_index.tau and query_encrypted_bf.tau
            // using a phi threshold as described in the paper.
            // For now, we process all.

            if doc.encrypted_index.bits.len() != query_encrypted_bf.bits.len() {
                // Should not happen if BLOOM_FILTER_SIZE is consistent
                continue; 
            }

            let mut oblivious_sum_bits = Vec::with_capacity(BLOOM_FILTER_SIZE);
            for i in 0..BLOOM_FILTER_SIZE {
                let stored_enc_bit = &doc.encrypted_index.bits[i];
                let query_enc_bit = &query_encrypted_bf.bits[i];
                
                // Homomorphic addition: E(stored_bit) + E(query_bit) -> E(stored_bit + query_bit)
                let sum_enc_bit = add_homomorphic(stored_enc_bit, query_enc_bit, pk);
                oblivious_sum_bits.push(sum_enc_bit);
            }
            // Tau for the sum BF is not meaningful in the same way as original tau.
            // The paper returns Delta_vector which is just the encrypted sums.
            results.push((doc.id.clone(), EncryptedBloomFilter { bits: oblivious_sum_bits, tau: 0 }));
        }
        results
    }
}

// --- Example Usage ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os2_workflow_example() {
        // 1. Initialization
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // 2. Client outsources documents
        let doc1_keywords = vec!["health", "research", "neuroscience"];
        let doc1_content = "This document discusses health research in neuroscience.";
        let enc_doc1 = client.outsource_document("doc1", doc1_content, doc1_keywords).unwrap();
        
        let doc2_keywords = vec!["finance", "market", "analysis"];
        let doc2_content = "Financial market analysis and trends.";
        let enc_doc2 = client.outsource_document("doc2", doc2_content, doc2_keywords).unwrap();

        server.store_document(enc_doc1);
        server.store_document(enc_doc2);
        
        // 3. Client generates a search query
        let search_keywords = vec!["neuroscience", "health"];
        let query_bf = client.generate_query_bloom_filter(search_keywords);

        // 4. Server evaluates the query (obliviously)
        // The server would typically filter documents based on tau and phi first.
        // Here, we evaluate against all stored documents for simplicity.
        let evaluation_results = server.evaluate_query(&query_bf);

        // 5. Client processes results
        println!("Search Results:");
        for (doc_id, oblivious_sum_bf) in evaluation_results {
            let similarity = client.process_search_result(&oblivious_sum_bf);
            println!("- Document ID: {}, Similarity: {:.4}", doc_id, similarity);

            // Optionally, client can fetch and decrypt the document if similarity is high
            if similarity > 0.7 { // Example threshold
                 let original_doc = server.stored_documents.iter().find(|d| d.id == doc_id).unwrap();
                 match client.decrypt_document_content(original_doc) {
                     Ok(content) => println!("  Decrypted content (high similarity): {}", content),
                     Err(e) => eprintln!("  Failed to decrypt {}: {:?}", doc_id, e),
                 }
            }
        }
        
        // Example: Test with keywords that won't match well with doc1
        let search_keywords_no_match = vec!["art", "history"];
        let query_bf_no_match = client.generate_query_bloom_filter(search_keywords_no_match);
        let evaluation_results_no_match = server.evaluate_query(&query_bf_no_match);
        
        println!("\nSearch Results (low/no match expected for doc1):");
         for (doc_id, oblivious_sum_bf) in evaluation_results_no_match {
            if doc_id == "doc1" { // Only show for doc1 for this specific test
                let similarity = client.process_search_result(&oblivious_sum_bf);
                println!("- Document ID: {}, Similarity: {:.4}", doc_id, similarity);
                assert!(similarity < 0.7, "Similarity for non-matching keywords should be lower");
            }
        }
    }
    
    #[test]
    fn test_bloom_filter_properties() {
        let mut bf = BloomFilter::new();
        bf.add("apple");
        bf.add("apricot");

        // Check tau (number of set bits)
        assert!(bf.tau > 0 && bf.tau <= K_HASH_FUNCTIONS * ("apple".len() - SLIDING_WINDOW_SIZE + 1 + "apricot".len() - SLIDING_WINDOW_SIZE + 1));
        
        let pk = PaillierPk::new();
        let sk = PaillierSk::new();
        let enc_bf = bf.encrypt(&pk);
        let dec_bf_bits = enc_bf.decrypt(&sk);

        assert_eq!(dec_bf_bits.len(), BLOOM_FILTER_SIZE);
        for i in 0..BLOOM_FILTER_SIZE {
            assert_eq!(dec_bf_bits[i], bf.bits[i] as u8);
        }
    }

    #[test]
    fn test_paillier_mock() {
        let pk = PaillierPk::new();
        let sk = PaillierSk::new();

        let bit0: u8 = 0;
        let bit1: u8 = 1;

        let enc0 = encrypt_paillier(bit0, &pk);
        let enc1 = encrypt_paillier(bit1, &pk);
        
        // Test decryption
        assert_eq!(decrypt_paillier(&enc0, &sk), bit0);
        assert_eq!(decrypt_paillier(&enc1, &sk), bit1);

        // Test homomorphic addition E(b1)+E(b2) -> E(b1+b2)
        // Our mock: add_homomorphic(E(b1), E(b2)) = E_new(b1+b2)
        // Decrypt(E_new(b1+b2)) should be (b1+b2) % modulus_for_sum
        
        // 0+0 = 0
        let sum_enc_0_0 = add_homomorphic(&encrypt_paillier(0, &pk), &encrypt_paillier(0, &pk), &pk);
        assert_eq!(decrypt_paillier(&sum_enc_0_0, &sk), 0);

        // 0+1 = 1
        let sum_enc_0_1 = add_homomorphic(&encrypt_paillier(0, &pk), &encrypt_paillier(1, &pk), &pk);
        assert_eq!(decrypt_paillier(&sum_enc_0_1, &sk), 1);
        
        // 1+0 = 1
        let sum_enc_1_0 = add_homomorphic(&encrypt_paillier(1, &pk), &encrypt_paillier(0, &pk), &pk);
        assert_eq!(decrypt_paillier(&sum_enc_1_0, &sk), 1);

        // 1+1 = 2
        let sum_enc_1_1 = add_homomorphic(&encrypt_paillier(1, &pk), &encrypt_paillier(1, &pk), &pk);
        assert_eq!(decrypt_paillier(&sum_enc_1_1, &sk), 2);
    }
}
