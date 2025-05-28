use num_bigint::BigUint;
use os2_software_impl::*;

/// Test suite for individual components
mod bloom_filter_tests {
    use super::*;

    #[test]
    fn test_bloom_filter_creation() {
        let bf = BloomFilter::new();
        assert_eq!(bf.tau, 0);
        assert_eq!(bf.bits.len(), 128); // BLOOM_FILTER_SIZE
        assert!(bf.bits.iter().all(|&bit| !bit));
    }

    #[test]
    fn test_bloom_filter_add_single_keyword() {
        let mut bf = BloomFilter::new();
        bf.add("test");

        assert!(bf.tau > 0);
        assert!(bf.tau <= 9); // max K_HASH_FUNCTIONS * max_windows for "test"
        assert!(bf.bits.iter().any(|&bit| bit));
    }

    #[test]
    fn test_bloom_filter_add_multiple_keywords() {
        let mut bf = BloomFilter::new();
        let keywords = vec!["apple", "banana", "cherry"];

        for keyword in &keywords {
            bf.add(keyword);
        }

        assert!(bf.tau > 0);
        let set_bits = bf.bits.iter().filter(|&&bit| bit).count();
        assert_eq!(set_bits, bf.tau);
    }

    #[test]
    fn test_bloom_filter_idempotency() {
        let mut bf1 = BloomFilter::new();
        let mut bf2 = BloomFilter::new();

        bf1.add("keyword");
        bf1.add("keyword"); // Add same keyword twice

        bf2.add("keyword"); // Add same keyword once

        // Should have similar tau values (allowing for some variation due to hashing)
        assert_eq!(bf1.bits, bf2.bits);
        assert_eq!(bf1.tau, bf2.tau);
    }

    #[test]
    fn test_bloom_filter_sliding_window_short_strings() {
        let mut bf = BloomFilter::new();
        bf.add("a"); // Single character
        assert!(bf.tau > 0);

        let mut bf2 = BloomFilter::new();
        bf2.add(""); // Empty string
        assert_eq!(bf2.tau, 0);
    }

    #[test]
    fn test_bloom_filter_encryption_preserves_structure() {
        let (pk, sk) = generate_keypair(512);
        let mut bf = BloomFilter::new();
        bf.add("test");
        bf.add("encryption");

        let encrypted_bf = bf.encrypt(&pk);
        assert_eq!(encrypted_bf.bits.len(), bf.bits.len());
        assert_eq!(encrypted_bf.tau, bf.tau);

        let decrypted_bits = encrypted_bf.decrypt(&sk, &pk);
        assert_eq!(decrypted_bits.len(), bf.bits.len());

        for (i, &original_bit) in bf.bits.iter().enumerate() {
            assert_eq!(decrypted_bits[i], if original_bit { 1 } else { 0 });
        }
    }
}

mod paillier_tests {
    use super::*;

    #[test]
    fn test_paillier_key_generation() {
        let (pk, sk) = generate_keypair(512);

        // Basic properties of generated keys
        assert!(pk.n > BigUint::from(0u32));
        assert!(pk.n_squared > pk.n);
        assert!(pk.g > BigUint::from(0u32));
        assert!(sk.lambda > BigUint::from(0u32));
        assert!(sk.mu > BigUint::from(0u32));
    }

    #[test]
    fn test_paillier_encryption_decryption_zero_one() {
        let (pk, sk) = generate_keypair(512);

        // Test with 0
        let m0 = BigUint::from(0u32);
        let c0 = encrypt_paillier(&m0, &pk);
        let d0 = decrypt_paillier(&c0, &sk, &pk);
        assert_eq!(d0, m0);

        // Test with 1
        let m1 = BigUint::from(1u32);
        let c1 = encrypt_paillier(&m1, &pk);
        let d1 = decrypt_paillier(&c1, &sk, &pk);
        assert_eq!(d1, m1);
    }

    #[test]
    fn test_paillier_encryption_randomness() {
        let (pk, sk) = generate_keypair(512);
        let m = BigUint::from(42u32);

        // Encrypt same message multiple times
        let c1 = encrypt_paillier(&m, &pk);
        let c2 = encrypt_paillier(&m, &pk);
        let c3 = encrypt_paillier(&m, &pk);

        // Ciphertexts should be different (probabilistic encryption)
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
        assert_ne!(c1, c3);

        // But all decrypt to the same plaintext
        assert_eq!(decrypt_paillier(&c1, &sk, &pk), m);
        assert_eq!(decrypt_paillier(&c2, &sk, &pk), m);
        assert_eq!(decrypt_paillier(&c3, &sk, &pk), m);
    }

    #[test]
    fn test_paillier_homomorphic_addition() {
        let (pk, sk) = generate_keypair(512);

        let m1 = BigUint::from(15u32);
        let m2 = BigUint::from(27u32);
        let expected_sum = &m1 + &m2;

        let c1 = encrypt_paillier(&m1, &pk);
        let c2 = encrypt_paillier(&m2, &pk);
        let c_sum = add_homomorphic(&c1, &c2, &pk);

        let decrypted_sum = decrypt_paillier(&c_sum, &sk, &pk);
        assert_eq!(decrypted_sum, expected_sum);
    }

    #[test]
    fn test_paillier_homomorphic_multiplication() {
        let (pk, sk) = generate_keypair(512);

        let m = BigUint::from(7u32);
        let k = BigUint::from(5u32);
        let expected_product = &m * &k;

        let c = encrypt_paillier(&m, &pk);
        let c_mul = mul_homomorphic(&c, &k, &pk);

        let decrypted_product = decrypt_paillier(&c_mul, &sk, &pk);
        assert_eq!(decrypted_product, expected_product);
    }

    #[test]
    fn test_paillier_bloom_filter_operations() {
        let (pk, sk) = generate_keypair(512);

        // Test all possible bit combinations for bloom filter
        let test_cases = vec![
            (0u8, 0u8, 0u8), // 0 + 0 = 0
            (0u8, 1u8, 1u8), // 0 + 1 = 1
            (1u8, 0u8, 1u8), // 1 + 0 = 1
            (1u8, 1u8, 2u8), // 1 + 1 = 2
        ];

        for (bit1, bit2, expected_sum) in test_cases {
            let c1 = encrypt_paillier(&BigUint::from(bit1), &pk);
            let c2 = encrypt_paillier(&BigUint::from(bit2), &pk);
            let c_sum = add_homomorphic(&c1, &c2, &pk);

            let decrypted = decrypt_paillier(&c_sum, &sk, &pk);
            assert_eq!(decrypted, BigUint::from(expected_sum));
        }
    }
}

mod symmetric_encryption_tests {
    use super::*;

    #[test]
    fn test_symmetric_key_generation() {
        let key1 = SymmetricKey::new();
        let key2 = SymmetricKey::new();

        // Keys should be different (statistically very unlikely to be same)
        // We can't directly compare them, so we test encryption produces different
        // results
        let plaintext = b"test message";
        let (ct1, _) = key1.encrypt(plaintext).unwrap();
        let (ct2, _) = key2.encrypt(plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_symmetric_encryption_decryption() {
        let key = SymmetricKey::new();
        let plaintext = b"This is a test message for AES-GCM encryption.";

        let (ciphertext, nonce) = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_symmetric_encryption_empty_message() {
        let key = SymmetricKey::new();
        let plaintext = b"";

        let (ciphertext, nonce) = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_symmetric_encryption_large_message() {
        let key = SymmetricKey::new();
        let plaintext = "A".repeat(10000).into_bytes();

        let (ciphertext, nonce) = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_symmetric_encryption_wrong_nonce_fails() {
        let key = SymmetricKey::new();
        let plaintext = b"test message";

        let (ciphertext, _) = key.encrypt(plaintext).unwrap();
        let (_, wrong_nonce) = key.encrypt(b"different message").unwrap();

        // Decryption with wrong nonce should fail
        let result = key.decrypt(&ciphertext, &wrong_nonce);
        assert!(result.is_err());
    }
}

mod os2_client_tests {
    use super::*;

    #[test]
    fn test_client_initialization() {
        let client = Os2Client::new();

        // Should be able to get public keys
        let pk1 = client.get_paillier_pk_for_server();
        let pk2 = client.get_paillier_pk_for_client_use();

        // Both should reference the same key
        assert_eq!(pk1.n, pk2.n);
        assert_eq!(pk1.n_squared, pk2.n_squared);
        assert_eq!(pk1.g, pk2.g);
    }

    #[test]
    fn test_document_outsourcing_basic() {
        let client = Os2Client::new();
        let doc_id = "test_doc";
        let content = "This is test content";
        let keywords = vec!["test", "content"];

        let encrypted_doc = client
            .outsource_document(doc_id, content, keywords)
            .unwrap();

        assert_eq!(encrypted_doc.id, doc_id);
        assert!(!encrypted_doc.encrypted_content.is_empty());
        assert!(encrypted_doc.encrypted_index.tau > 0);

        // Should be able to decrypt back to original content
        let decrypted = client.decrypt_document_content(&encrypted_doc).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_document_outsourcing_no_keywords() {
        let client = Os2Client::new();
        let encrypted_doc = client.outsource_document("doc", "content", vec![]).unwrap();

        // Should have tau = 0 when no keywords
        assert_eq!(encrypted_doc.encrypted_index.tau, 0);

        let decrypted = client.decrypt_document_content(&encrypted_doc).unwrap();
        assert_eq!(decrypted, "content");
    }

    #[test]
    fn test_query_generation() {
        let client = Os2Client::new();
        let keywords = vec!["search", "query", "test"];

        let query_bf = client.generate_query_bloom_filter(keywords);

        assert!(query_bf.tau > 0);
        assert_eq!(query_bf.bits.len(), 128); // BLOOM_FILTER_SIZE
    }

    #[test]
    fn test_query_generation_empty() {
        let client = Os2Client::new();
        let query_bf = client.generate_query_bloom_filter(vec![]);

        assert_eq!(query_bf.tau, 0);
        assert_eq!(query_bf.bits.len(), 128);
    }

    #[test]
    fn test_similarity_calculation_identical() {
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        let keywords = vec!["identical", "keywords"];
        let doc = client
            .outsource_document("doc", "content", keywords.clone())
            .unwrap();
        server.store_document(doc);

        let query_bf = client.generate_query_bloom_filter(keywords);
        let results = server.evaluate_query(&query_bf);

        assert_eq!(results.len(), 1);
        let similarity = client.process_search_result(&results[0].1);

        // Should have high similarity for identical keywords
        assert!(similarity >= 0.7);
    }

    #[test]
    fn test_similarity_calculation_no_overlap() {
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        let doc_keywords = vec!["completely", "different"];
        let query_keywords = vec!["totally", "unrelated"];

        let doc = client
            .outsource_document("doc", "content", doc_keywords)
            .unwrap();
        server.store_document(doc);

        let query_bf = client.generate_query_bloom_filter(query_keywords);
        let results = server.evaluate_query(&query_bf);

        assert_eq!(results.len(), 1);
        let similarity = client.process_search_result(&results[0].1);

        // Should have lower similarity for completely different keywords
        // Note: might not be 0 due to bloom filter false positives
        assert!(similarity <= 0.9);
    }
}

mod cloud_server_tests {
    use super::*;

    #[test]
    fn test_server_initialization() {
        let server = CloudServer::new();
        assert_eq!(server.stored_documents.len(), 0);
    }

    #[test]
    fn test_server_key_setup() {
        let mut server = CloudServer::new();
        let client = Os2Client::new();

        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // Server should now have the public key
        // We can't directly access it, but storing and querying should work
        let doc = client
            .outsource_document("test", "content", vec!["keyword"])
            .unwrap();
        server.store_document(doc);
        assert_eq!(server.stored_documents.len(), 1);
    }

    #[test]
    fn test_server_document_storage() {
        let mut server = CloudServer::new();
        let client = Os2Client::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        let docs = vec![
            client
                .outsource_document("doc1", "content1", vec!["key1"])
                .unwrap(),
            client
                .outsource_document("doc2", "content2", vec!["key2"])
                .unwrap(),
            client
                .outsource_document("doc3", "content3", vec!["key3"])
                .unwrap(),
        ];

        for doc in docs {
            server.store_document(doc);
        }

        assert_eq!(server.stored_documents.len(), 3);
    }

    #[test]
    fn test_server_query_evaluation() {
        let mut server = CloudServer::new();
        let client = Os2Client::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // Store multiple documents
        let docs = vec![
            ("doc1", vec!["machine", "learning"]),
            ("doc2", vec!["web", "development"]),
            ("doc3", vec!["data", "science"]),
        ];

        for (id, keywords) in &docs {
            let doc = client
                .outsource_document(id, "content", keywords.clone())
                .unwrap();
            server.store_document(doc);
        }

        let query_bf = client.generate_query_bloom_filter(vec!["machine", "learning"]);
        let results = server.evaluate_query(&query_bf);

        assert_eq!(results.len(), docs.len());

        // All results should have the same bloom filter size
        for (_, result_bf) in &results {
            assert_eq!(result_bf.bits.len(), 128);
        }
    }

    #[test]
    #[should_panic(expected = "Paillier PK not set on server")]
    fn test_server_query_without_key_panics() {
        let server = CloudServer::new();
        let client = Os2Client::new();

        let query_bf = client.generate_query_bloom_filter(vec!["test"]);
        let _ = server.evaluate_query(&query_bf);
    }
}

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_workflow_multiple_documents() {
        let client = Os2Client::new();
        let mut server = CloudServer::new();
        server.receive_paillier_pk(client.get_paillier_pk_for_server());

        // Create documents with overlapping keywords
        let documents = vec![
            (
                "doc1",
                "AI and machine learning research",
                vec!["ai", "machine", "learning", "research"],
            ),
            (
                "doc2",
                "Machine learning applications",
                vec!["machine", "learning", "applications"],
            ),
            (
                "doc3",
                "Deep learning neural networks",
                vec!["deep", "learning", "neural", "networks"],
            ),
            (
                "doc4",
                "Web development tutorial",
                vec!["web", "development", "tutorial"],
            ),
        ];

        for (id, content, keywords) in &documents {
            let doc = client
                .outsource_document(id, content, keywords.clone())
                .unwrap();
            server.store_document(doc);
        }

        // Query for machine learning documents
        let query_bf = client.generate_query_bloom_filter(vec!["machine", "learning"]);
        let results = server.evaluate_query(&query_bf);

        assert_eq!(results.len(), 4);

        // Calculate similarities and verify ranking
        let mut similarities: Vec<(String, f64)> = results
            .into_iter()
            .map(|(doc_id, result_bf)| {
                let similarity = client.process_search_result(&result_bf);
                (doc_id, similarity)
            })
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // doc1 and doc2 should have higher similarity than doc4
        let doc1_similarity = similarities.iter().find(|(id, _)| id == "doc1").unwrap().1;
        let doc2_similarity = similarities.iter().find(|(id, _)| id == "doc2").unwrap().1;
        let doc4_similarity = similarities.iter().find(|(id, _)| id == "doc4").unwrap().1;

        assert!(doc1_similarity > doc4_similarity);
        assert!(doc2_similarity > doc4_similarity);
    }

    #[test]
    fn test_edge_case_very_long_keywords() {
        let client = Os2Client::new();
        let long_keyword = "a".repeat(1000);
        let keywords = vec![long_keyword.as_str()];

        let doc = client
            .outsource_document("doc", "content", keywords)
            .unwrap();
        assert!(doc.encrypted_index.tau > 0);

        let decrypted = client.decrypt_document_content(&doc).unwrap();
        assert_eq!(decrypted, "content");
    }

    #[test]
    fn test_unicode_keyword_handling() {
        let client = Os2Client::new();
        let unicode_keywords = vec!["café", "naïve", "🚀", "日本語"];

        let doc = client
            .outsource_document("unicode_doc", "Unicode content", unicode_keywords)
            .unwrap();
        assert!(doc.encrypted_index.tau > 0);

        let decrypted = client.decrypt_document_content(&doc).unwrap();
        assert_eq!(decrypted, "Unicode content");
    }
}
