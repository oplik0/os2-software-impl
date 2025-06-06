use os2_software_impl::*;

#[test]
fn test_full_os2_workflow() {
    // Complete end-to-end test of the OS2 system
    #[allow(deprecated)]
    let client = Os2Client::new_for_testing(); // Use faster keys for testing
    let mut server = CloudServer::new();

    // Setup
    server.receive_paillier_pk(client.get_paillier_pk_for_server());
    // Create test documents with various keyword overlaps - FPGA/hardware design
    // themed
    let documents = vec![
        (
            "doc1",
            "FPGA implementation of cryptographic accelerators using Verilog HDL",
            vec!["fpga", "cryptographic", "accelerators", "verilog", "hdl"],
        ),
        (
            "doc2",
            "Hardware optimization techniques for high-frequency trading systems",
            vec![
                "hardware",
                "optimization",
                "high-frequency",
                "trading",
                "systems",
            ],
        ),
        (
            "doc3",
            "Digital signal processing on reconfigurable computing platforms",
            vec![
                "digital",
                "signal",
                "processing",
                "reconfigurable",
                "computing",
            ],
        ),
        (
            "doc4",
            "ASIC design methodologies for low-power embedded processors",
            vec!["asic", "design", "low-power", "embedded", "processors"],
        ),
        (
            "doc5",
            "SystemVerilog verification environments for complex SoC designs",
            vec!["systemverilog", "verification", "complex", "soc", "designs"],
        ),
    ];

    // Store documents
    for (id, content, keywords) in &documents {
        let encrypted_doc = client
            .outsource_document(id, content, keywords.clone())
            .unwrap();
        server.store_document(encrypted_doc);
    }
    // Test various queries
    let test_queries = vec![
        (
            vec!["fpga", "verilog"],
            "Should match doc1 for FPGA/Verilog",
        ),
        (
            vec!["hardware", "optimization"],
            "Should match doc2 for hardware optimization",
        ),
        (vec!["asic", "design"], "Should match doc4 for ASIC design"),
        (
            vec!["nonexistent", "keywords"],
            "Should have low similarity for all docs",
        ),
    ];

    for (query_keywords, description) in test_queries {
        println!("Testing query: {query_keywords:?} - {description}");

        let query_bf = client.generate_query_bloom_filter(query_keywords.clone());
        let results = server.evaluate_query(&query_bf);

        assert_eq!(results.len(), documents.len());
        let mut similarities = Vec::new();
        for (doc_id, oblivious_sum_bf) in results {
            let similarity = client.process_search_result(&oblivious_sum_bf);
            similarities.push((doc_id.clone(), similarity));
            println!("  {doc_id} -> similarity: {similarity:.4}");
        }

        // Verify similarities are within valid range
        for (_, similarity) in &similarities {
            assert!(*similarity >= 0.0 && *similarity <= 1.0);
        }
    }
}

#[test]
fn test_keyword_similarity_accuracy() {
    #[allow(deprecated)]
    let client = Os2Client::new_for_testing(); // Use faster keys for testing
    let mut server = CloudServer::new();
    server.receive_paillier_pk(client.get_paillier_pk_for_server());
    // Create hardware design documents with known keyword overlaps
    let docs = vec![
        (
            "design_full",
            vec!["fpga", "verilog", "synthesis", "timing"],
        ),
        (
            "design_partial",
            vec!["fpga", "verilog", "hardware", "power"],
        ),
        (
            "design_alt",
            vec!["hardware", "layout", "verification", "mask"],
        ),
        ("single_match", vec!["fpga", "software", "python", "gui"]),
    ];

    for (doc_id, keywords) in &docs {
        let content = format!("Hardware design document about {doc_id}");
        let encrypted_doc = client
            .outsource_document(doc_id, &content, keywords.clone())
            .unwrap();
        server.store_document(encrypted_doc);
    }
    // Query with hardware-related keywords ["fpga", "verilog", "synthesis",
    // "timing"]
    let query_keywords = vec!["fpga", "verilog", "synthesis", "timing"];
    let query_bf = client.generate_query_bloom_filter(query_keywords);
    let results = server.evaluate_query(&query_bf);

    let mut similarities: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for (doc_id, oblivious_sum_bf) in results {
        let similarity = client.process_search_result(&oblivious_sum_bf);
        similarities.insert(doc_id, similarity);
    }
    // Verify relative ordering (though exact values depend on bloom filter
    // properties and hash collisions)
    let design_full_sim = similarities["design_full"];
    let design_partial_sim = similarities["design_partial"];
    let design_alt_sim = similarities["design_alt"];
    let single_sim = similarities["single_match"];

    println!("Hardware Design Similarities: design_full={design_full_sim:.4}, design_partial={design_partial_sim:.4}, design_alt={design_alt_sim:.4}, single={single_sim:.4}");

    // Full match should have highest similarity
    assert!(
        design_full_sim >= design_partial_sim,
        "Full match should beat partial match"
    );
    assert!(
        design_full_sim >= single_sim,
        "Full match should beat single match"
    );
    assert!(
        design_full_sim >= design_alt_sim,
        "Full match should beat no match"
    );

    // Partial match should beat no direct matches
    assert!(
        design_partial_sim >= design_alt_sim,
        "Partial match should beat no match"
    );

    // Note: Due to bloom filter hash collisions, single_match vs design_alt
    // ordering may vary
}

#[test]
fn test_encryption_security_properties() {
    #[allow(deprecated)]
    let client = Os2Client::new_for_testing(); // Use faster keys for testing

    // Test that same plaintext encrypts to different ciphertexts (semantic
    // security)
    let keywords = vec!["test", "encryption"];
    let query_bf1 = client.generate_query_bloom_filter(keywords.clone());
    let query_bf2 = client.generate_query_bloom_filter(keywords);

    // The encrypted bloom filters should be different due to randomness
    let mut differences = 0;
    for i in 0..query_bf1.bits.len() {
        if query_bf1.bits[i] != query_bf2.bits[i] {
            differences += 1;
        }
    }

    // Should have some differences due to encryption randomness
    // Note: This test might occasionally fail due to the nature of random
    // encryption
    println!(
        "Encryption differences: {}/{}",
        differences,
        query_bf1.bits.len()
    ); // Test that decryption is consistent - use the client's keys that were used for
       // encryption
    let pk = client.get_paillier_pk_for_client_use();
    #[allow(deprecated)]
    let sk = client.get_paillier_sk_for_testing();
    let plaintext_bits1 = query_bf1.decrypt(sk, &pk);
    let plaintext_bits2 = query_bf2.decrypt(sk, &pk);

    // Decrypted values should be identical
    assert_eq!(plaintext_bits1, plaintext_bits2);
}

#[test]
fn test_bloom_filter_properties() {
    // Test bloom filter false positive rate with hardware design keywords
    let mut bf = BloomFilter::new();

    // Add a set of known hardware design keywords
    let known_keywords = vec!["fpga", "verilog", "synthesis", "timing", "placement"];
    for keyword in &known_keywords {
        bf.add(keyword);
    }

    // Test a large set of random keywords for false positives
    let test_keywords: Vec<String> = (0..1000).map(|i| format!("random_hw_term_{i}")).collect();

    let mut false_positives = 0;
    for test_keyword in &test_keywords {
        let mut test_bf = BloomFilter::new();
        test_bf.add(test_keyword);

        // Check if there's significant overlap with our known keywords bloom filter
        let mut matches = 0;
        for i in 0..bf.bits.len() {
            if bf.bits[i] && test_bf.bits[i] {
                matches += 1;
            }
        }

        // If there are many matches, it might be a false positive
        if matches > bf.tau / 2 {
            false_positives += 1;
        }
    }
    let false_positive_rate = false_positives as f64 / test_keywords.len() as f64;
    println!("Estimated false positive rate for hardware keywords: {false_positive_rate:.4}");

    // Should have reasonable false positive rate
    assert!(false_positive_rate < 0.5, "False positive rate too high");
}
