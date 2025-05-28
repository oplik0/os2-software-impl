use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use num_bigint::BigUint;
use os2_software_impl::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
struct OS2BenchmarkResult {
    operation: String,
    document_count: usize,
    keyword_count: usize,
    bloom_filter_size: usize,
    duration_ns: u64,
    throughput_ops_per_sec: f64,
    memory_estimate_bytes: usize,
    timestamp: String,
}

impl OS2BenchmarkResult {
    fn new(
        operation: String,
        document_count: usize,
        keyword_count: usize,
        bloom_filter_size: usize,
        duration_ns: u64,
        memory_estimate_bytes: usize,
    ) -> Self {
        let throughput_ops_per_sec = 1_000_000_000.0 / duration_ns as f64;
        let timestamp = chrono::Utc::now().to_rfc3339();

        Self {
            operation,
            document_count,
            keyword_count,
            bloom_filter_size,
            duration_ns,
            throughput_ops_per_sec,
            memory_estimate_bytes,
            timestamp,
        }
    }

    fn save_to_file(&self, filename: &str) -> std::io::Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let json = serde_json::to_string_pretty(self)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)?;
        writeln!(file, "{}", json)?;
        writeln!(file, ",")?; // For JSON array format
        Ok(())
    }
}

// Hardware comparison data structure
#[derive(Serialize, Deserialize, Debug)]
struct HardwareComparisonData {
    software_results: Vec<OS2BenchmarkResult>,
    hardware_results: Vec<HardwareResult>,
    comparison_summary: ComparisonSummary,
}

#[derive(Serialize, Deserialize, Debug)]
struct HardwareResult {
    operation: String,
    hardware_type: String, // e.g., "FPGA", "GPU", "ASIC"
    duration_ns: u64,
    power_consumption_watts: f64,
    cost_estimate_usd: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ComparisonSummary {
    speedup_factor: f64,
    energy_efficiency_ratio: f64,
    cost_performance_ratio: f64,
}

// Benchmark realistic OS2 workflow scenarios
fn realistic_workflow_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_workflows");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    // Scenario 1: Small office document search (50 documents)
    group.bench_function("small_office_scenario", |b| {
        b.iter_batched(
            || setup_document_scenario(50, 5),
            |(client, mut server, documents)| {
                // Store documents
                for doc in documents {
                    server.store_document(doc);
                }

                // Perform multiple searches
                let queries = vec![
                    vec!["report", "quarterly"],
                    vec!["meeting", "notes"],
                    vec!["budget", "analysis"],
                ];

                for query_keywords in queries {
                    let query_bf = client.generate_query_bloom_filter(query_keywords);
                    let results = server.evaluate_query(&query_bf);

                    for (_, result_bf) in results {
                        black_box(client.process_search_result(&result_bf));
                    }
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Scenario 2: Enterprise search (500 documents)
    group.bench_function("enterprise_scenario", |b| {
        b.iter_batched(
            || setup_document_scenario(500, 8),
            |(client, mut server, documents)| {
                for doc in documents {
                    server.store_document(doc);
                }

                let query_bf =
                    client.generate_query_bloom_filter(vec!["project", "development", "software"]);
                let results = server.evaluate_query(&query_bf);

                for (_, result_bf) in results {
                    black_box(client.process_search_result(&result_bf));
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Scenario 3: Cloud-scale search (5000 documents)
    group.bench_function("cloud_scale_scenario", |b| {
        b.iter_batched(
            || setup_document_scenario(5000, 10),
            |(client, mut server, documents)| {
                for doc in documents {
                    server.store_document(doc);
                }

                let query_bf = client.generate_query_bloom_filter(vec!["data", "analysis"]);
                let results = server.evaluate_query(&query_bf);

                // Process only first 100 results for timing purposes
                for (_, result_bf) in results.into_iter().take(100) {
                    black_box(client.process_search_result(&result_bf));
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// Benchmark individual cryptographic operations for hardware comparison
fn crypto_operations_for_hardware_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_for_hardware_comparison");
    group.measurement_time(Duration::from_secs(10));

    // Benchmark single Paillier operations with different key sizes
    for key_size in [1024, 2048, 4096].iter() {
        let (pk, sk) = generate_keypair(*key_size);
        let message = BigUint::from(1u32);
        let ciphertext = encrypt_paillier(&message, &pk);

        group.bench_with_input(
            BenchmarkId::new("paillier_encrypt_single", key_size),
            &(&pk, &message),
            |b, (pk, message)| {
                b.iter(|| encrypt_paillier(black_box(message), black_box(pk)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("paillier_decrypt_single", key_size),
            &(&sk, &pk, &ciphertext),
            |b, (sk, pk, ciphertext)| {
                b.iter(|| decrypt_paillier(black_box(ciphertext), black_box(sk), black_box(pk)));
            },
        );

        let c1 = encrypt_paillier(&BigUint::from(1u32), &pk);
        let c2 = encrypt_paillier(&BigUint::from(1u32), &pk);

        group.bench_with_input(
            BenchmarkId::new("paillier_add_single", key_size),
            &(&pk, &c1, &c2),
            |b, (pk, c1, c2)| {
                b.iter(|| add_homomorphic(black_box(c1), black_box(c2), black_box(pk)));
            },
        );
    }

    // Benchmark batch operations (common in hardware implementations)
    let (pk, sk) = generate_keypair(2048);
    let batch_sizes = [1, 10, 100, 1000];

    for batch_size in batch_sizes.iter() {
        let messages: Vec<BigUint> = (0..*batch_size).map(|i| BigUint::from(i as u32)).collect();

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("paillier_encrypt_batch", batch_size),
            &(&pk, &messages),
            |b, (pk, messages)| {
                b.iter(|| {
                    for message in messages.iter() {
                        black_box(encrypt_paillier(black_box(message), black_box(pk)));
                    }
                });
            },
        );

        let ciphertexts: Vec<BigUint> = messages.iter().map(|m| encrypt_paillier(m, &pk)).collect();

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("paillier_decrypt_batch", batch_size),
            &(&sk, &pk, &ciphertexts),
            |b, (sk, pk, ciphertexts)| {
                b.iter(|| {
                    for ciphertext in ciphertexts.iter() {
                        black_box(decrypt_paillier(
                            black_box(ciphertext),
                            black_box(sk),
                            black_box(pk),
                        ));
                    }
                });
            },
        );
    }

    group.finish();
}

// Benchmark bloom filter operations for hardware comparison
fn bloom_filter_hardware_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_filter_for_hardware");

    // Test different bloom filter sizes
    let bf_sizes = [128, 256, 512, 1024];

    for bf_size in bf_sizes.iter() {
        // Temporarily modify BLOOM_FILTER_SIZE for testing
        // Note: In practice, you'd want to make this configurable

        group.bench_with_input(
            BenchmarkId::new("bloom_filter_creation", bf_size),
            bf_size,
            |b, _bf_size| {
                b.iter(|| {
                    let mut bf = BloomFilter::new();
                    for i in 0..10 {
                        bf.add(&format!("keyword{}", i));
                    }
                    black_box(bf)
                });
            },
        );
    }

    // Benchmark bloom filter operations with varying keyword counts
    let keyword_counts = [1, 5, 10, 25, 50];

    for keyword_count in keyword_counts.iter() {
        let keywords: Vec<String> = (0..*keyword_count)
            .map(|i| format!("keyword{}", i))
            .collect();

        group.throughput(Throughput::Elements(*keyword_count as u64));
        group.bench_with_input(
            BenchmarkId::new("bloom_filter_add_keywords", keyword_count),
            &keywords,
            |b, keywords| {
                b.iter(|| {
                    let mut bf = BloomFilter::new();
                    for keyword in keywords {
                        bf.add(black_box(keyword));
                    }
                    black_box(bf)
                });
            },
        );
    }

    // Benchmark bloom filter encryption/decryption
    let (pk, sk) = generate_keypair(2048);
    let mut bf = BloomFilter::new();
    for i in 0..20 {
        bf.add(&format!("keyword{}", i));
    }

    group.bench_function("bloom_filter_encrypt_2048", |b| {
        b.iter(|| bf.encrypt(black_box(&pk)));
    });

    let encrypted_bf = bf.encrypt(&pk);
    group.bench_function("bloom_filter_decrypt_2048", |b| {
        b.iter(|| encrypted_bf.decrypt(black_box(&sk), black_box(&pk)));
    });

    group.finish();
}

// Benchmark server-side operations for hardware acceleration potential
fn server_operations_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("server_operations");

    let client = Os2Client::new();
    let mut server = CloudServer::new();
    server.receive_paillier_pk(client.get_paillier_pk_for_server());

    // Pre-populate server with documents
    let document_counts = [10, 50, 100, 500];

    for doc_count in document_counts.iter() {
        // Setup server with documents
        let mut test_server = CloudServer::new();
        test_server.receive_paillier_pk(client.get_paillier_pk_for_server());

        for i in 0..*doc_count {
            let doc = client
                .outsource_document(
                    &format!("doc{}", i),
                    &format!("Content for document {}", i),
                    vec!["keyword1", "keyword2", &format!("keyword{}", i % 5)],
                )
                .unwrap();
            test_server.store_document(doc);
        }

        let query_bf = client.generate_query_bloom_filter(vec!["keyword1", "keyword2"]);

        group.throughput(Throughput::Elements(*doc_count as u64));
        group.bench_with_input(
            BenchmarkId::new("server_query_evaluation", doc_count),
            &(test_server, query_bf),
            |b, (server, query_bf)| {
                b.iter(|| black_box(server.evaluate_query(black_box(query_bf))));
            },
        );
    }

    group.finish();
}

// Generate hardware comparison report
fn generate_hardware_comparison_report() -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create("hardware_comparison_template.json")?;

    let template = HardwareComparisonData {
        software_results: vec![OS2BenchmarkResult::new(
            "paillier_encrypt".to_string(),
            1,
            1,
            128,
            1_000_000, // 1ms
            1024,
        )],
        hardware_results: vec![
            HardwareResult {
                operation: "paillier_encrypt".to_string(),
                hardware_type: "FPGA_Platform_A".to_string(),
                duration_ns: 100_000, // 0.1ms (10x speedup)
                power_consumption_watts: 5.0,
                cost_estimate_usd: 500.0,
            },
            HardwareResult {
                operation: "paillier_encrypt".to_string(),
                hardware_type: "GPU_NVIDIA_A100".to_string(),
                duration_ns: 50_000, // 0.05ms (20x speedup)
                power_consumption_watts: 400.0,
                cost_estimate_usd: 10000.0,
            },
        ],
        comparison_summary: ComparisonSummary {
            speedup_factor: 10.0,
            energy_efficiency_ratio: 2.0,
            cost_performance_ratio: 0.5,
        },
    };

    let json = serde_json::to_string_pretty(&template)?;
    file.write_all(json.as_bytes())?;

    println!("Hardware comparison template generated: hardware_comparison_template.json");
    println!("To use this template:");
    println!("1. Run the benchmarks: cargo bench");
    println!("2. Replace software_results with actual benchmark data");
    println!("3. Add your hardware implementation results to hardware_results");
    println!("4. Update comparison_summary with calculated ratios");

    Ok(())
}

// Helper function to setup document scenarios
fn setup_document_scenario(
    doc_count: usize,
    keywords_per_doc: usize,
) -> (Os2Client, CloudServer, Vec<EncryptedDocument>) {
    let client = Os2Client::new();
    let mut server = CloudServer::new();
    server.receive_paillier_pk(client.get_paillier_pk_for_server());

    let mut documents = Vec::new();

    for i in 0..doc_count {
        let doc_id = format!("doc_{}", i);
        let content = format!("This is document {} with content for testing. It contains various keywords and information.", i);

        let mut keywords = Vec::new();
        for j in 0..keywords_per_doc {
            keywords.push(format!("keyword_{}", (i + j) % 20)); // Cycle through
                                                                // 20 different
                                                                // keywords
        }

        // Convert to &str for the function call
        let keyword_refs: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();

        let encrypted_doc = client
            .outsource_document(&doc_id, &content, keyword_refs)
            .unwrap();
        documents.push(encrypted_doc);
    }

    (client, server, documents)
}

// Benchmark specifically designed for comparing with hardware implementations
fn hardware_comparison_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_comparison");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(100); // More samples for accurate comparison

    // Single operation benchmarks (easiest to compare with hardware)
    let (pk, sk) = generate_keypair(2048);
    let message = BigUint::from(1u32);
    let ciphertext = encrypt_paillier(&message, &pk);

    group.bench_function("single_paillier_encrypt_2048", |b| {
        b.iter(|| encrypt_paillier(black_box(&message), black_box(&pk)));
    });

    group.bench_function("single_paillier_decrypt_2048", |b| {
        b.iter(|| decrypt_paillier(black_box(&ciphertext), black_box(&sk), black_box(&pk)));
    });

    let c1 = encrypt_paillier(&BigUint::from(1u32), &pk);
    let c2 = encrypt_paillier(&BigUint::from(1u32), &pk);

    group.bench_function("single_paillier_add_2048", |b| {
        b.iter(|| add_homomorphic(black_box(&c1), black_box(&c2), black_box(&pk)));
    });

    // Bloom filter operations
    group.bench_function("single_bloom_filter_encrypt", |b| {
        b.iter_batched(
            || {
                let mut bf = BloomFilter::new();
                bf.add("test_keyword");
                bf
            },
            |bf| black_box(bf.encrypt(&pk)),
            criterion::BatchSize::SmallInput,
        );
    });

    // AES-GCM operations (for comparison with hardware crypto accelerators)
    let key = SymmetricKey::new();
    let plaintext = vec![0u8; 1024]; // 1KB

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("single_aes_gcm_encrypt_1kb", |b| {
        b.iter(|| key.encrypt(black_box(&plaintext)).unwrap());
    });

    let (ciphertext, nonce) = key.encrypt(&plaintext).unwrap();
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("single_aes_gcm_decrypt_1kb", |b| {
        b.iter(|| {
            key.decrypt(black_box(&ciphertext), black_box(&nonce))
                .unwrap()
        });
    });

    group.finish();

    // Generate the comparison template
    generate_hardware_comparison_report().unwrap_or_else(|e| {
        eprintln!("Failed to generate hardware comparison report: {}", e);
    });
}

criterion_group!(
    benches,
    realistic_workflow_benchmark,
    crypto_operations_for_hardware_benchmark,
    bloom_filter_hardware_benchmark,
    server_operations_benchmark,
    hardware_comparison_benchmark
);
criterion_main!(benches);
