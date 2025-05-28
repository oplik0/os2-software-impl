use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use num_bigint::BigUint;
use os2_software_impl::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
struct BenchmarkResults {
    operation: String,
    key_size: usize,
    duration_ns: u64,
    throughput_ops_per_sec: f64,
    timestamp: String,
}

impl BenchmarkResults {
    #[allow(dead_code)]
    fn new(operation: String, key_size: usize, duration_ns: u64) -> Self {
        let throughput_ops_per_sec = 1_000_000_000.0 / duration_ns as f64;
        let timestamp = chrono::Utc::now().to_rfc3339();

        Self {
            operation,
            key_size,
            duration_ns,
            throughput_ops_per_sec,
            timestamp,
        }
    }

    #[allow(dead_code)]
    fn save_to_file(&self, filename: &str) -> std::io::Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let json = serde_json::to_string(self)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)?;
        writeln!(file, "{json}")?;
        Ok(())
    }
}

// Benchmark Paillier key generation for different key sizes
fn paillier_keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("paillier_keygen");

    for key_size in [512, 1024, 2048].iter() {
        group.bench_with_input(
            BenchmarkId::new("generate_keypair", key_size),
            key_size,
            |b, &key_size| {
                b.iter(|| {
                    let (pk, sk) = generate_keypair(black_box(key_size));
                    black_box((pk, sk))
                });
            },
        );
    }
    group.finish();
}

// Benchmark Paillier encryption for different key sizes and message sizes
fn paillier_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("paillier_encryption");

    // Pre-generate keys for different sizes
    let keys_512 = generate_keypair(512);
    let keys_1024 = generate_keypair(1024);
    let keys_2048 = generate_keypair(2048);

    let test_messages = [
        BigUint::from(0u32),
        BigUint::from(1u32),
        BigUint::from(255u32),
        BigUint::from(65535u32),
    ];

    for (key_size, (pk, _)) in [(512, &keys_512), (1024, &keys_1024), (2048, &keys_2048)].iter() {
        for (msg_idx, message) in test_messages.iter().enumerate() {
            group.bench_with_input(
                BenchmarkId::new(format!("encrypt_{key_size}bit"), msg_idx),
                &(pk, message),
                |b, (pk, message)| {
                    b.iter(|| encrypt_paillier(black_box(message), black_box(pk)));
                },
            );
        }
    }
    group.finish();
}

// Benchmark Paillier decryption
fn paillier_decryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("paillier_decryption");

    let keys_512 = generate_keypair(512);
    let keys_1024 = generate_keypair(1024);
    let keys_2048 = generate_keypair(2048);

    let test_message = BigUint::from(42u32);

    for (key_size, (pk, sk)) in [(512, &keys_512), (1024, &keys_1024), (2048, &keys_2048)].iter() {
        let ciphertext = encrypt_paillier(&test_message, pk);

        group.bench_with_input(
            BenchmarkId::new("decrypt", key_size),
            &(sk, pk, &ciphertext),
            |b, (sk, pk, ciphertext)| {
                b.iter(|| decrypt_paillier(black_box(ciphertext), black_box(sk), black_box(pk)));
            },
        );
    }
    group.finish();
}

// Benchmark homomorphic operations
fn paillier_homomorphic_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("paillier_homomorphic");

    let (pk, _sk) = generate_keypair(1024);
    let m1 = BigUint::from(123u32);
    let m2 = BigUint::from(456u32);
    let c1 = encrypt_paillier(&m1, &pk);
    let c2 = encrypt_paillier(&m2, &pk);
    let scalar = BigUint::from(5u32);

    group.bench_function("homomorphic_addition", |b| {
        b.iter(|| add_homomorphic(black_box(&c1), black_box(&c2), black_box(&pk)));
    });

    group.bench_function("homomorphic_scalar_multiplication", |b| {
        b.iter(|| mul_homomorphic(black_box(&c1), black_box(&scalar), black_box(&pk)));
    });

    group.finish();
}

// Benchmark bloom filter operations
fn bloom_filter_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_filter");

    // Benchmark bloom filter creation and keyword addition
    group.bench_function("create_empty", |b| {
        b.iter(BloomFilter::new);
    });

    let keywords = vec!["apple", "banana", "cherry", "date", "elderberry"];
    group.bench_function("add_keywords", |b| {
        b.iter(|| {
            let mut bf = BloomFilter::new();
            for keyword in &keywords {
                bf.add(black_box(keyword));
            }
            black_box(bf)
        });
    });

    // Benchmark bloom filter encryption
    let (pk, sk) = generate_keypair(1024);
    let mut bf = BloomFilter::new();
    for keyword in &keywords {
        bf.add(keyword);
    }

    group.bench_function("encrypt_bloom_filter", |b| {
        b.iter(|| bf.encrypt(black_box(&pk)));
    });

    let encrypted_bf = bf.encrypt(&pk);
    group.bench_function("decrypt_bloom_filter", |b| {
        b.iter(|| encrypted_bf.decrypt(black_box(&sk), black_box(&pk)));
    });

    group.finish();
}

// Benchmark AES-GCM symmetric encryption
fn symmetric_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric_encryption");

    let key = SymmetricKey::new();
    let plaintexts = [
        vec![0u8; 16],     // 16 bytes
        vec![0u8; 256],    // 256 bytes
        vec![0u8; 1024],   // 1KB
        vec![0u8; 10240],  // 10KB
        vec![0u8; 102400], // 100KB
    ];

    for (size_name, plaintext) in [
        ("16B", &plaintexts[0]),
        ("256B", &plaintexts[1]),
        ("1KB", &plaintexts[2]),
        ("10KB", &plaintexts[3]),
        ("100KB", &plaintexts[4]),
    ]
    .iter()
    {
        group.throughput(Throughput::Bytes(plaintext.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", size_name),
            plaintext,
            |b, plaintext| {
                b.iter(|| key.encrypt(black_box(plaintext)).unwrap());
            },
        );

        let (ciphertext, nonce) = key.encrypt(plaintext).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", size_name),
            &(ciphertext, nonce),
            |b, (ciphertext, nonce)| {
                b.iter(|| {
                    key.decrypt(black_box(ciphertext), black_box(nonce))
                        .unwrap()
                });
            },
        );
    }

    group.finish();
}

// Benchmark hash function performance (used in bloom filters)
fn hash_performance_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_performance");

    use sha2::{Digest, Sha256};

    let inputs = [
        vec![0u8; 2],    // Sliding window size
        vec![0u8; 16],   // Small input
        vec![0u8; 256],  // Medium input
        vec![0u8; 1024], // Large input
    ];

    for (size_name, input) in [
        ("2B", &inputs[0]),
        ("16B", &inputs[1]),
        ("256B", &inputs[2]),
        ("1KB", &inputs[3]),
    ]
    .iter()
    {
        group.throughput(Throughput::Bytes(input.len() as u64));

        group.bench_with_input(BenchmarkId::new("sha256", size_name), input, |b, input| {
            b.iter(|| {
                let mut hasher = Sha256::default();
                hasher.update(black_box(input));
                black_box(hasher.finalize())
            });
        });
    }

    group.finish();
}

// End-to-end benchmark measuring complete OS2 operations
fn end_to_end_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    // Document outsourcing benchmark
    group.bench_function("document_outsourcing", |b| {
        b.iter_batched(
            || {
                let client = Os2Client::new();
                let content = "This is a test document with some content for benchmarking.";
                let keywords = vec!["test", "document", "benchmark", "content"];
                (client, content, keywords)
            },
            |(client, content, keywords)| {
                black_box(
                    client
                        .outsource_document("doc1", content, keywords)
                        .unwrap(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Query generation benchmark
    group.bench_function("query_generation", |b| {
        b.iter_batched(
            || {
                let client = Os2Client::new();
                let keywords = vec!["search", "query", "test"];
                (client, keywords)
            },
            |(client, keywords)| black_box(client.generate_query_bloom_filter(keywords)),
            criterion::BatchSize::SmallInput,
        );
    });

    // Server query evaluation benchmark
    group.bench_function("server_query_evaluation", |b| {
        b.iter_batched(
            || {
                let client = Os2Client::new();
                let mut server = CloudServer::new();
                server.receive_paillier_pk(client.get_paillier_pk_for_server());

                // Store 5 documents
                for i in 0..5 {
                    let doc = client
                        .outsource_document(
                            &format!("doc{i}"),
                            &format!("Content for document {i}"),
                            vec!["keyword1", "keyword2", &format!("keyword{i}")],
                        )
                        .unwrap();
                    server.store_document(doc);
                }

                let query_bf = client.generate_query_bloom_filter(vec!["keyword1", "keyword2"]);
                (server, query_bf)
            },
            |(server, query_bf)| black_box(server.evaluate_query(&query_bf)),
            criterion::BatchSize::SmallInput,
        );
    });

    // Result processing benchmark
    group.bench_function("result_processing", |b| {
        b.iter_batched(
            || {
                let client = Os2Client::new();
                let mut server = CloudServer::new();
                server.receive_paillier_pk(client.get_paillier_pk_for_server());

                let doc = client
                    .outsource_document("doc1", "Test content", vec!["test", "content"])
                    .unwrap();
                server.store_document(doc);

                let query_bf = client.generate_query_bloom_filter(vec!["test", "content"]);
                let results = server.evaluate_query(&query_bf);
                (client, results[0].1.clone())
            },
            |(client, oblivious_sum_bf)| black_box(client.process_search_result(&oblivious_sum_bf)),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// Scalability benchmark - how performance changes with increasing data sizes
fn scalability_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for doc_count in [1, 5, 10, 25, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("query_evaluation_scale", doc_count),
            doc_count,
            |b, &doc_count| {
                b.iter_batched(
                    || {
                        let client = Os2Client::new();
                        let mut server = CloudServer::new();
                        server.receive_paillier_pk(client.get_paillier_pk_for_server());

                        // Store documents
                        for i in 0..doc_count {
                            let doc = client
                                .outsource_document(
                                    &format!("doc{i}"),
                                    &format!("Content for document {i}"),
                                    vec!["keyword1", "keyword2", &format!("keyword{}", i % 3)],
                                )
                                .unwrap();
                            server.store_document(doc);
                        }

                        let query_bf = client.generate_query_bloom_filter(vec!["keyword1"]);
                        (client, server, query_bf)
                    },
                    |(client, server, query_bf)| {
                        let results = server.evaluate_query(&query_bf);
                        // Also measure result processing time
                        for (_, result_bf) in results {
                            black_box(client.process_search_result(&result_bf));
                        }
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// Memory usage benchmark - measure memory consumption patterns
fn memory_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Benchmark memory usage of encrypted bloom filters
    group.bench_function("encrypted_bloom_filter_memory", |b| {
        b.iter_batched(
            || {
                let (pk, _) = generate_keypair(1024);
                let mut bf = BloomFilter::new();
                for i in 0..50 {
                    bf.add(&format!("keyword{i}"));
                }
                (bf, pk)
            },
            |(bf, pk)| {
                // This measures the time to create the encrypted structure
                // which correlates with memory allocation
                black_box(bf.encrypt(&pk))
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark memory usage of storing multiple documents
    group.bench_function("document_storage_memory", |b| {
        b.iter_batched(
            || {
                let client = Os2Client::new();
                let mut documents = Vec::new();
                for i in 0..10 {
                    let doc = client
                        .outsource_document(
                            &format!("doc{i}"),
                            &format!("Large content for document {i} {}", "x".repeat(1000)),
                            vec!["keyword1", "keyword2", &format!("keyword{i}")],
                        )
                        .unwrap();
                    documents.push(doc);
                }
                documents
            },
            |documents| {
                let mut server = CloudServer::new();
                for doc in documents {
                    server.store_document(doc);
                }
                black_box(server)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    paillier_keygen_benchmark,
    paillier_encryption_benchmark,
    paillier_decryption_benchmark,
    paillier_homomorphic_benchmark,
    bloom_filter_benchmark,
    symmetric_encryption_benchmark,
    hash_performance_benchmark,
    end_to_end_benchmark,
    scalability_benchmark,
    memory_benchmark
);
criterion_main!(benches);
