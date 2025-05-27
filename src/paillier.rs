use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;

/// Public key for Paillier encryption
#[derive(Debug, Clone)]
pub struct PaillierPk {
    pub n: BigUint,
    pub n_squared: BigUint,
    pub g: BigUint,
}

/// Private key for Paillier decryption
#[derive(Debug, Clone)]
pub struct PaillierSk {
    pub lambda: BigUint,
    pub mu: BigUint,
}

/// Simple prime generation for demonstration (not cryptographically secure for production)
fn generate_prime(bit_size: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let candidate = rng.gen_biguint(bit_size.try_into().unwrap()) | (BigUint::one() << (bit_size - 1)) | BigUint::one();
        if is_probably_prime(&candidate, 20) {
            return candidate;
        }
    }
}

/// Miller-Rabin primality test (simplified)
fn is_probably_prime(n: &BigUint, k: u32) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as d * 2^r
    let n_minus_one = n - BigUint::one();
    let mut d = n_minus_one.clone();
    let mut r = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = thread_rng();
    'outer: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::from(2u32)));
        let mut x = a.modpow(&d, n);
        
        if x == BigUint::one() || x == n_minus_one {
            continue 'outer;
        }
        
        for _ in 0..r-1 {
            x = (&x * &x) % n;
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// Generate a Paillier key pair with given bit size
pub fn generate_keypair(bit_size: usize) -> (PaillierPk, PaillierSk) {
    // Generate two distinct large primes p and q
    let p = generate_prime(bit_size / 2);
    let mut q = generate_prime(bit_size / 2);
    while q == p {
        q = generate_prime(bit_size / 2);
    }

    let n = &p * &q;
    let n_squared = &n * &n;
    let g = &n + BigUint::one();

    // lambda = lcm(p-1, q-1)
    let p1 = &p - BigUint::one();
    let q1 = &q - BigUint::one();
    let lambda = p1.lcm(&q1);    // mu = (L(g^lambda mod n^2))^{-1} mod n
    let u = g.modpow(&lambda, &n_squared);
    let l = (&u - BigUint::one()) / &n;
    
    // Simple modular inverse using Fermat's little theorem (works when n is prime)
    // For composite n, we use extended Euclidean algorithm
    fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        // Extended Euclidean Algorithm
        if a.is_zero() {
            return None;
        }
        
        let mut old_r = a.clone();
        let mut r = m.clone();
        let mut old_s = BigUint::one();
        let mut s = BigUint::zero();
        
        while !r.is_zero() {
            let quotient = &old_r / &r;
            let new_r = &old_r - &quotient * &r;
            old_r = r.clone();
            r = new_r;
            
            let new_s = if &quotient * &s <= old_s {
                &old_s - &quotient * &s
            } else {
                m - ((&quotient * &s - &old_s) % m)
            };
            old_s = s.clone();
            s = new_s;
        }
        
        if old_r == BigUint::one() {
            Some(old_s % m)
        } else {
            None
        }
    }
    
    let mu = mod_inverse(&l, &n).expect("Mu inverse should exist");

    (
        PaillierPk { n: n.clone(), n_squared: n_squared.clone(), g },
        PaillierSk { lambda, mu },
    )
}

/// Encrypt a plaintext m (0 <= m < n) under pk, returns ciphertext c in Z_{n^2}
pub fn encrypt_paillier(m: &BigUint, pk: &PaillierPk) -> BigUint {
    let mut rng = thread_rng();
    // choose random r in [1, n) with gcd(r, n) = 1
    let mut r = rng.gen_biguint_range(&BigUint::one(), &pk.n);
    while r.gcd(&pk.n) != BigUint::one() {
        r = rng.gen_biguint_range(&BigUint::one(), &pk.n);
    }
    // c = g^m * r^n mod n^2
    let gm = pk.g.modpow(m, &pk.n_squared);
    let rn = r.modpow(&pk.n, &pk.n_squared);
    (&gm * &rn) % &pk.n_squared
}

/// Decrypt ciphertext c under keys sk and pk, returns plaintext m
pub fn decrypt_paillier(c: &BigUint, sk: &PaillierSk, pk: &PaillierPk) -> BigUint {
    let u = c.modpow(&sk.lambda, &pk.n_squared);
    let l = (&u - BigUint::one()) / &pk.n;
    (&l * &sk.mu) % &pk.n
}

/// Homomorphic addition: given two ciphertexts c1 = E(m1), c2 = E(m2), returns E(m1 + m2)
pub fn add_homomorphic(c1: &BigUint, c2: &BigUint, pk: &PaillierPk) -> BigUint {
    // c1 * c2 mod n^2
    (c1 * c2) % &pk.n_squared
}

/// Homomorphic multiplication by constant: returns E(m * k)
pub fn mul_homomorphic(c: &BigUint, k: &BigUint, pk: &PaillierPk) -> BigUint {
    // c^k mod n^2
    c.modpow(k, &pk.n_squared)
}