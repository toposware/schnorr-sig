// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand_core::{OsRng, RngCore};

extern crate schnorr_sig;
use schnorr_sig::{
    ExtendedPrivateKey, ExtendedPublicKey, KeyPair, PrivateKey, PublicKey, PRIVATE_KEY_SEED_LENGTH,
};

// The byte lengths correspond to 1, 10 and 20 `Fp` elements.
static MESSAGE_LENGTHS: [usize; 3] = [8, 80, 160];

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng;
    let skey = PrivateKey::new(&mut rng);
    let keypair = KeyPair::new(&mut rng);
    let mut seed = [0u8; PRIVATE_KEY_SEED_LENGTH];
    rng.fill_bytes(&mut seed);
    let ext_skey = ExtendedPrivateKey::generate_master_key(&seed).unwrap();
    let ext_pkey = ExtendedPublicKey::from_extended_private_key(&ext_skey);
    let mut i = [0u8; 4];
    rng.fill_bytes(&mut i);
    i[3] &= 0b0111_1111;

    c.bench_function("Create keypair", |bench| {
        bench.iter(|| KeyPair::new(&mut rng))
    });

    c.bench_function("Public key from private key", |bench| {
        let skey = PrivateKey::new(&mut rng);
        bench.iter(|| PublicKey::from(&skey))
    });

    let sign_str = "Sign with private key - ".to_string();
    for &length in MESSAGE_LENGTHS.iter() {
        let name = sign_str.clone() + &length.to_string() + " Fp elements";
        c.bench_function(&name, |bench| {
            let mut message = vec![0u8; length];
            rng.fill_bytes(&mut message);
            bench.iter(|| skey.sign(&message, &mut rng))
        });
    }

    let sign_str = "Sign with keypair - ".to_string();
    for &length in MESSAGE_LENGTHS.iter() {
        let name = sign_str.clone() + &length.to_string() + " Fp elements";
        c.bench_function(&name, |bench| {
            let mut message = vec![0u8; length];
            rng.fill_bytes(&mut message);
            bench.iter(|| keypair.sign(&message, &mut rng))
        });
    }

    let sign_str = "Verify - ".to_string();
    for &length in MESSAGE_LENGTHS.iter() {
        let name = sign_str.clone() + &length.to_string() + " Fp elements";
        c.bench_function(&name, |bench| {
            let mut message = vec![0u8; length];
            rng.fill_bytes(&mut message);
            let signature = keypair.sign(&message, &mut rng);
            bench.iter(|| signature.verify(&message, &keypair.public_key))
        });
    }

    c.bench_function("Derive (priv. key -> priv. key)", |bench| {
        bench.iter(|| ext_skey.derive_private(&i))
    });

    c.bench_function("Derive (priv. key -> pub. key)", |bench| {
        bench.iter(|| ext_skey.derive_public(&i))
    });

    c.bench_function("Derive (pub. key -> pub. key)", |bench| {
        bench.iter(|| ext_pkey.derive_normal_public(&i))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
