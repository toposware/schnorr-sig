// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate criterion;

use cheetah::group::ff::Field;
use cheetah::Fp;
use criterion::Criterion;
use rand_core::OsRng;

extern crate schnorr_sig;
use schnorr_sig::PrivateKey;
use schnorr_sig::PublicKey;
use schnorr_sig::Signature;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng;

    c.bench_function("sign", |bench| {
        let mut message = [Fp::zero(); 26];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let skey = PrivateKey::new(&mut rng);

        bench.iter(|| Signature::sign(&message, &skey, &mut rng))
    });

    c.bench_function("verify", |bench| {
        let mut message = [Fp::zero(); 26];
        for message_chunk in message.iter_mut() {
            *message_chunk = Fp::random(&mut rng);
        }

        let skey = PrivateKey::new(&mut rng);
        let pkey = PublicKey::from_private_key(skey);

        let signature = Signature::sign(&message, &skey, &mut rng);

        bench.iter(|| signature.verify(&message, &pkey))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
