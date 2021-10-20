#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand_core::OsRng;
use stark_curve::FieldElement;

extern crate schnorr_sig;
use schnorr_sig::PrivateKey;
use schnorr_sig::PublicKey;
use schnorr_sig::Signature;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("sign", |bench| {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = PrivateKey::new(OsRng);

        bench.iter(|| Signature::sign(&message, &skey, OsRng))
    });

    c.bench_function("verify", |bench| {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = PrivateKey::new(OsRng);
        let pkey = PublicKey::from_private_key(skey);

        let signature = Signature::sign(&message, &skey, OsRng);

        bench.iter(|| signature.verify(&message, &pkey))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
