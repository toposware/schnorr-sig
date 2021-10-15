#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand_core::OsRng;
use stark_curve::{AffinePoint, FieldElement, Scalar};

extern crate schnorr_sig;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("sign", |bench| {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = Scalar::random(OsRng);
        let pkey = AffinePoint::from(AffinePoint::generator() * skey);
        message[0] = pkey.get_x();
        message[1] = pkey.get_y();

        bench.iter(|| schnorr_sig::sign(message, skey, OsRng))
    });

    c.bench_function("verify", |bench| {
        let mut message = [FieldElement::zero(); 6];
        for message_chunk in message.iter_mut().skip(2) {
            *message_chunk = FieldElement::random(OsRng);
        }

        let skey = Scalar::random(OsRng);
        let pkey = AffinePoint::from(AffinePoint::generator() * skey);
        message[0] = pkey.get_x();
        message[1] = pkey.get_y();

        let signature = schnorr_sig::sign(message, skey, OsRng);

        bench.iter(|| schnorr_sig::verify_signature(message, signature))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
