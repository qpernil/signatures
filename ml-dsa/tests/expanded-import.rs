//! Checked expanded-key import regressions for every ML-DSA parameter set.
#![allow(deprecated)]
use ml_dsa::{
    ExpandedSigningKey, Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey, Verifier,
};

fn check<P: MlDsaParams>() {
    let seeded = SigningKey::<P>::from_seed(&Seed::from([7; 32]));
    let encoded = seeded.expanded_key().to_expanded();
    let imported = ExpandedSigningKey::<P>::from_expanded_checked(&encoded)
        .expect("valid expanded key and signature");
    assert_eq!(imported.to_expanded(), encoded);
    let signature = imported
        .sign_deterministic(b"checked import", b"")
        .expect("valid expanded key and signature");
    seeded
        .verifying_key()
        .verify(b"checked import", &signature)
        .expect("valid expanded key and signature");
    // rho, tr, s1 and s2 need to agree with the derived t0 and public key.
    for offset in [0, 64, 128, encoded.len() - 1] {
        let mut bad = encoded.clone();
        bad[offset] ^= 1;
        assert!(ExpandedSigningKey::<P>::from_expanded_checked(&bad).is_err());
    }
    // Reserved small-coefficient encodings must return an error, not panic.
    let mut bad = encoded.clone();
    bad[128] = 0xff;
    assert!(ExpandedSigningKey::<P>::from_expanded_checked(&bad).is_err());
    let mut bad = encoded.clone();
    bad.fill(0xff);
    assert!(ExpandedSigningKey::<P>::from_expanded_checked(&bad).is_err());
    // K is a signing randomizer seed, not redundant key-pair metadata.
    let mut other_k = encoded;
    other_k[32] ^= 1;
    assert!(ExpandedSigningKey::<P>::from_expanded_checked(&other_k).is_ok());
}
#[test]
fn checked_expanded_import_ml_dsa_44() {
    check::<MlDsa44>();
}
#[test]
fn checked_expanded_import_ml_dsa_65() {
    check::<MlDsa65>();
}
#[test]
fn checked_expanded_import_ml_dsa_87() {
    check::<MlDsa87>();
}
