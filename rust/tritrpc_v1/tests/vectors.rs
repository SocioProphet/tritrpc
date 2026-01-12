use tritrpc_v1::{tleb3, tritpack243};

#[test]
fn micro_vectors() {
    let b = tritpack243::pack(&[2, 1, 0, 0, 2]);
    assert_eq!(b, vec![0xBF]);
    let b2 = tritpack243::pack(&[2, 2, 1]);
    assert_eq!(b2, vec![0xF5, 0x19]);
}

#[test]
fn tleb3_roundtrip() {
    for &n in [0u64, 1, 2, 3, 8, 9, 10, 123, 4096, 65535].iter() {
        let enc = tleb3::encode_len(n);
        let (dec, _) = tleb3::decode_len(&enc, 0).unwrap();
        assert_eq!(dec, n);
    }
}
