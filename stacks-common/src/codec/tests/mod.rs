use std::io::Cursor;

use super::*;

#[test]
fn codec_for_bool() {
    let t = true;
    let f = false;
    assert_eq!(&t.serialize_to_vec(), &vec![1u8]);
    assert_eq!(&f.serialize_to_vec(), &vec![0u8]);
    assert_eq!(
        bool::consensus_deserialize(&mut Cursor::new(&t.serialize_to_vec())).unwrap(),
        t
    );
    assert_eq!(
        bool::consensus_deserialize(&mut Cursor::new(&f.serialize_to_vec())).unwrap(),
        f
    );
    assert!(bool::consensus_deserialize(&mut Cursor::new(&vec![2u8])).is_err());
}

#[test]
fn codec_for_option() {
    let t = Some(true);
    let f = Some(false);
    let n: Option<bool> = None;
    assert_eq!(&t.serialize_to_vec(), &vec![1u8, 1u8]);
    assert_eq!(&f.serialize_to_vec(), &vec![1u8, 0u8]);
    assert_eq!(&n.serialize_to_vec(), &vec![0u8]);
    assert_eq!(
        Option::<bool>::consensus_deserialize(&mut Cursor::new(&t.serialize_to_vec())).unwrap(),
        t
    );
    assert_eq!(
        Option::<bool>::consensus_deserialize(&mut Cursor::new(&f.serialize_to_vec())).unwrap(),
        f
    );
    assert_eq!(
        Option::<bool>::consensus_deserialize(&mut Cursor::new(&n.serialize_to_vec())).unwrap(),
        n
    );
    assert!(bool::consensus_deserialize(&mut Cursor::new(&vec![2u8])).is_err());
}

#[test]
fn codec_for_u128() {
    let n: u128 = 0x1234567890abcdef1234567890abcdef;
    assert_eq!(
        &n.serialize_to_vec(),
        &vec![
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef
        ]
    );
    assert_eq!(
        u128::consensus_deserialize(&mut Cursor::new(&n.serialize_to_vec())).unwrap(),
        n
    );
}
