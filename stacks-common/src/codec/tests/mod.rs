use std::io::Cursor;

use super::*;

#[test]
fn codec_for_bool() {
    let t = true;
    let f = false;
    let t_binary = t.serialize_to_vec();
    let f_binary = f.serialize_to_vec();
    assert_eq!(&t_binary, &vec![1u8]);
    assert_eq!(&f_binary, &vec![0u8]);
    assert_eq!(
        bool::consensus_deserialize(&mut Cursor::new(&vec![1u8])).unwrap(),
        true
    );
    assert_eq!(
        bool::consensus_deserialize(&mut Cursor::new(&vec![0u8])).unwrap(),
        false
    );
    let r = bool::consensus_deserialize(&mut Cursor::new(&vec![2u8]));
    assert!(r.is_err());
}

#[test]
fn codec_for_option() {
    let t = Some(true);
    let f = Some(false);
    let n: Option<bool> = None;
    let t_binary = t.serialize_to_vec();
    let f_binary = f.serialize_to_vec();
    let n_binary = n.serialize_to_vec();
    assert_eq!(&t_binary, &vec![1u8, 1u8]);
    assert_eq!(&f_binary, &vec![1u8, 0u8]);
    assert_eq!(&n_binary, &vec![0u8]);
    assert_eq!(
        Option::<bool>::consensus_deserialize(&mut Cursor::new(&vec![1u8, 1u8])).unwrap(),
        Some(true)
    );
    assert_eq!(
        Option::<bool>::consensus_deserialize(&mut Cursor::new(&vec![1u8, 0u8])).unwrap(),
        Some(false)
    );
    assert_eq!(
        Option::<bool>::consensus_deserialize(&mut Cursor::new(&vec![0u8])).unwrap(),
        None
    );
    let r = bool::consensus_deserialize(&mut Cursor::new(&vec![2u8]));
    assert!(r.is_err());
}

#[test]
fn codec_for_u128() {
    let n: u128 = 0x1234567890abcdef1234567890abcdef;
    let n_binary = n.serialize_to_vec();
    assert_eq!(
        &n_binary,
        &vec![
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef
        ]
    );
    assert_eq!(
        u128::consensus_deserialize(&mut Cursor::new(&vec![
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef
        ]))
        .unwrap(),
        0x1234567890abcdef1234567890abcdef
    );
}
