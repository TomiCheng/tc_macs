//! The vector of Bouncy Castle's `ISO9797Alg3MacTest`, the triple-length key
//! and padding against DES chained by hand, and the error paths.

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_block_modes::KeyWithIvRef;
use tc_block_padding::{BlockCipherPadding, Iso7816d4Padding};
use tc_des::DesEngine;
use tc_iso9797_mac::{Iso9797Alg3Mac, Iso9797Alg3MacCreateError};
use tc_macs::{InitError, Mac, MacError, MacInit};

// Bouncy Castle `ISO9797Alg3MacTest`
const KEY: [u8; 16] = [
    0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57, 0x01, 0x31, 0xd9, 0x61, 0x9d, 0xc1, 0x37, 0x6e,
];
const MESSAGE: &[u8] = b"Hello World !!!!";
const TAG: [u8; 8] = [0xf0, 0x9b, 0x85, 0x62, 0x13, 0xba, 0xb8, 0x3b];

const IV: [u8; 8] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe];
const TRIPLE_KEY: [u8; 24] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
];

fn des(direction: CipherDirection, key: &[u8], block: [u8; 8]) -> [u8; 8] {
    let mut engine = DesEngine::new();
    engine.init(direction, &KeyRef::new(key)).unwrap();
    let mut output = [0; 8];
    engine.process_block(&block, &mut output).unwrap();
    output
}

// The algorithm from ISO/IEC 9797-1 itself, over blocks already padded
fn by_hand(key: &[u8], iv: [u8; 8], blocks: &[[u8; 8]]) -> [u8; 8] {
    let mut chain = iv;
    for block in blocks {
        let mut input = *block;
        for (byte, chain) in input.iter_mut().zip(&chain) {
            *byte ^= chain;
        }
        chain = des(CipherDirection::Encrypt, &key[..8], input);
    }
    let third = if key.len() == 24 {
        &key[16..]
    } else {
        &key[..8]
    };
    let middle = des(CipherDirection::Decrypt, &key[8..16], chain);
    des(CipherDirection::Encrypt, third, middle)
}

fn tag_of<P: tc_iso9797_mac::Iso9797Padding>(mac: &mut Iso9797Alg3Mac<P>) -> Vec<u8> {
    let mut tag = vec![0; mac.mac_size()];
    assert_eq!(mac.do_final(&mut tag), Ok(tag.len()));
    tag
}

#[test]
fn the_bouncy_castle_vector_matches_in_one_piece_and_in_pieces() {
    let mut mac = Iso9797Alg3Mac::new();
    mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
    mac.update(MESSAGE).unwrap();
    assert_eq!(tag_of(&mut mac), TAG);

    for chunk in MESSAGE.chunks(3) {
        mac.update(chunk).unwrap();
    }
    assert_eq!(tag_of(&mut mac), TAG);
}

#[test]
fn a_triple_length_key_and_an_iv_match_des_chained_by_hand() {
    let mut mac = Iso9797Alg3Mac::new();
    mac.init(&KeyWithIvRef::new(&TRIPLE_KEY, &IV)).unwrap();
    mac.update(b"0123456789abcdefXYZ").unwrap();

    let blocks = [*b"01234567", *b"89abcdef", *b"XYZ\0\0\0\0\0"];
    assert_eq!(tag_of(&mut mac), by_hand(&TRIPLE_KEY, IV, &blocks));
}

#[test]
fn padding_completes_a_partial_block_and_follows_a_full_one_with_its_own() {
    let padded = |message: &[u8]| {
        let mut mac = Iso9797Alg3Mac::with_padding(Iso7816d4Padding);
        mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
        mac.update(message).unwrap();
        tag_of(&mut mac)
    };
    let pad = |prefix: &[u8]| {
        let mut block = [0; 8];
        block[..prefix.len()].copy_from_slice(prefix);
        Iso7816d4Padding
            .add_padding(&mut block, prefix.len())
            .unwrap();
        block
    };

    assert_eq!(padded(b"abc"), by_hand(&KEY, [0; 8], &[pad(b"abc")]));
    assert_eq!(
        padded(b"abcdefgh"),
        by_hand(&KEY, [0; 8], &[*b"abcdefgh", pad(b"")])
    );
}

#[test]
fn a_shorter_tag_is_the_prefix_of_the_full_one() {
    let mut mac = Iso9797Alg3Mac::with_mac_size_bits(32).unwrap();
    mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
    mac.update(MESSAGE).unwrap();
    assert_eq!(tag_of(&mut mac), TAG[..4]);
}

#[test]
fn a_tag_length_outside_whole_bytes_up_to_the_block_is_refused() {
    for bits in [0, 7, 12, 72] {
        assert_eq!(
            Iso9797Alg3Mac::with_mac_size_bits(bits).err(),
            Some(Iso9797Alg3MacCreateError::InvalidMacSize(bits))
        );
    }
}

#[test]
fn init_refuses_keys_other_than_double_or_triple_length_and_ivs_other_than_a_block() {
    let mut mac = Iso9797Alg3Mac::new();
    for length in [0, 8, 15, 17, 32] {
        assert_eq!(
            mac.init(&KeyWithIvRef::new(&vec![0; length], &[0; 8])),
            Err(InitError::InvalidKeyLength(length))
        );
    }
    for length in [0, 7, 9, 16] {
        assert_eq!(
            mac.init(&KeyWithIvRef::new(&KEY, &vec![0; length])),
            Err(InitError::InvalidIvLength(length))
        );
    }
}

#[test]
fn a_failed_init_never_goes_on_under_the_previous_key() {
    let mut mac = Iso9797Alg3Mac::new();
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
    assert!(mac.init(&KeyWithIvRef::new(&KEY[..8], &[0; 8])).is_err());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let mut mac = Iso9797Alg3Mac::new();
    mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
    mac.update(MESSAGE).unwrap();
    let mut short = [0x55; 7];
    assert_eq!(
        mac.do_final(&mut short),
        Err(MacError::OutputTooShort {
            required: 8,
            available: 7
        })
    );
    assert_eq!(short, [0x55; 7]);
    assert_eq!(tag_of(&mut mac), TAG);
}

#[test]
fn reset_restarts_the_chain_from_the_iv() {
    let mut mac = Iso9797Alg3Mac::new();
    mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
    mac.update(b"discarded across a block").unwrap();
    mac.reset();
    mac.update(MESSAGE).unwrap();
    assert_eq!(tag_of(&mut mac), TAG);
}

#[test]
fn display_writes_the_bouncy_castle_name() {
    assert_eq!(Iso9797Alg3Mac::new().to_string(), "ISO9797Alg3");
}
