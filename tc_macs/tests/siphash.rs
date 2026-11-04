//! SipHash against the 64 SipHash-2-4 vectors of the reference implementation,
//! keyed with the bytes 0 to 15 over the first bytes of 0, 1, 2 and so on. The
//! one at length 15 is the example of the SipHash paper, appendix A, and of
//! Bouncy Castle C#'s `SipHashTest`.

#![cfg(feature = "siphash")]

use tc_macs::{InitError, KeyRef, Mac, MacError, MacInit, SipHash};

const VECTORS: [u64; 64] = [
    0x726fdb47dd0e0e31,
    0x74f839c593dc67fd,
    0x0d6c8009d9a94f5a,
    0x85676696d7fb7e2d,
    0xcf2794e0277187b7,
    0x18765564cd99a68d,
    0xcbc9466e58fee3ce,
    0xab0200f58b01d137,
    0x93f5f5799a932462,
    0x9e0082df0ba9e4b0,
    0x7a5dbbc594ddb9f3,
    0xf4b32f46226bada7,
    0x751e8fbc860ee5fb,
    0x14ea5627c0843d90,
    0xf723ca908e7af2ee,
    0xa129ca6149be45e5,
    0x3f2acc7f57c29bdb,
    0x699ae9f52cbe4794,
    0x4bc1b3f0968dd39c,
    0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98,
    0xd0f2cbb02e3b67c7,
    0x93536795e3a33e88,
    0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94,
    0xbce192de8a85b8ea,
    0x17d835b85bbb15f3,
    0x2f2e6163076bcfad,
    0xde4daaaca71dc9a5,
    0xa6a2506687956571,
    0xad87a3535c49ef28,
    0x32d892fad841c342,
    0x7127512f72f27cce,
    0xa7f32346f95978e3,
    0x12e0b01abb051238,
    0x15e034d40fa197ae,
    0x314dffbe0815a3b4,
    0x027990f029623981,
    0xcadcd4e59ef40c4d,
    0x9abfd8766a33735c,
    0x0e3ea96b5304a7d0,
    0xad0c42d6fc585992,
    0x187306c89bc215a9,
    0xd4a60abcf3792b95,
    0xf935451de4f21df2,
    0xa9538f0419755787,
    0xdb9acddff56ca510,
    0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951,
    0xc766e62cfcadaf96,
    0xee64435a9752fe72,
    0xa192d576b245165a,
    0x0a8787bf8ecb74b2,
    0x81b3e73d20b49b6f,
    0x7fa8220ba3b2ecea,
    0x245731c13ca42499,
    0xb78dbfaf3a8d83bd,
    0xea1ad565322a1a0b,
    0x60e61c23a3795013,
    0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1,
    0x9f626da15c9625f3,
    0xe51b38608ef25f57,
    0x958a324ceb064572,
];

fn key() -> [u8; 16] {
    core::array::from_fn(|index| index as u8)
}

fn message() -> [u8; 64] {
    core::array::from_fn(|index| index as u8)
}

fn keyed() -> SipHash {
    let mut mac = SipHash::new();
    mac.init(&KeyRef::new(&key())).unwrap();
    mac
}

fn tag(mac: &mut SipHash) -> u64 {
    let mut output = [0; 8];
    assert_eq!(mac.do_final(&mut output), Ok(8));
    u64::from_le_bytes(output)
}

#[test]
fn every_reference_vector_matches_at_every_split_of_the_input() {
    let message = message();
    for (length, &expected) in VECTORS.iter().enumerate() {
        for split in 0..=length {
            let mut mac = keyed();
            mac.update(&message[..split]).unwrap();
            mac.update(&message[split..length]).unwrap();
            assert_eq!(tag(&mut mac), expected, "length {length} split {split}");
        }
    }
}

#[test]
fn every_reference_vector_matches_a_byte_at_a_time() {
    let message = message();
    for (length, &expected) in VECTORS.iter().enumerate() {
        let mut mac = keyed();
        for byte in &message[..length] {
            mac.update(core::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(tag(&mut mac), expected, "length {length}");
    }
}

#[test]
fn do_final_starts_the_next_message_under_the_same_key() {
    let mut mac = keyed();
    for (length, &expected) in VECTORS.iter().enumerate() {
        mac.update(&message()[..length]).unwrap();
        assert_eq!(tag(&mut mac), expected, "length {length}");
    }
}

#[test]
fn reset_discards_the_message_and_keeps_the_key() {
    let mut mac = keyed();
    mac.update(b"discarded, with a partial word").unwrap();
    mac.reset();
    mac.update(&message()[..15]).unwrap();
    assert_eq!(tag(&mut mac), VECTORS[15]);
}

#[test]
fn the_round_counts_change_the_tag_and_the_name() {
    let mut other = SipHash::with_rounds(4, 8);
    other.init(&KeyRef::new(&key())).unwrap();
    other.update(&message()[..15]).unwrap();
    assert_ne!(tag(&mut other), VECTORS[15]);
    assert_eq!(other.to_string(), "SipHash-4-8");
    assert_eq!(SipHash::default().to_string(), "SipHash-2-4");
}

#[test]
fn the_mac_refuses_to_run_before_a_successful_init() {
    let mut mac = SipHash::new();
    let mut output = [0x55; 8];
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut output), Err(MacError::NotInitialised));
    assert_eq!(output, [0x55; 8]);
    mac.reset();
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn init_accepts_only_a_key_of_16_bytes() {
    let long = [0x42; 32];
    let mut mac = SipHash::new();
    for length in [0, 7, 8, 15, 17, 32] {
        assert_eq!(
            mac.init(&KeyRef::new(&long[..length])),
            Err(InitError::InvalidKeyLength(length))
        );
    }
    assert_eq!(mac.init(&KeyRef::new(&long[..16])), Ok(()));
}

#[test]
fn a_failed_init_never_goes_on_under_the_previous_key() {
    let mut mac = keyed();
    assert_eq!(
        mac.init(&KeyRef::new(&[0; 15])),
        Err(InitError::InvalidKeyLength(15))
    );
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let mut mac = keyed();
    mac.update(&message()[..15]).unwrap();
    let mut short = [0x55; 7];
    assert_eq!(
        mac.do_final(&mut short),
        Err(MacError::OutputTooShort {
            required: 8,
            available: 7
        })
    );
    assert_eq!(short, [0x55; 7]);
    assert_eq!(tag(&mut mac), VECTORS[15]);
}

#[test]
fn a_longer_output_keeps_its_tail() {
    let mut mac = keyed();
    mac.update(&message()[..15]).unwrap();
    let mut output = [0x55; 12];
    assert_eq!(mac.do_final(&mut output), Ok(8));
    assert_eq!(output[..8], VECTORS[15].to_le_bytes());
    assert_eq!(output[8..], [0x55; 4]);
}

#[test]
fn the_size_constants_match_the_mac() {
    let mac = SipHash::new();
    assert_eq!(mac.mac_size(), SipHash::TAG_BYTES);
    assert_eq!(SipHash::TAG_BYTES, 8);
    assert_eq!(SipHash::KEY_BYTES, 16);
}
