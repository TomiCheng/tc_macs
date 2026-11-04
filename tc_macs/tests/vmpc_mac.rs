//! VMPC-MAC against the vector of Bouncy Castle C#'s `VMPCMacTest`.

#![cfg(feature = "vmpc-mac")]

use tc_macs::{InitError, KeyWithIvRef, Mac, MacError, MacInit, VmpcMac};

const KEY: [u8; 16] = [
    0x96, 0x61, 0x41, 0x0a, 0xb7, 0x97, 0xd8, 0xa9, 0xeb, 0x76, 0x7c, 0x21, 0x17, 0x2d, 0xf6, 0xc7,
];
const IV: [u8; 16] = [
    0x4b, 0x5c, 0x2f, 0x00, 0x3e, 0x67, 0xf3, 0x95, 0x57, 0xa8, 0xd2, 0x6f, 0x3d, 0xa2, 0xb1, 0x55,
];
const EXPECTED: [u8; 20] = [
    0x9b, 0xda, 0x16, 0xe2, 0xad, 0x0e, 0x28, 0x47, 0x74, 0xa3, 0xac, 0xbc, 0x88, 0x35, 0xa8, 0x32,
    0x6c, 0x11, 0xfa, 0xad,
];

fn message() -> [u8; 256] {
    core::array::from_fn(|index| index as u8)
}

fn keyed() -> VmpcMac {
    let mut mac = VmpcMac::new();
    mac.init(&KeyWithIvRef::new(&KEY, &IV)).unwrap();
    mac
}

fn tag(mac: &mut VmpcMac) -> [u8; 20] {
    let mut output = [0; 20];
    assert_eq!(mac.do_final(&mut output), Ok(20));
    output
}

#[test]
fn the_bouncy_castle_vector_matches_at_every_split_of_the_input() {
    let message = message();
    for split in 0..=message.len() {
        let mut mac = keyed();
        mac.update(&message[..split]).unwrap();
        mac.update(&message[split..]).unwrap();
        assert_eq!(tag(&mut mac), EXPECTED, "split at {split}");
    }
}

#[test]
fn do_final_starts_the_next_message_under_the_same_key_and_iv() {
    let mut mac = keyed();
    mac.update(&message()).unwrap();
    assert_eq!(tag(&mut mac), EXPECTED);
    mac.update(&message()).unwrap();
    assert_eq!(tag(&mut mac), EXPECTED);
}

#[test]
fn reset_discards_the_message_and_keeps_the_key_and_iv() {
    let mut mac = keyed();
    mac.update(b"discarded").unwrap();
    mac.reset();
    mac.update(&message()).unwrap();
    assert_eq!(tag(&mut mac), EXPECTED);
}

#[test]
fn the_mac_refuses_to_run_before_a_successful_init() {
    let mut mac = VmpcMac::new();
    let mut output = [0x55; 20];
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut output), Err(MacError::NotInitialised));
    assert_eq!(output, [0x55; 20]);
    mac.reset();
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn init_accepts_only_keys_and_ivs_of_16_to_64_bytes() {
    let long = [0x42; 65];
    let mut mac = VmpcMac::new();
    for length in [0, 15, 65] {
        assert_eq!(
            mac.init(&KeyWithIvRef::new(&long[..length], &IV)),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            mac.init(&KeyWithIvRef::new(&KEY, &long[..length])),
            Err(InitError::InvalidIvLength(length))
        );
    }
    for length in [16, 64] {
        assert_eq!(mac.init(&KeyWithIvRef::new(&long[..length], &IV)), Ok(()));
        assert_eq!(mac.init(&KeyWithIvRef::new(&KEY, &long[..length])), Ok(()));
    }
}

#[test]
fn a_failed_init_never_goes_on_under_the_previous_key() {
    let mut mac = keyed();
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&[0; 15], &IV)),
        Err(InitError::InvalidKeyLength(15))
    );
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let mut mac = keyed();
    mac.update(&message()).unwrap();
    let mut short = [0x55; 19];
    assert_eq!(
        mac.do_final(&mut short),
        Err(MacError::OutputTooShort {
            required: 20,
            available: 19
        })
    );
    assert_eq!(short, [0x55; 19]);
    assert_eq!(tag(&mut mac), EXPECTED);
}

#[test]
fn a_longer_output_keeps_its_tail() {
    let mut mac = keyed();
    mac.update(&message()).unwrap();
    let mut output = [0x55; 24];
    assert_eq!(mac.do_final(&mut output), Ok(20));
    assert_eq!(output[..20], EXPECTED);
    assert_eq!(output[20..], [0x55; 4]);
}

#[test]
fn the_name_and_size_follow_bouncy_castle() {
    let mac = VmpcMac::default();
    assert_eq!(mac.to_string(), "VMPC-MAC");
    assert_eq!(mac.mac_size(), VmpcMac::TAG_BYTES);
    assert_eq!(VmpcMac::TAG_BYTES, 20);
}
