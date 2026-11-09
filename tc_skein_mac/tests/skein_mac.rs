//! The vectors of Bouncy Castle's `SkeinMacTest`, and the error paths.

#[path = "vectors/bc_skein_mac.rs"]
mod bc_skein_mac;

use bc_skein_mac::CASES;
use tc_macs::{InitError, Mac, MacError, MacInit};
use tc_skein_mac::{SkeinMac, SkeinParamsRef};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn keyed(state: usize, output: usize, key: &[u8]) -> SkeinMac {
    let mut mac = SkeinMac::new(state, output);
    mac.init(&SkeinParamsRef::new().with_key(key)).unwrap();
    mac
}

fn tag_of(mac: &mut SkeinMac) -> Vec<u8> {
    let mut tag = vec![0; mac.mac_size()];
    assert_eq!(mac.do_final(&mut tag), Ok(tag.len()));
    tag
}

#[test]
fn every_bouncy_castle_vector_matches_in_one_piece_and_byte_by_byte() {
    assert!(!CASES.is_empty());
    for &(state, output, message, key, expected) in CASES {
        let (message, key, expected) = (unhex(message), unhex(key), unhex(expected));

        let mut mac = keyed(state, output, &key);
        mac.update(&message).unwrap();
        assert_eq!(tag_of(&mut mac), expected, "{state}-{output}");

        for byte in &message {
            mac.update(core::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(tag_of(&mut mac), expected, "{state}-{output} by bytes");
    }
}

#[test]
fn the_mac_refuses_to_run_before_a_successful_init() {
    let mut mac = SkeinMac::new(512, 256);
    let mut tag = [0x55; 32];
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut tag), Err(MacError::NotInitialised));
    assert_eq!(tag, [0x55; 32]);
}

#[test]
fn init_refuses_a_missing_key_and_a_key_shorter_than_16_bytes() {
    let mut mac = SkeinMac::new(512, 256);
    assert_eq!(
        mac.init(&SkeinParamsRef::new()),
        Err(InitError::InvalidKeyLength(0))
    );
    assert_eq!(
        mac.init(&SkeinParamsRef::new().with_key(&[0; 15])),
        Err(InitError::InvalidKeyLength(15))
    );
    assert!(mac.init(&SkeinParamsRef::new().with_key(&[0; 16])).is_ok());
}

#[test]
fn a_failed_init_never_goes_on_under_the_previous_key() {
    let mut mac = keyed(512, 256, &[0x42; 32]);
    assert!(mac.init(&SkeinParamsRef::new()).is_err());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let mut mac = keyed(512, 256, &[0x42; 32]);
    mac.update(b"message").unwrap();
    let mut short = [0x55; 31];
    assert_eq!(
        mac.do_final(&mut short),
        Err(MacError::OutputTooShort {
            required: 32,
            available: 31
        })
    );
    assert_eq!(short, [0x55; 31]);

    let mut fresh = keyed(512, 256, &[0x42; 32]);
    fresh.update(b"message").unwrap();
    assert_eq!(tag_of(&mut mac), tag_of(&mut fresh));
}

#[test]
fn do_final_and_reset_keep_the_key_and_drop_the_message() {
    let mut mac = keyed(1024, 512, &[0x42; 64]);
    mac.update(b"message").unwrap();
    let expected = tag_of(&mut mac);

    mac.update(b"message").unwrap();
    assert_eq!(tag_of(&mut mac), expected);

    mac.update(b"discarded").unwrap();
    mac.reset();
    mac.update(b"message").unwrap();
    assert_eq!(tag_of(&mut mac), expected);
}

#[test]
fn a_clone_continues_independently_of_the_original() {
    let mut mac = keyed(256, 128, &[0x42; 32]);
    mac.update(b"mess").unwrap();
    let mut copy = mac.clone();
    mac.update(b"age").unwrap();
    copy.update(b"age").unwrap();
    assert_eq!(tag_of(&mut mac), tag_of(&mut copy));
}

#[test]
fn the_other_skein_parameters_change_the_tag() {
    let key = [0x42; 32];
    let mut plain = keyed(512, 256, &key);
    let mut personal = SkeinMac::new(512, 256);
    personal
        .init(
            &SkeinParamsRef::new()
                .with_key(&key)
                .with_personalisation(b"20261104 me@example.com app/v1"),
        )
        .unwrap();
    assert_ne!(tag_of(&mut plain), tag_of(&mut personal));
}

#[test]
fn the_name_follows_bouncy_castle() {
    assert_eq!(SkeinMac::new(512, 256).to_string(), "Skein-MAC-512-256");
    assert_eq!(
        SkeinMac::new(SkeinMac::SKEIN_1024, 384).to_string(),
        "Skein-MAC-1024-384"
    );
}

#[cfg(feature = "alloc")]
#[test]
fn owned_parameters_give_the_same_tag_as_borrowed_ones() {
    use tc_skein_mac::SkeinParamsOwned;

    let key = [0x42; 32];
    let mut owned = SkeinMac::new(512, 256);
    owned
        .init(&SkeinParamsOwned::new().with_key(key.to_vec()))
        .unwrap();
    assert_eq!(tag_of(&mut owned), tag_of(&mut keyed(512, 256, &key)));
}
