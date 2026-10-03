//! HMAC against the HMAC-SHA-256 and HMAC-SHA-512 vectors of RFC 4231.

#![cfg(feature = "hmac")]

use tc_macs::{FixedHmac, KeyRef, Mac, MacError, MacInit};
use tc_sha::{Sha256Digest, Sha512Digest};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn tag<M: Mac>(mac: &mut M, input: &[u8]) -> Vec<u8> {
    mac.update(input).unwrap();
    let mut output = vec![0; mac.mac_size()];
    let written = mac.do_final(&mut output).unwrap();
    assert_eq!(written, output.len());
    output
}

const LONG_KEY: [u8; 131] = [0xaa; 131];

/// (key, message, HMAC-SHA-256, HMAC-SHA-512): test cases 1, 2, 6 and 7 of
/// RFC 4231.
fn vectors() -> [(Vec<u8>, &'static [u8], &'static str, &'static str); 4] {
    [
        (
            vec![0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            LONG_KEY.to_vec(),
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
        (
            LONG_KEY.to_vec(),
            b"This is a test using a larger than block-size key and a larger than block-size data. \
              The key needs to be hashed before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    ]
}

#[test]
fn the_fixed_hmac_matches_the_rfc_4231_vectors() {
    for (key, message, sha256, sha512) in vectors() {
        let mut mac = FixedHmac::new(Sha256Digest::new());
        mac.init(&KeyRef::new(&key)).unwrap();
        assert_eq!(tag(&mut mac, message), hex(sha256));

        let mut mac = FixedHmac::new(Sha512Digest::new());
        mac.init(&KeyRef::new(&key)).unwrap();
        assert_eq!(tag(&mut mac, message), hex(sha512));
    }
}

#[test]
fn do_final_and_reset_restart_the_hmac_under_the_same_key() {
    let (key, message, expected, _) = vectors()[1].clone();
    let mut mac = FixedHmac::new(Sha256Digest::new());
    mac.init(&KeyRef::new(&key)).unwrap();
    assert_eq!(tag(&mut mac, message), hex(expected));
    assert_eq!(tag(&mut mac, message), hex(expected));
    mac.update(b"discarded").unwrap();
    mac.reset();
    assert_eq!(tag(&mut mac, message), hex(expected));
}

#[test]
fn the_tag_does_not_depend_on_how_the_input_is_split() {
    let (key, message, expected, _) = vectors()[3].clone();
    let mut mac = FixedHmac::new(Sha256Digest::new());
    mac.init(&KeyRef::new(&key)).unwrap();
    for split in 0..=message.len() {
        mac.update(&message[..split]).unwrap();
        assert_eq!(
            tag(&mut mac, &message[split..]),
            hex(expected),
            "split {split}"
        );
    }
}

#[test]
fn an_hmac_reports_its_tag_size_and_its_name() {
    let mac = FixedHmac::new(Sha256Digest::new());
    assert_eq!(mac.mac_size(), 32);
    assert_eq!(mac.to_string(), "SHA-256/HMAC");
}

#[test]
fn using_an_hmac_before_init_fails() {
    let mut mac = FixedHmac::new(Sha256Digest::new());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut [0; 32]), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_is_rejected_without_losing_the_message() {
    let (key, message, expected, _) = vectors()[0].clone();
    let mut mac = FixedHmac::new(Sha256Digest::new());
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(message).unwrap();
    assert_eq!(
        mac.do_final(&mut [0; 31]),
        Err(MacError::OutputTooShort {
            required: 32,
            available: 31
        })
    );
    assert_eq!(tag(&mut mac, &[]), hex(expected));
}

#[cfg(feature = "alloc")]
mod allocating {
    use super::*;
    use tc_macs::Hmac;

    #[test]
    fn the_allocating_hmac_matches_the_rfc_4231_vectors() {
        for (key, message, sha256, sha512) in vectors() {
            let mut mac = Hmac::new(Sha256Digest::new());
            mac.init(&KeyRef::new(&key)).unwrap();
            assert_eq!(tag(&mut mac, message), hex(sha256));

            let mut mac = Hmac::new(Sha512Digest::new());
            mac.init(&KeyRef::new(&key)).unwrap();
            assert_eq!(tag(&mut mac, message), hex(sha512));
        }
    }

    #[test]
    fn the_allocating_hmac_matches_the_fixed_one_for_every_length() {
        let key = [0x5a; 100];
        let mut mac = Hmac::new(Sha256Digest::new());
        mac.init(&KeyRef::new(&key)).unwrap();
        let mut fixed = FixedHmac::new(Sha256Digest::new());
        fixed.init(&KeyRef::new(&key)).unwrap();

        let message: Vec<u8> = (0..=200).collect();
        for len in 0..message.len() {
            assert_eq!(
                tag(&mut mac, &message[..len]),
                tag(&mut fixed, &message[..len])
            );
        }
        assert_eq!(mac.to_string(), "SHA-256/HMAC");
    }
}
