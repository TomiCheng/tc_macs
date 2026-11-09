//! The vectors of Bouncy Castle's `KMACTest`: the six KMAC samples of NIST SP
//! 800-185, its KMACXOF and padding checks, and the error paths.

use tc_digest::{TryDigest, TryXof};
use tc_kmac::KMac;
use tc_macs::{KeyRef, Mac, MacError, MacInit};

fn unhex(value: &str) -> Vec<u8> {
    let digits: Vec<u8> = value.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

const KEY: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const TAGGED: &[u8] = b"My Tagged Application";

fn long_message() -> Vec<u8> {
    (0..200).map(|byte| byte as u8).collect()
}

fn keyed(bits: usize, customization: &[u8], key: &[u8]) -> KMac {
    let mut mac = KMac::new(bits, customization);
    mac.init(&KeyRef::new(key)).unwrap();
    mac
}

fn tag_of(mac: &mut KMac) -> Vec<u8> {
    let mut tag = vec![0; mac.mac_size()];
    assert_eq!(mac.do_final(&mut tag), Ok(tag.len()));
    tag
}

#[test]
fn the_six_nist_samples_match() {
    let samples: [(usize, &[u8], Vec<u8>, &str); 6] = [
        (
            128,
            b"",
            vec![0, 1, 2, 3],
            "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
        ),
        (
            128,
            TAGGED,
            vec![0, 1, 2, 3],
            "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
        ),
        (
            128,
            TAGGED,
            long_message(),
            "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
        ),
        (
            256,
            TAGGED,
            vec![0, 1, 2, 3],
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7\
             f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
        ),
        (
            256,
            b"",
            long_message(),
            "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691\
             589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
        ),
        (
            256,
            TAGGED,
            long_message(),
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9\
             70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
        ),
    ];
    for (bits, customization, message, expected) in samples {
        let mut mac = keyed(bits, customization, &unhex(KEY));
        mac.update(&message).unwrap();
        assert_eq!(tag_of(&mut mac), unhex(expected), "KMAC{bits}");

        for byte in &message {
            mac.update(core::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(tag_of(&mut mac), unhex(expected), "KMAC{bits} by bytes");
    }
}

#[test]
fn kmacxof_output_does_not_depend_on_its_length_and_its_end_starts_the_next_message() {
    let expected = unhex("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c");
    let mut mac = keyed(128, TAGGED, &unhex(KEY));
    mac.update(&[0, 1, 2, 3]).unwrap();
    let mut first = [0_u8; 32];
    mac.try_output(&mut first).unwrap();
    assert_eq!(first.as_slice(), expected);

    let mut next = [0_u8; 32];
    mac.try_output(&mut next).unwrap();
    assert_ne!(next, first);
    mac.try_output_final(&mut next).unwrap();

    // A fixed length through output_final is KMAC itself
    mac.update(&[0, 1, 2, 3]).unwrap();
    mac.try_output_final(&mut next).unwrap();
    assert_eq!(
        next.as_slice(),
        unhex("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5")
    );

    mac.update(&[0, 1, 2, 3]).unwrap();
    mac.try_output(&mut first).unwrap();
    assert_eq!(first.as_slice(), expected);
    mac.try_output_final(&mut first).unwrap();
    assert_eq!(
        first.as_slice(),
        unhex("ffcb48c7620ccd67d1c83224186892cef2f2a99278d5cfdde10e48bdc89718c2")
    );
}

#[test]
fn a_key_whose_padding_crosses_the_rate_matches() {
    let message = unhex("01880204187b3e43eda8d51ec181d37dde5b17eccdd8be84c268dc6c9500700857");
    for (bits, key_length, expected) in [
        (
            128,
            163,
            "6e6ab56468c7445f81c679f89f45c90a95a9c01afbaab5f7065b7e2e96f7d2bb",
        ),
        (
            256,
            131,
            "f6302d4f854b4872e811b37993b6bfe027258089b6a9fbb26a755b1ebfc0d830",
        ),
    ] {
        let mut mac = keyed(bits, b"", &vec![0; key_length]);
        mac.update(&message).unwrap();
        let mut output = [0_u8; 32];
        mac.try_output(&mut output).unwrap();
        assert_eq!(output.as_slice(), unhex(expected), "KMAC{bits}");
    }
}

#[test]
fn a_long_customization_and_an_empty_key_match() {
    let mut mac = keyed(256, &[0; 200], &[]);
    mac.update(&long_message()).unwrap();
    assert_eq!(
        tag_of(&mut mac),
        unhex(
            "f9476d9b3e42bf23307af5ccb5287fd6f033b23c400566a2ebc5829bd119aa54\
             5cd9b6bde76ef61cd31c3c0f0aaf0945f44481e863b19e9c26fb46c8b2a8a9bb"
        )
    );
}

#[test]
fn the_mac_refuses_to_run_before_init() {
    let mut mac = KMac::new(128, b"");
    let mut tag = [0x55; 32];
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut tag), Err(MacError::NotInitialised));
    assert_eq!(mac.try_output(&mut tag), Err(MacError::NotInitialised));
    assert_eq!(tag, [0x55; 32]);
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let mut mac = keyed(128, TAGGED, &unhex(KEY));
    mac.update(&[0, 1, 2, 3]).unwrap();
    let mut short = [0x55; 31];
    assert_eq!(
        mac.do_final(&mut short),
        Err(MacError::OutputTooShort {
            required: 32,
            available: 31
        })
    );
    assert_eq!(short, [0x55; 31]);
    assert_eq!(
        tag_of(&mut mac),
        unhex("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5")
    );
}

#[test]
fn reset_keeps_the_key_and_drops_the_message_and_a_new_key_replaces_it() {
    let mut mac = keyed(128, TAGGED, &unhex(KEY));
    mac.update(b"discarded").unwrap();
    mac.reset();
    mac.update(&[0, 1, 2, 3]).unwrap();
    let expected = tag_of(&mut mac);
    assert_eq!(
        expected,
        unhex("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5")
    );

    mac.init(&KeyRef::new(&[0x42; 8])).unwrap();
    mac.update(&[0, 1, 2, 3]).unwrap();
    assert_ne!(tag_of(&mut mac), expected);
}

#[test]
fn the_digest_view_reports_the_tag_and_the_rate() {
    let mac = KMac::new(128, b"");
    assert_eq!((mac.digest_size(), mac.byte_length()), (32, 168));
    let mac = KMac::new(256, b"");
    assert_eq!((mac.digest_size(), mac.byte_length()), (64, 136));
}

#[test]
fn display_writes_the_bouncy_castle_name() {
    assert_eq!(KMac::new(128, b"").to_string(), "KMAC128");
    assert_eq!(KMac::new(256, b"").to_string(), "KMAC256");
}
