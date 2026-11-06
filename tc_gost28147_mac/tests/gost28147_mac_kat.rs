//! The zero-IV vector is one of Bouncy Castle's `GOST28147MacTest`; the IV vectors
//! were produced with Bouncy Castle's `Gost28147Mac`.

use tc_gost28147::s_box;
use tc_gost28147_mac::{Gost28147Mac, Gost28147MacParamsRef};
use tc_macs::{InitError, Mac, MacError, MacInit};

const KEY: [u8; 32] = [
    0x6d, 0x14, 0x5d, 0xc9, 0x93, 0xf4, 0x01, 0x9e, 0x10, 0x42, 0x80, 0xdf, 0x6f, 0xcd, 0x8c, 0xd8,
    0xe0, 0x1e, 0x10, 0x1e, 0x4c, 0x11, 0x3d, 0x7e, 0xc4, 0xf4, 0x69, 0xce, 0x6d, 0xcd, 0x9e, 0x49,
];
const MESSAGE: &[u8] = b"what do ya want for nothing?";

fn tag(params: &Gost28147MacParamsRef<'_>, message: &[u8]) -> [u8; 4] {
    let mut mac = Gost28147Mac::new();
    mac.init(params).unwrap();
    for chunk in message.chunks(5) {
        mac.update(chunk).unwrap();
    }
    let mut output = [0_u8; 4];
    mac.do_final(&mut output).unwrap();
    output
}

#[test]
fn matches_the_bouncy_castle_vector_under_a_zero_iv() {
    let params = Gost28147MacParamsRef::new(&KEY, &[0; 8]).with_s_box(&s_box::E_A);
    assert_eq!(tag(&params, MESSAGE), [0x93, 0x46, 0x8a, 0x46]);
}

#[test]
fn a_nonzero_iv_matches_bouncy_castle() {
    // Produced by Bouncy Castle's Gost28147Mac keyed with ParametersWithIV,
    // whose S-box is its default E-A.
    let params = Gost28147MacParamsRef::new(&KEY, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(tag(&params, MESSAGE), [0x0c, 0xae, 0xfa, 0xa3]);
}

#[test]
fn a_single_block_message_ignores_the_iv_as_bouncy_castle_does() {
    let with_iv = Gost28147MacParamsRef::new(&KEY, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let without = Gost28147MacParamsRef::new(&KEY, &[0; 8]);
    assert_eq!(tag(&with_iv, b"short"), [0x5b, 0x0d, 0xe3, 0x1a]);
    assert_eq!(tag(&without, b"short"), [0x5b, 0x0d, 0xe3, 0x1a]);
}

#[test]
fn the_iv_must_be_exactly_one_block() {
    let mut mac = Gost28147Mac::new();
    for length in [0, 7, 9, 16] {
        assert_eq!(
            mac.init(&Gost28147MacParamsRef::new(&KEY, &vec![0; length])),
            Err(InitError::InvalidIvLength(length))
        );
    }
}

#[test]
fn display_writes_the_bouncy_castle_name() {
    assert_eq!(Gost28147Mac::new().to_string(), "Gost28147Mac");
}

#[test]
fn the_key_and_the_s_box_must_have_their_lengths() {
    let mut mac = Gost28147Mac::new();
    assert_eq!(
        mac.init(&Gost28147MacParamsRef::new(&KEY[..31], &[0; 8])),
        Err(InitError::InvalidKeyLength(31))
    );
    assert_eq!(
        mac.init(&Gost28147MacParamsRef::new(&KEY, &[0; 8]).with_s_box(&[0; 7])),
        Err(InitError::InvalidSBoxLength(7))
    );
}

#[test]
fn a_refused_init_leaves_the_mac_uninitialized() {
    let mut mac = Gost28147Mac::new();
    assert_eq!(mac.update(&[]), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut [0; 4]), Err(MacError::NotInitialised));

    mac.init(&Gost28147MacParamsRef::new(&KEY, &[0; 8]))
        .unwrap();
    assert!(
        mac.init(&Gost28147MacParamsRef::new(&KEY, &[0; 7]))
            .is_err()
    );
    assert_eq!(mac.update(&[]), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let params = Gost28147MacParamsRef::new(&KEY, &[0; 8]);
    let mut mac = Gost28147Mac::new();
    mac.init(&params).unwrap();
    mac.update(MESSAGE).unwrap();
    assert_eq!(
        mac.do_final(&mut [0; 3]),
        Err(MacError::OutputTooShort {
            required: 4,
            available: 3,
        })
    );
    let mut output = [0; 4];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, tag(&params, MESSAGE));
}

#[test]
fn reset_and_do_final_keep_the_key_and_the_iv() {
    let params = Gost28147MacParamsRef::new(&KEY, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut mac = Gost28147Mac::new();
    mac.init(&params).unwrap();

    mac.update(b"discarded").unwrap();
    mac.reset();
    mac.update(MESSAGE).unwrap();
    let mut first = [0; 4];
    mac.do_final(&mut first).unwrap();

    mac.update(MESSAGE).unwrap();
    let mut second = [0; 4];
    mac.do_final(&mut second).unwrap();

    assert_eq!(first, [0x0c, 0xae, 0xfa, 0xa3]);
    assert_eq!(second, first);
}
