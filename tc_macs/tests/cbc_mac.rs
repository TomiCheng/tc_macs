//! CBC-MAC against the DES vectors of Bouncy Castle C#'s `MacTest.cs`.

#![cfg(feature = "cbc-mac")]

use core::convert::Infallible;

use tc_block_padding::{BlockCipherPadding, PaddingError, Pkcs7Padding};
use tc_des::DesEngine;
use tc_macs::{FixedCbcMac, FixedPaddedCbcMac, InitError, KeyWithIvRef, Mac, MacError, MacInit};

const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
// Bouncy Castle keyed without an IV uses an all-zero one.
const ZERO_IV: [u8; 8] = [0; 8];

/// "7654321 Now is the time for "
const INPUT1: &[u8] = b"7654321 Now is the time for ";
/// "7654321 ", exactly one DES block.
const INPUT2: &[u8] = b"7654321 ";

fn tag<M: Mac>(mac: &mut M, input: &[u8]) -> Vec<u8> {
    mac.update(input).unwrap();
    let mut output = vec![0; mac.mac_size()];
    let written = mac.do_final(&mut output).unwrap();
    assert_eq!(written, output.len());
    output
}

fn cbc_mac(iv: &[u8; 8]) -> FixedCbcMac<DesEngine, 8> {
    let mut mac = FixedCbcMac::new(DesEngine::new());
    mac.init(&KeyWithIvRef::new(&KEY, iv)).unwrap();
    mac
}

fn pkcs7_cbc_mac() -> FixedPaddedCbcMac<DesEngine, 8, Pkcs7Padding> {
    let mut mac = FixedPaddedCbcMac::new(DesEngine::new(), Pkcs7Padding);
    mac.init(&KeyWithIvRef::new(&KEY, &ZERO_IV)).unwrap();
    mac
}

#[test]
fn an_unpadded_mac_matches_the_bouncy_castle_vectors() {
    assert_eq!(
        tag(&mut cbc_mac(&ZERO_IV), INPUT1),
        [0xf1, 0xd3, 0x0f, 0x68]
    );
    assert_eq!(tag(&mut cbc_mac(&IV), INPUT1), [0x58, 0xd2, 0xe7, 0x7e]);
    // MacTest's output4 (3af549c9) comes from CFB-MAC and is tested there.
}

#[test]
fn a_pkcs7_padded_mac_matches_the_bouncy_castle_vectors() {
    assert_eq!(tag(&mut pkcs7_cbc_mac(), INPUT2), [0x18, 0x8f, 0xbd, 0xd5]);
    assert_eq!(tag(&mut pkcs7_cbc_mac(), INPUT1), [0x70, 0x45, 0xee, 0xcd]);
}

#[test]
fn the_tag_does_not_depend_on_how_the_input_is_split() {
    let message: Vec<u8> = (0..40).collect();
    for len in 0..=message.len() {
        let message = &message[..len];
        let expected = (
            tag(&mut cbc_mac(&IV), message),
            tag(&mut pkcs7_cbc_mac(), message),
        );
        for split in 0..=len {
            let mut plain = cbc_mac(&IV);
            plain.update(&message[..split]).unwrap();
            let mut padded = pkcs7_cbc_mac();
            padded.update(&message[..split]).unwrap();
            let actual = (
                tag(&mut plain, &message[split..]),
                tag(&mut padded, &message[split..]),
            );
            assert_eq!(actual, expected, "length {len}, split {split}");
        }
    }
}

#[test]
fn do_final_restarts_the_mac_under_the_same_key() {
    let mut mac = cbc_mac(&IV);
    mac.update(b"discarded").unwrap();
    mac.reset();
    assert_eq!(tag(&mut mac, INPUT1), [0x58, 0xd2, 0xe7, 0x7e]);
    assert_eq!(tag(&mut mac, INPUT1), [0x58, 0xd2, 0xe7, 0x7e]);
}

#[test]
fn a_full_final_block_gets_a_block_of_padding_only_when_padded() {
    // Without padding a full final block gets nothing more, so an extra block
    // of zeros changes the tag.
    let mut zero_block = INPUT2.to_vec();
    zero_block.extend_from_slice(&[0; 8]);
    assert_ne!(
        tag(&mut cbc_mac(&ZERO_IV), INPUT2),
        tag(&mut cbc_mac(&ZERO_IV), &zero_block)
    );

    // With padding it equals a whole block of PKCS#7 added by hand.
    let mut padded_by_hand = INPUT2.to_vec();
    padded_by_hand.extend_from_slice(&[8; 8]);
    assert_eq!(
        tag(&mut pkcs7_cbc_mac(), INPUT2),
        tag(&mut cbc_mac(&ZERO_IV), &padded_by_hand)
    );
}

#[test]
fn a_mac_reports_its_tag_size_and_its_mode_name() {
    let mac = FixedCbcMac::<_, 8>::with_mac_size(DesEngine::new(), 8);
    assert_eq!(mac.mac_size(), 8);
    assert_eq!(mac.to_string(), "DES/CBC");
    let padded = FixedPaddedCbcMac::<_, 8, _>::new(DesEngine::new(), Pkcs7Padding);
    assert_eq!(padded.mac_size(), 4);
    assert_eq!(padded.to_string(), "DES/CBC");
}

#[test]
#[should_panic(expected = "CBC-MAC size must be between 1 and the block size")]
fn a_tag_longer_than_the_block_is_rejected_at_construction() {
    FixedCbcMac::<_, 8>::with_mac_size(DesEngine::new(), 9);
}

#[test]
fn using_a_mac_before_init_fails() {
    let mut mac = FixedCbcMac::<_, 8>::new(DesEngine::new());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut [0; 4]), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_is_rejected_without_losing_the_message() {
    let mut mac = cbc_mac(&IV);
    mac.update(INPUT1).unwrap();
    assert_eq!(
        mac.do_final(&mut [0; 3]),
        Err(MacError::OutputTooShort {
            required: 4,
            available: 3
        })
    );
    assert_eq!(tag(&mut mac, &[]), [0x58, 0xd2, 0xe7, 0x7e]);
}

#[test]
fn a_failed_init_leaves_the_mac_unusable() {
    let mut mac = cbc_mac(&IV);
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&KEY, &[0; 16])),
        Err(InitError::InvalidIvLength(16))
    );
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn an_engine_of_another_block_size_is_rejected_at_init() {
    let mut mac = FixedCbcMac::<_, 16>::new(DesEngine::new());
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&KEY, &[0; 16])),
        Err(InitError::UnsupportedBlockSize {
            actual: 8,
            required: 16
        })
    );
}

#[test]
fn an_engine_init_error_is_kept_as_the_source() {
    use core::error::Error;

    let mut mac = FixedCbcMac::<_, 8>::new(DesEngine::new());
    let error = mac.init(&KeyWithIvRef::new(&[0; 5], &IV)).unwrap_err();
    assert!(matches!(error, InitError::Cipher(_)));
    assert!(error.source().is_some());
}

/// A padding that always fails.
struct FailingPadding;

impl BlockCipherPadding for FailingPadding {
    type Error = PaddingError;

    fn add_padding(&mut self, _: &mut [u8], _: usize) -> Result<usize, PaddingError> {
        Err(PaddingError::PositionOutOfRange)
    }

    fn pad_count(&self, _: &[u8]) -> Result<usize, PaddingError> {
        Err(PaddingError::CorruptPadding)
    }
}

#[test]
fn a_padding_failure_discards_the_message() {
    let mut mac = FixedPaddedCbcMac::<_, 8, _>::new(DesEngine::new(), FailingPadding);
    mac.init(&KeyWithIvRef::new(&KEY, &ZERO_IV)).unwrap();
    mac.update(INPUT2).unwrap();
    assert_eq!(mac.do_final(&mut [0; 4]), Err(MacError::PaddingFailed));
    assert_eq!(
        MacError::<Infallible>::PaddingFailed.to_string(),
        "MAC padding could not be added"
    );
}

#[cfg(feature = "alloc")]
mod allocating {
    use super::*;
    use tc_macs::{CbcMac, PaddedCbcMac};

    #[test]
    fn the_allocating_macs_match_the_bouncy_castle_vectors() {
        let mut mac = CbcMac::new(DesEngine::new());
        mac.init(&KeyWithIvRef::new(&KEY, &ZERO_IV)).unwrap();
        assert_eq!(tag(&mut mac, INPUT1), [0xf1, 0xd3, 0x0f, 0x68]);
        mac.init(&KeyWithIvRef::new(&KEY, &IV)).unwrap();
        assert_eq!(tag(&mut mac, INPUT1), [0x58, 0xd2, 0xe7, 0x7e]);

        let mut padded = PaddedCbcMac::new(DesEngine::new(), Pkcs7Padding);
        padded.init(&KeyWithIvRef::new(&KEY, &ZERO_IV)).unwrap();
        assert_eq!(tag(&mut padded, INPUT2), [0x18, 0x8f, 0xbd, 0xd5]);
        assert_eq!(tag(&mut padded, INPUT1), [0x70, 0x45, 0xee, 0xcd]);
    }

    #[test]
    fn the_allocating_macs_match_the_fixed_ones_for_every_length() {
        let params = KeyWithIvRef::new(&KEY, &IV);
        let mut mac = CbcMac::with_mac_size(DesEngine::new(), 8);
        mac.init(&params).unwrap();
        let mut padded = PaddedCbcMac::with_mac_size(DesEngine::new(), 8, Pkcs7Padding);
        padded.init(&params).unwrap();
        let mut fixed = FixedCbcMac::<_, 8>::with_mac_size(DesEngine::new(), 8);
        fixed.init(&params).unwrap();
        let mut fixed_padded =
            FixedPaddedCbcMac::<_, 8, _>::with_mac_size(DesEngine::new(), 8, Pkcs7Padding);
        fixed_padded.init(&params).unwrap();

        // One instance computes many messages in a row, which also checks that
        // wiping does not empty the Vec buffers.
        let message: Vec<u8> = (0..40).collect();
        for len in 0..=message.len() {
            assert_eq!(
                tag(&mut mac, &message[..len]),
                tag(&mut fixed, &message[..len])
            );
            assert_eq!(
                tag(&mut padded, &message[..len]),
                tag(&mut fixed_padded, &message[..len])
            );
        }
    }

    #[test]
    fn the_allocating_macs_report_their_tag_size_and_mode_name() {
        let mac = CbcMac::new(DesEngine::new());
        assert_eq!(mac.mac_size(), 4);
        assert_eq!(mac.to_string(), "DES/CBC");
        let padded = PaddedCbcMac::new(DesEngine::new(), Pkcs7Padding);
        assert_eq!(padded.to_string(), "DES/CBC");
    }

    #[test]
    #[should_panic(expected = "CBC-MAC size must be between 1 and the block size")]
    fn an_allocating_mac_rejects_a_tag_longer_than_the_block() {
        CbcMac::with_mac_size(DesEngine::new(), 9);
    }
}
