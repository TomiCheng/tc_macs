//! CFB-MAC against the DES vectors of Bouncy Castle C#'s `MacTest.cs`.

#![cfg(feature = "cfb-mac")]

use tc_block_modes::KeyWithIvRef;
use tc_block_padding::Pkcs7Padding;
use tc_des::DesEngine;
use tc_macs::{FixedCfbMac, FixedPaddedCfbMac, InitError, Mac, MacError, MacInit};

const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];

const INPUT1: &[u8] = b"7654321 Now is the time for ";
const INPUT2: &[u8] = b"7654321 ";

fn tag<M: Mac>(mac: &mut M, input: &[u8]) -> Vec<u8> {
    mac.update(input).unwrap();
    let mut output = vec![0; mac.mac_size()];
    let written = mac.do_final(&mut output).unwrap();
    assert_eq!(written, output.len());
    output
}

fn cfb8_mac(iv: &[u8; 8]) -> FixedCfbMac<DesEngine, 8> {
    let mut mac = FixedCfbMac::new(DesEngine::new());
    mac.init(&KeyWithIvRef::new(&KEY, iv)).unwrap();
    mac
}

/// A segment of a whole block, so that padding meets partial segments.
fn cfb64_mac() -> FixedCfbMac<DesEngine, 8> {
    let mut mac = FixedCfbMac::with_sizes(DesEngine::new(), 8, 4);
    mac.init(&KeyWithIvRef::new(&KEY, &IV)).unwrap();
    mac
}

fn pkcs7_cfb64_mac() -> FixedPaddedCfbMac<DesEngine, 8, Pkcs7Padding> {
    let mut mac = FixedPaddedCfbMac::with_sizes(DesEngine::new(), 8, 4, Pkcs7Padding);
    mac.init(&KeyWithIvRef::new(&KEY, &IV)).unwrap();
    mac
}

#[test]
fn a_cfb8_mac_matches_the_bouncy_castle_vectors() {
    assert_eq!(tag(&mut cfb8_mac(&IV), INPUT1), [0xcd, 0x64, 0x74, 0x03]);
    // MacTest's output4: Bouncy Castle re-keys the same instance with a key
    // alone, and MacCFBBlockCipher then keeps the previous IV.
    assert_eq!(tag(&mut cfb8_mac(&IV), INPUT2), [0x3a, 0xf5, 0x49, 0xc9]);
}

#[test]
fn the_tag_does_not_depend_on_how_the_input_is_split() {
    let message: Vec<u8> = (0..40).collect();
    for len in 0..=message.len() {
        let message = &message[..len];
        let expected = (
            tag(&mut cfb8_mac(&IV), message),
            tag(&mut cfb64_mac(), message),
        );
        for split in 0..=len {
            let mut cfb8 = cfb8_mac(&IV);
            cfb8.update(&message[..split]).unwrap();
            let mut cfb64 = cfb64_mac();
            cfb64.update(&message[..split]).unwrap();
            let actual = (
                tag(&mut cfb8, &message[split..]),
                tag(&mut cfb64, &message[split..]),
            );
            assert_eq!(actual, expected, "length {len}, split {split}");
        }
    }
}

#[test]
fn padding_fills_only_a_partial_final_segment() {
    // A partial segment: the same as PKCS#7 added by hand.
    let mut padded_by_hand = b"12345".to_vec();
    padded_by_hand.extend_from_slice(&[3; 3]);
    assert_eq!(
        tag(&mut pkcs7_cfb64_mac(), b"12345"),
        tag(&mut cfb64_mac(), &padded_by_hand)
    );

    // A full segment: Bouncy Castle adds nothing, so the tag is the unpadded
    // one.
    assert_eq!(
        tag(&mut pkcs7_cfb64_mac(), INPUT2),
        tag(&mut cfb64_mac(), INPUT2)
    );
}

#[test]
fn do_final_and_reset_restart_the_mac_under_the_same_key() {
    let mut mac = cfb8_mac(&IV);
    assert_eq!(tag(&mut mac, INPUT1), [0xcd, 0x64, 0x74, 0x03]);
    mac.update(b"discarded").unwrap();
    mac.reset();
    assert_eq!(tag(&mut mac, INPUT1), [0xcd, 0x64, 0x74, 0x03]);
}

#[test]
fn a_mac_reports_its_tag_size_and_its_feedback_in_the_name() {
    let mac = FixedCfbMac::<_, 8>::new(DesEngine::new());
    assert_eq!(mac.mac_size(), 4);
    assert_eq!(mac.to_string(), "DES/CFB8");
    let padded = FixedPaddedCfbMac::<_, 8, _>::with_sizes(DesEngine::new(), 8, 8, Pkcs7Padding);
    assert_eq!(padded.mac_size(), 8);
    assert_eq!(padded.to_string(), "DES/CFB64");
}

#[test]
#[should_panic(expected = "CFB-MAC feedback size must be between 1 and the block size")]
fn a_feedback_size_larger_than_the_block_is_rejected_at_construction() {
    FixedCfbMac::<_, 8>::with_sizes(DesEngine::new(), 9, 4);
}

#[test]
#[should_panic(expected = "CFB-MAC size must be between 1 and the block size")]
fn a_tag_longer_than_the_block_is_rejected_at_construction() {
    FixedCfbMac::<_, 8>::with_sizes(DesEngine::new(), 1, 9);
}

#[test]
fn using_a_mac_before_init_fails() {
    let mut mac = FixedCfbMac::<_, 8>::new(DesEngine::new());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut [0; 4]), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_is_rejected_without_losing_the_message() {
    let mut mac = cfb8_mac(&IV);
    mac.update(INPUT1).unwrap();
    assert_eq!(
        mac.do_final(&mut [0; 3]),
        Err(MacError::OutputTooShort {
            required: 4,
            available: 3
        })
    );
    assert_eq!(tag(&mut mac, &[]), [0xcd, 0x64, 0x74, 0x03]);
}

#[test]
fn init_rejects_a_wrong_iv_length_and_leaves_the_mac_unusable() {
    let mut mac = cfb8_mac(&IV);
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&KEY, &[0; 4])),
        Err(InitError::InvalidIvLength(4))
    );
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn an_engine_of_another_block_size_is_rejected_at_init() {
    let mut mac = FixedCfbMac::<_, 16>::new(DesEngine::new());
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

    let mut mac = FixedCfbMac::<_, 8>::new(DesEngine::new());
    let error = mac.init(&KeyWithIvRef::new(&[0; 5], &IV)).unwrap_err();
    assert!(matches!(error, InitError::Cipher(_)));
    assert!(error.source().is_some());
}

#[cfg(feature = "alloc")]
mod allocating {
    use super::*;
    use tc_macs::{CfbMac, PaddedCfbMac};

    #[test]
    fn the_allocating_macs_match_the_bouncy_castle_vectors() {
        let mut mac = CfbMac::new(DesEngine::new());
        mac.init(&KeyWithIvRef::new(&KEY, &IV)).unwrap();
        assert_eq!(tag(&mut mac, INPUT1), [0xcd, 0x64, 0x74, 0x03]);
        assert_eq!(tag(&mut mac, INPUT2), [0x3a, 0xf5, 0x49, 0xc9]);
        assert_eq!(mac.to_string(), "DES/CFB8");
    }

    #[test]
    fn the_allocating_macs_match_the_fixed_ones_for_every_length() {
        let params = KeyWithIvRef::new(&KEY, &IV);
        let mut mac = CfbMac::with_sizes(DesEngine::new(), 3, 8);
        mac.init(&params).unwrap();
        let mut padded = PaddedCfbMac::with_sizes(DesEngine::new(), 3, 8, Pkcs7Padding);
        padded.init(&params).unwrap();
        let mut fixed = FixedCfbMac::<_, 8>::with_sizes(DesEngine::new(), 3, 8);
        fixed.init(&params).unwrap();
        let mut fixed_padded =
            FixedPaddedCfbMac::<_, 8, _>::with_sizes(DesEngine::new(), 3, 8, Pkcs7Padding);
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
    #[should_panic(expected = "CFB-MAC size must be between 1 and the block size")]
    fn an_allocating_mac_rejects_a_tag_longer_than_the_block() {
        CfbMac::with_sizes(DesEngine::new(), 1, 9);
    }
}
