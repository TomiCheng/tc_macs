//! CMAC against the AES vectors of NIST SP 800-38B (RFC 4493) and the DESede
//! vector of Bouncy Castle C#.

#![cfg(feature = "cmac")]

use tc_aes::AesEngine;
use tc_des::{DesEdeEngine, DesEngine};
use tc_macs::{FixedCmac, InitError, KeyRef, Mac, MacError, MacInit};

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

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";

/// 0, 16, 40 and 64 bytes: empty, one block, a partial final block, and four
/// blocks.
const MESSAGES: [&str; 4] = [
    "",
    "6bc1bee22e409f96e93d7e117393172a",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
     30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
];

const AES_VECTORS: [(&str, [&str; 4]); 3] = [
    (
        KEY_128,
        [
            "bb1d6929e95937287fa37d129b756746",
            "070a16b46b4d4144f79bdd9dd04a287c",
            "dfa66747de9ae63030ca32611497c827",
            "51f0bebf7e3b9d92fc49741779363cfe",
        ],
    ),
    (
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        [
            "d17ddf46adaacde531cac483de7a9367",
            "9e99a7bf31e710900662f65e617c5184",
            "8a1de5be2eb31aad089a82e6ee908b0e",
            "a1d5df0eed790f794d77589659f39a11",
        ],
    ),
    (
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        [
            "028962f61b7bf89efc6b551f4667d983",
            "28a7023f452e8f82bd4bf28d8c37c35c",
            "aaf3d8f1de5640c232f5b169b9c911e6",
            "e1992190549f6ed5696a2c056c315410",
        ],
    ),
];

fn aes_cmac(key: &[u8]) -> FixedCmac<AesEngine, 16> {
    let mut mac = FixedCmac::new(AesEngine::new());
    mac.init(&KeyRef::new(key)).unwrap();
    mac
}

#[test]
fn an_aes_cmac_matches_the_nist_vectors_for_every_key_size() {
    for (key, expected) in AES_VECTORS {
        let mut mac = aes_cmac(&hex(key));
        for (message, expected) in MESSAGES.into_iter().zip(expected) {
            assert_eq!(tag(&mut mac, &hex(message)), hex(expected), "key {key}");
        }
    }
}

#[test]
fn a_des_ede_cmac_matches_the_bouncy_castle_vector() {
    let mut mac = FixedCmac::<_, 8>::new(DesEdeEngine::new());
    mac.init(&KeyRef::new(&hex(KEY_128))).unwrap();
    assert_eq!(tag(&mut mac, &[]), hex("1ca670dea381d37c"));
}

#[test]
fn the_tag_does_not_depend_on_how_the_input_is_split() {
    let message = hex(MESSAGES[3]);
    let expected = hex(AES_VECTORS[0].1[3]);
    let mut mac = aes_cmac(&hex(KEY_128));
    for split in 0..=message.len() {
        mac.update(&message[..split]).unwrap();
        assert_eq!(tag(&mut mac, &message[split..]), expected, "split {split}");
    }
}

#[test]
fn a_truncated_tag_is_the_prefix_of_the_full_one() {
    let mut mac = FixedCmac::<_, 16>::with_mac_size(AesEngine::new(), 8);
    mac.init(&KeyRef::new(&hex(KEY_128))).unwrap();
    assert_eq!(mac.mac_size(), 8);
    assert_eq!(
        tag(&mut mac, &hex(MESSAGES[1])),
        hex("070a16b46b4d4144f79bdd9dd04a287c")[..8]
    );
}

#[test]
fn reset_discards_the_message_and_keeps_the_key() {
    let mut mac = aes_cmac(&hex(KEY_128));
    mac.update(b"discarded").unwrap();
    mac.reset();
    assert_eq!(tag(&mut mac, &hex(MESSAGES[2])), hex(AES_VECTORS[0].1[2]));
}

#[test]
fn a_cmac_names_itself_after_its_engine() {
    assert_eq!(
        FixedCmac::<_, 16>::new(AesEngine::new()).to_string(),
        "AES/CMAC"
    );
    assert_eq!(FixedCmac::<_, 16>::new(AesEngine::new()).mac_size(), 16);
}

#[test]
#[should_panic(expected = "CMAC supports 64- and 128-bit block ciphers only")]
fn a_block_size_other_than_64_or_128_bits_is_rejected_at_construction() {
    FixedCmac::<_, 32>::new(AesEngine::new());
}

#[test]
#[should_panic(expected = "CMAC size must be between 1 and the block size")]
fn a_tag_longer_than_the_block_is_rejected_at_construction() {
    FixedCmac::<_, 16>::with_mac_size(AesEngine::new(), 17);
}

#[test]
fn using_a_cmac_before_init_fails() {
    let mut mac = FixedCmac::<_, 16>::new(AesEngine::new());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut [0; 16]), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_is_rejected_without_losing_the_message() {
    let mut mac = aes_cmac(&hex(KEY_128));
    mac.update(&hex(MESSAGES[2])).unwrap();
    assert_eq!(
        mac.do_final(&mut [0; 15]),
        Err(MacError::OutputTooShort {
            required: 16,
            available: 15
        })
    );
    assert_eq!(tag(&mut mac, &[]), hex(AES_VECTORS[0].1[2]));
}

#[test]
fn a_failed_init_keeps_the_engine_error_and_leaves_the_cmac_unusable() {
    use core::error::Error;

    let mut mac = aes_cmac(&hex(KEY_128));
    let error = mac.init(&KeyRef::new(&[0; 15])).unwrap_err();
    assert!(matches!(error, InitError::Cipher(_)));
    assert!(error.source().is_some());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}

#[test]
fn an_engine_of_another_block_size_is_rejected_at_init() {
    let mut mac = FixedCmac::<_, 16>::new(DesEngine::new());
    assert_eq!(
        mac.init(&KeyRef::new(&[0; 8])),
        Err(InitError::UnsupportedBlockSize {
            actual: 8,
            required: 16
        })
    );
}

#[cfg(feature = "alloc")]
mod allocating {
    use super::*;
    use tc_macs::Cmac;

    #[test]
    fn the_allocating_cmac_matches_the_nist_vectors() {
        for (key, expected) in AES_VECTORS {
            let mut mac = Cmac::new(AesEngine::new());
            mac.init(&KeyRef::new(&hex(key))).unwrap();
            for (message, expected) in MESSAGES.into_iter().zip(expected) {
                assert_eq!(tag(&mut mac, &hex(message)), hex(expected), "key {key}");
            }
        }
        let mut mac = Cmac::new(DesEdeEngine::new());
        mac.init(&KeyRef::new(&hex(KEY_128))).unwrap();
        assert_eq!(tag(&mut mac, &[]), hex("1ca670dea381d37c"));
        assert_eq!(mac.to_string(), "DESede/CMAC");
    }

    #[test]
    #[should_panic(expected = "CMAC supports 64- and 128-bit block ciphers only")]
    fn the_allocating_cmac_rejects_other_block_sizes() {
        struct FourByteBlocks;

        impl tc_block_cipher::BlockCipher for FourByteBlocks {
            type Error = tc_block_cipher::BlockError;

            fn block_size(&self) -> usize {
                4
            }

            fn process_block(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize, Self::Error> {
                unreachable!()
            }
        }

        Cmac::new(FourByteBlocks);
    }
}
