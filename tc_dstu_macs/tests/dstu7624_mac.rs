//! The vectors are those of the `MacTests` of Bouncy Castle's `DSTU7624Test`,
//! which has none for the 256-bit block.

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_dstu_macs::{
    Dstu7624Mac128, Dstu7624Mac256, Dstu7624Mac512, Dstu7624MacCreateError, Dstu7624MacError,
};
use tc_dstu7624::Dstu7624Engine256;
use tc_macs::{InitError, KeyRef, Mac, MacInit};

#[test]
fn matches_the_bouncy_castle_128_bit_block_vector() {
    let key = core::array::from_fn::<_, 16, _>(|index| index as u8);
    let message = core::array::from_fn::<_, 48, _>(|index| (index + 0x20) as u8);
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&message).unwrap();

    let mut output = [0_u8; 16];
    mac.do_final(&mut output).unwrap();
    assert_eq!(
        output,
        [
            0x12, 0x3b, 0x4e, 0xab, 0x8e, 0x63, 0xec, 0xf3, 0xe6, 0x45, 0xa9, 0x9c, 0x11, 0x15,
            0xe2, 0x41,
        ]
    );
}

#[test]
fn matches_the_bouncy_castle_512_bit_block_vector() {
    let key = core::array::from_fn::<_, 64, _>(|index| index as u8);
    let message = core::array::from_fn::<_, 128, _>(|index| (index + 0x40) as u8);
    let mut mac = Dstu7624Mac512::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    for chunk in message.chunks(11) {
        mac.update(chunk).unwrap();
    }

    let mut output = [0_u8; 16];
    mac.do_final(&mut output).unwrap();
    assert_eq!(
        output,
        [
            0x72, 0x79, 0xfa, 0x6b, 0xc8, 0xef, 0x75, 0x25, 0xb2, 0xb3, 0x52, 0x60, 0xd0, 0x0a,
            0x17, 0x43,
        ]
    );
}

#[test]
fn rejects_a_partial_final_block_without_losing_it() {
    let key = [0_u8; 16];
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&[0_u8; 15]).unwrap();
    assert_eq!(
        mac.do_final(&mut [0_u8; 16]),
        Err(Dstu7624MacError::InputNotBlockAligned {
            block_size: 16,
            remainder: 15,
        })
    );
    mac.update(&[0]).unwrap();
    assert_eq!(mac.do_final(&mut [0_u8; 16]), Ok(16));
}

#[test]
fn the_256_bit_block_chains_the_cipher_as_the_other_blocks_do() {
    let key = core::array::from_fn::<_, 32, _>(|index| index as u8);
    let message = core::array::from_fn::<_, 64, _>(|index| (index + 0x20) as u8);

    let mut cipher = Dstu7624Engine256::default();
    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(&key))
        .unwrap();
    let mut delta = [0_u8; 32];
    cipher.process_block(&[0; 32], &mut delta).unwrap();
    let mut chain = [0_u8; 32];
    cipher.process_block(&message[..32], &mut chain).unwrap();
    let last = core::array::from_fn::<_, 32, _>(|i| chain[i] ^ message[32 + i] ^ delta[i]);
    let mut expected = [0_u8; 32];
    cipher.process_block(&last, &mut expected).unwrap();

    let mut mac = Dstu7624Mac256::new(256).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&message).unwrap();
    let mut output = [0_u8; 32];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn a_tag_must_be_whole_bytes_and_fit_in_the_block() {
    for bits in [0, 7, 136] {
        assert_eq!(
            Dstu7624Mac128::new(bits).err(),
            Some(Dstu7624MacCreateError::InvalidMacSize {
                requested_bits: bits,
                maximum_bits: 128,
            })
        );
    }
    assert!(Dstu7624Mac128::new(8).is_ok());
}

#[test]
fn a_short_output_buffer_leaves_the_message_in_place() {
    let key = [0_u8; 16];
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&[0x11; 16]).unwrap();
    assert_eq!(
        mac.do_final(&mut [0_u8; 15]),
        Err(Dstu7624MacError::OutputTooShort {
            required: 16,
            available: 15,
        })
    );
    let mut first = [0_u8; 16];
    mac.do_final(&mut first).unwrap();

    mac.update(&[0x11; 16]).unwrap();
    let mut second = [0_u8; 16];
    mac.do_final(&mut second).unwrap();
    assert_eq!(first, second);
}

#[test]
fn reset_discards_the_message_and_keeps_the_key() {
    let key = [0_u8; 16];
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(&[0x11; 16]).unwrap();
    let mut expected = [0_u8; 16];
    mac.do_final(&mut expected).unwrap();

    mac.update(&[0x22; 5]).unwrap();
    mac.reset();
    mac.update(&[0x11; 16]).unwrap();
    let mut output = [0_u8; 16];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn a_refused_key_leaves_the_mac_uninitialized() {
    let mut mac = Dstu7624Mac128::new(128).unwrap();
    assert_eq!(mac.update(&[]), Err(Dstu7624MacError::NotInitialised));
    assert_eq!(
        mac.do_final(&mut [0_u8; 16]),
        Err(Dstu7624MacError::NotInitialised)
    );

    mac.init(&KeyRef::new(&[0_u8; 16])).unwrap();
    assert!(matches!(
        mac.init(&KeyRef::new(&[0_u8; 15])),
        Err(InitError::Cipher(_))
    ));
    assert_eq!(mac.update(&[]), Err(Dstu7624MacError::NotInitialised));
}

#[test]
fn display_writes_the_bouncy_castle_name() {
    assert_eq!(Dstu7624Mac128::new(128).unwrap().to_string(), "Dstu7624Mac");
}
