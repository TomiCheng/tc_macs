//! The vectors are those of Bouncy Castle's `DSTU7564Test`.

use tc_digest::Digest;
use tc_dstu_macs::Dstu7564Mac;
use tc_dstu7564::Dstu7564Digest;
use tc_macs::{InitError, KeyParams, KeyRef, Mac, MacError, MacInit};

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn authenticate(mac_bits: usize, key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Dstu7564Mac::new(mac_bits);
    mac.init(&KeyRef::new(key)).unwrap();
    mac.update(message).unwrap();
    let mut output = vec![0_u8; mac.mac_size()];
    assert_eq!(mac.do_final(&mut output), Ok(mac_bits / 8));
    output
}

#[test]
fn matches_bouncy_castle_vectors() {
    let message = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
    let cases = [
        (
            256,
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "B60594D56FA79BA210314C72C2495087CCD0A99FC04ACFE2A39EF669925D98EE",
        ),
        (
            384,
            "2F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "BEBFD8D730336F043ABACB41829E79A4D320AEDDD8D14024D5B805DA70C396FA295C281A38B30AE728A304B3F5AE490E",
        ),
        (
            512,
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "F270043C06A5C37E65D9D791C5FBFB966E5EE709F8F54019C9A55B76CA40B70100579F269CEC24E347A9D864614CF3ABBF6610742E4DB3BD2ABC000387C49D24",
        ),
    ];

    for (mac_bits, key, expected) in cases {
        assert_eq!(authenticate(mac_bits, &hex(key), &message), hex(expected));
    }
}

#[test]
fn matches_short_bouncy_castle_vector() {
    let key = hex("08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875");
    let message = hex("0001020304050607");
    let expected = hex("383A0B11989ABF61B2CF3EB489351EB7C9AEF70CF5A9D6DBD90F340FF151BA2D");

    assert_eq!(authenticate(256, &key, &message), expected);
}

#[test]
fn matches_bouncy_castle_block_boundary_vectors() {
    let key = hex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");
    let input_1024: Vec<u8> = (0..1024).map(|index| index as u8).collect();
    let input_1023 = &input_1024[..1023];

    assert_eq!(
        authenticate(256, &key, &input_1024),
        hex("165382df70adcb040b17c1aced117d26d598b239ab631271a05f6d0f875ae9ea")
    );
    assert_eq!(
        authenticate(256, &key, input_1023),
        hex("ed45f163e694d990d2d835dca2f3f869a55a31396c8138161b190d5914d50686")
    );
}

#[test]
fn chunking_and_successful_finalization_preserve_initialized_key() {
    let key = hex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");
    let message = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
    let expected = authenticate(256, &key, &message);

    let mut mac = Dstu7564Mac::new(256);
    mac.init(&KeyRef::new(&key)).unwrap();
    for chunk in message.chunks(3) {
        mac.update(chunk).unwrap();
    }
    let mut output = [0_u8; 32];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output.as_slice(), expected);

    mac.update(&message).unwrap();
    mac.do_final(&mut output).unwrap();
    assert_eq!(output.as_slice(), expected);
}

#[test]
fn trait_objects_names_and_errors_work() {
    let key = hex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");
    let message = hex("0001020304050607");
    let mut mac = Dstu7564Mac::new(256);

    assert_eq!(mac.update(&[]), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut []), Err(MacError::NotInitialised));
    assert_eq!(
        mac.init(&KeyRef::new(&[])),
        Err(InitError::InvalidKeyLength(0))
    );

    let params = KeyRef::new(&key);
    let params: &dyn KeyParams = &params;
    mac.init(params).unwrap();

    assert_eq!(
        mac.init(&KeyRef::new(&[])),
        Err(InitError::InvalidKeyLength(0))
    );
    assert_eq!(mac.update(&[]), Err(MacError::NotInitialised));
    mac.init(params).unwrap();

    assert_eq!(mac.to_string(), "DSTU7564Mac");

    let mac: &mut dyn Mac<Error = MacError> = &mut mac;
    mac.update(&message).unwrap();
    assert_eq!(
        mac.do_final(&mut [0_u8; 31]),
        Err(MacError::OutputTooShort {
            required: 32,
            available: 31,
        })
    );

    let mut output = [0_u8; 32];
    assert_eq!(mac.do_final(&mut output), Ok(32));
    assert_eq!(output, authenticate(256, &key, &message).as_slice());
}

#[test]
#[should_panic(expected = "DSTU 7564 bit length must be 256, 384 or 512")]
fn rejects_unsupported_mac_size() {
    let _ = Dstu7564Mac::new(128);
}

#[test]
fn a_key_of_a_whole_number_of_blocks_is_padded_with_one_more_block() {
    // Bouncy Castle's padding overruns its buffer on this key, so the expected
    // tag comes from the digest, with the padding spelled out.
    const BLOCK_BYTES: usize = 64;
    let key = [0x42_u8; BLOCK_BYTES];
    let message = b"attack at dawn";

    let mut padded_key = [0_u8; 2 * BLOCK_BYTES];
    padded_key[..BLOCK_BYTES].copy_from_slice(&key);
    padded_key[BLOCK_BYTES] = 0x80;
    let length_offset = padded_key.len() - 12;
    padded_key[length_offset..length_offset + 4]
        .copy_from_slice(&(8 * BLOCK_BYTES as u32).to_le_bytes());

    let mut message_padding = [0_u8; BLOCK_BYTES - 14];
    message_padding[0] = 0x80;
    let length_offset = message_padding.len() - 12;
    message_padding[length_offset..length_offset + 8]
        .copy_from_slice(&(8 * message.len() as u64).to_le_bytes());

    let mut digest = Dstu7564Digest::new(256);
    digest.update(&padded_key);
    digest.update(message);
    digest.update(&message_padding);
    digest.update(&key.map(|byte| !byte));
    let mut expected = [0_u8; 32];
    digest.do_final(&mut expected);

    assert_eq!(authenticate(256, &key, message), expected);
}

#[test]
fn reset_discards_the_message_and_keeps_the_key() {
    let key = [0x42_u8; 32];
    let mut mac = Dstu7564Mac::new(256);
    mac.init(&KeyRef::new(&key)).unwrap();
    mac.update(b"discarded").unwrap();
    mac.reset();
    mac.update(b"kept").unwrap();

    let mut output = [0_u8; 32];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output.as_slice(), authenticate(256, &key, b"kept"));
}
