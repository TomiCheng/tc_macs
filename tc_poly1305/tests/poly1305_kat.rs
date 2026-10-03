use tc_macs::{InitError, KeyParams, KeyRef, Mac, MacError, MacInit};
use tc_poly1305::{KEY_BYTES, Poly1305, TAG_BYTES};

const RFC_KEY: [u8; KEY_BYTES] = [
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
];
const RFC_MESSAGE: &[u8] = b"Cryptographic Forum Research Group";
const RFC_TAG: [u8; TAG_BYTES] = [
    0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn initialized(key: &[u8]) -> Result<Poly1305, InitError> {
    let params = KeyRef::new(key);
    let mut engine = Poly1305::new();
    engine.init(&params)?;
    Ok(engine)
}

fn authenticate(key: &[u8], message: &[u8]) -> [u8; TAG_BYTES] {
    let mut engine = initialized(key).unwrap();
    engine.update(message).unwrap();
    let mut tag = [0_u8; TAG_BYTES];
    assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
    tag
}

#[test]
fn matches_rfc_8439_vector() {
    assert_eq!(authenticate(&RFC_KEY, RFC_MESSAGE), RFC_TAG);
}

#[test]
fn matches_bouncy_castle_raw_vector() {
    let key = hex("eea6a7251c1e72916d11c2cb214d3c25\
         2539121d8e234e652d651fa4c8cff880");
    let message = hex(
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a\
         c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738\
         b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da\
         99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
    );
    let expected = hex("f3ffc7703f9400e52a7dfb4b3d3305d9");

    assert_eq!(authenticate(&key, &message), expected.as_slice());
}

#[test]
fn every_chunk_size_matches_rfc_vector() {
    for chunk_size in 1..=RFC_MESSAGE.len() {
        let mut engine = initialized(&RFC_KEY).unwrap();
        for chunk in RFC_MESSAGE.chunks(chunk_size) {
            engine.update(chunk).unwrap();
        }

        let mut tag = [0_u8; TAG_BYTES];
        engine.do_final(&mut tag).unwrap();
        assert_eq!(tag, RFC_TAG, "chunk size {chunk_size}");
    }
}

#[test]
fn empty_message_tag_is_the_second_key_half() {
    assert_eq!(authenticate(&RFC_KEY, &[]), RFC_KEY[16..]);
}

#[test]
fn caller_params_dynamic_dispatch_names_and_errors_work() {
    let mut engine = Poly1305::new();
    assert_eq!(engine.update(&[]), Err(MacError::NotInitialised));
    assert_eq!(engine.do_final(&mut []), Err(MacError::NotInitialised));

    let params = KeyRef::new(&RFC_KEY);
    let params: &dyn KeyParams = &params;
    engine.init(params).unwrap();

    assert_eq!(engine.to_string(), "Poly1305");

    let mac: &mut dyn Mac<Error = MacError> = &mut engine;
    assert_eq!(mac.mac_size(), TAG_BYTES);
    mac.update(RFC_MESSAGE).unwrap();
    assert_eq!(
        mac.do_final(&mut [0_u8; TAG_BYTES - 1]),
        Err(MacError::OutputTooShort {
            required: TAG_BYTES,
            available: TAG_BYTES - 1,
        })
    );
    let mut tag = [0_u8; TAG_BYTES];
    assert_eq!(mac.do_final(&mut tag), Ok(TAG_BYTES));
    assert_eq!(tag, RFC_TAG);

    let short_key = [0_u8; KEY_BYTES - 1];
    let params = KeyRef::new(&short_key);
    assert_eq!(
        engine.init(&params),
        Err(InitError::InvalidKeyLength(KEY_BYTES - 1))
    );
    assert_eq!(engine.update(&[]), Err(MacError::NotInitialised));
}

#[test]
fn do_final_consumes_the_one_time_key() {
    let mut engine = initialized(&RFC_KEY).unwrap();
    engine.update(RFC_MESSAGE).unwrap();
    let mut tag = [0_u8; TAG_BYTES];
    engine.do_final(&mut tag).unwrap();

    assert_eq!(engine.update(RFC_MESSAGE), Err(MacError::NotInitialised));
    assert_eq!(engine.do_final(&mut tag), Err(MacError::NotInitialised));
    engine.reset();
    assert_eq!(engine.update(&[]), Err(MacError::NotInitialised));
}

#[test]
fn reset_before_do_final_keeps_the_key() {
    let mut engine = initialized(&RFC_KEY).unwrap();
    engine.update(b"discarded").unwrap();
    engine.reset();
    engine.update(RFC_MESSAGE).unwrap();
    let mut tag = [0_u8; TAG_BYTES];
    engine.do_final(&mut tag).unwrap();
    assert_eq!(tag, RFC_TAG);
}

#[test]
fn a_short_output_buffer_does_not_consume_the_key() {
    let mut engine = initialized(&RFC_KEY).unwrap();
    engine.update(RFC_MESSAGE).unwrap();
    assert!(engine.do_final(&mut [0_u8; TAG_BYTES - 1]).is_err());
    let mut tag = [0_u8; TAG_BYTES];
    engine.do_final(&mut tag).unwrap();
    assert_eq!(tag, RFC_TAG);
}
