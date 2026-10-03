//! GMAC against the vectors of Bouncy Castle C#'s `GMacTest.cs`, which are
//! NIST GCM test vectors with associated data alone.

use tc_aes::AesEngine;
use tc_block_modes::KeyWithIvRef;
use tc_des::DesEngine;
use tc_macs::{Gmac, InitError, Mac, MacError, MacInit};

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

/// (name, key, IV, message, tag); the name gives the key, IV, message and tag
/// lengths in bits.
const VECTORS: [(&str, &str, &str, &str, &str); 11] = [
    (
        "128/96/0/128",
        "11754cd72aec309bf52f7687212e8957",
        "3c819d9a9bed087615030b65",
        "",
        "250327c674aaf477aef2675748cf6971",
    ),
    (
        "128/96/0/120",
        "272f16edb81a7abbea887357a58c1917",
        "794ec588176c703d3d2a7a07",
        "",
        "b6e6f197168f5049aeda32dafbdaeb",
    ),
    (
        "128/96/0/112",
        "81b6844aab6a568c4556a2eb7eae752f",
        "ce600f59618315a6829bef4d",
        "",
        "89b43e9dbc1b4f597dbbc7655bb5",
    ),
    (
        "128/96/0/104",
        "cde2f9a9b1a004165ef9dc981f18651b",
        "29512c29566c7322e1e33e8e",
        "",
        "2e58ce7dabd107c82759c66a75",
    ),
    (
        "128/96/0/96",
        "b01e45cc3088aaba9fa43d81d481823f",
        "5a2c4a66468713456a4bd5e1",
        "",
        "014280f944f53c681164b2ff",
    ),
    (
        "128/96/128/128",
        "77be63708971c4e240d1cb79e8d77feb",
        "e0e00f19fed7ba0136a797f3",
        "7a43ec1d9c0a5a78a0b16533a6213cab",
        "209fcc8d3675ed938e9c7166709dd946",
    ),
    (
        "128/96/128/96",
        "bea48ae4980d27f357611014d4486625",
        "32bddb5c3aa998a08556454c",
        "8a50b0b8c7654bced884f7f3afda2ead",
        "8e0f6d8bf05ffebe6f500eb1",
    ),
    (
        "128/96/384/128",
        "99e3e8793e686e571d8285c564f75e2b",
        "c2dd0ab868da6aa8ad9c0d23",
        "b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c\
         5917ee476541809ac6867a8c399309fc",
        "3f4fba100eaf1f34b0baadaae9995d85",
    ),
    (
        "128/96/384/96",
        "c77acd1b0918e87053cb3e51651e7013",
        "39ff857a81745d10f718ac00",
        "407992f82ea23b56875d9a3cb843ceb83fd27cb954f7c5534d58539fe96fb534\
         502a1b38ea4fac134db0a42de4be1137",
        "2a5dc173285375dc82835876",
    ),
    (
        "128/1024/0/128",
        "d0f1f4defa1e8c08b4b26d576392027c",
        "42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ec\
         c021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2f\
         a626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6\
         a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac",
        "",
        "7ab49b57ddf5f62c427950111c5c4f0d",
    ),
    (
        "128/1024/384/96",
        "3cce72d37933394a8cac8a82deada8f0",
        "aa2f0d676d705d9733c434e481972d4888129cf7ea55c66511b9c0d25a92a174\
         b1e28aa072f27d4de82302828955aadcb817c4907361869bd657b45ff4a6f323\
         871987fcf9413b0702d46667380cd493ed24331a28b9ce5bbfa82d3a6e7679fc\
         ce81254ba64abcad14fd18b22c560a9d2c1cd1d3c42dac44c683edf92aced894",
        "5686b458e9c176f4de8428d9ebd8e12f569d1c7595cf49a4b0654ab194409f86\
         c0dd3fdb8eb18033bb4338c70f0b97d1",
        "a3a9444b21f330c3df64c8b6",
    ),
];

#[test]
fn gmac_matches_the_bouncy_castle_vectors() {
    for (name, key, iv, message, expected) in VECTORS {
        let expected = hex(expected);
        let mut mac = Gmac::with_mac_size(AesEngine::new(), expected.len());
        mac.init(&KeyWithIvRef::new(&hex(key), &hex(iv))).unwrap();
        assert_eq!(tag(&mut mac, &hex(message)), expected, "{name}");
    }
}

#[test]
fn the_tag_does_not_depend_on_how_the_input_is_split() {
    let (_, key, iv, message, expected) = VECTORS[7];
    let (key, iv, message) = (hex(key), hex(iv), hex(message));
    for split in 0..=message.len() {
        let mut mac = Gmac::new(AesEngine::new());
        mac.init(&KeyWithIvRef::new(&key, &iv)).unwrap();
        mac.update(&message[..split]).unwrap();
        assert_eq!(
            tag(&mut mac, &message[split..]),
            hex(expected),
            "split {split}"
        );
    }
}

#[test]
fn do_final_leaves_the_mac_finalized_until_a_fresh_nonce() {
    let (_, key, iv, message, expected) = VECTORS[5];
    let (key, iv) = (hex(key), hex(iv));
    let mut mac = Gmac::new(AesEngine::new());
    mac.init(&KeyWithIvRef::new(&key, &iv)).unwrap();
    assert_eq!(tag(&mut mac, &hex(message)), hex(expected));

    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    mac.reset();
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&key, &iv)),
        Err(InitError::NonceReuse)
    );

    let mut fresh = iv.clone();
    fresh[0] ^= 1;
    mac.init(&KeyWithIvRef::new(&key, &fresh)).unwrap();
    mac.update(b"x").unwrap();
}

#[test]
fn reset_before_do_final_discards_the_message_and_keeps_the_nonce() {
    let (_, key, iv, message, expected) = VECTORS[5];
    let mut mac = Gmac::new(AesEngine::new());
    mac.init(&KeyWithIvRef::new(&hex(key), &hex(iv))).unwrap();
    mac.update(b"discarded").unwrap();
    mac.reset();
    assert_eq!(tag(&mut mac, &hex(message)), hex(expected));
}

#[test]
fn gmac_names_itself_after_its_engine() {
    let mac = Gmac::new(AesEngine::new());
    assert_eq!(mac.to_string(), "AES-GMAC");
    assert_eq!(mac.mac_size(), 16);
}

#[test]
#[should_panic(expected = "GMAC size must be between 4 and 16 bytes")]
fn a_tag_shorter_than_four_bytes_is_rejected_at_construction() {
    Gmac::with_mac_size(AesEngine::new(), 3);
}

#[test]
#[should_panic(expected = "GMAC size must be between 4 and 16 bytes")]
fn a_tag_longer_than_the_block_is_rejected_at_construction() {
    Gmac::with_mac_size(AesEngine::new(), 17);
}

#[test]
fn using_gmac_before_init_fails() {
    let mut mac = Gmac::new(AesEngine::new());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
    assert_eq!(mac.do_final(&mut [0; 16]), Err(MacError::NotInitialised));
}

#[test]
fn a_short_output_buffer_is_rejected_without_losing_the_message() {
    let (_, key, iv, message, expected) = VECTORS[5];
    let mut mac = Gmac::new(AesEngine::new());
    mac.init(&KeyWithIvRef::new(&hex(key), &hex(iv))).unwrap();
    mac.update(&hex(message)).unwrap();
    assert_eq!(
        mac.do_final(&mut [0; 15]),
        Err(MacError::OutputTooShort {
            required: 16,
            available: 15
        })
    );
    assert_eq!(tag(&mut mac, &[]), hex(expected));
}

#[test]
fn init_rejects_an_empty_iv_and_a_64_bit_engine() {
    let mut mac = Gmac::new(AesEngine::new());
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&[0; 16], &[])),
        Err(InitError::InvalidIvLength(0))
    );

    let mut mac = Gmac::new(DesEngine::new());
    assert_eq!(
        mac.init(&KeyWithIvRef::new(&[0; 8], &[0; 12])),
        Err(InitError::UnsupportedBlockSize {
            actual: 8,
            required: 16
        })
    );
}

#[test]
fn an_engine_init_error_is_kept_as_the_source() {
    use core::error::Error;

    let mut mac = Gmac::new(AesEngine::new());
    let error = mac
        .init(&KeyWithIvRef::new(&[0; 15], &[0; 12]))
        .unwrap_err();
    assert!(matches!(error, InitError::Cipher(_)));
    assert!(error.source().is_some());
    assert_eq!(mac.update(b"x"), Err(MacError::NotInitialised));
}
