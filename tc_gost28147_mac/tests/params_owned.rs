#![cfg(feature = "alloc")]
//! The IV vector was produced with Bouncy Castle's `Gost28147Mac`, as in
//! `gost28147_mac_kat.rs`.

use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_gost28147::{Gost28147Params, s_box};
use tc_gost28147_mac::{Gost28147Mac, Gost28147MacParamsOwned, Gost28147MacParamsRef};
use tc_macs::{InitError, Mac, MacInit};
use tc_zeroize::Zeroize;

const KEY: [u8; 32] = [
    0x6d, 0x14, 0x5d, 0xc9, 0x93, 0xf4, 0x01, 0x9e, 0x10, 0x42, 0x80, 0xdf, 0x6f, 0xcd, 0x8c, 0xd8,
    0xe0, 0x1e, 0x10, 0x1e, 0x4c, 0x11, 0x3d, 0x7e, 0xc4, 0xf4, 0x69, 0xce, 0x6d, 0xcd, 0x9e, 0x49,
];
const IV: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const MESSAGE: &[u8] = b"what do ya want for nothing?";

fn tag<P>(params: &P) -> [u8; 4]
where
    Gost28147Mac: MacInit<P, Error = InitError>,
{
    let mut mac = Gost28147Mac::new();
    mac.init(params).unwrap();
    mac.update(MESSAGE).unwrap();
    let mut output = [0_u8; 4];
    mac.do_final(&mut output).unwrap();
    output
}

#[test]
fn owned_parameters_match_the_bouncy_castle_vector_with_the_default_s_box() {
    let params = Gost28147MacParamsOwned::new(KEY.to_vec(), IV.to_vec());
    assert_eq!(params.s_box(), s_box::E_A);
    assert_eq!(tag(&params), [0x0c, 0xae, 0xfa, 0xa3]);
}

#[test]
fn a_selected_s_box_gives_the_same_tag_as_the_borrowed_parameters() {
    let owned =
        Gost28147MacParamsOwned::new(KEY.to_vec(), IV.to_vec()).with_s_box(s_box::E_B.to_vec());
    let borrowed = Gost28147MacParamsRef::new(&KEY, &IV).with_s_box(&s_box::E_B);

    assert_eq!(owned.s_box(), s_box::E_B);
    assert_eq!(tag(&owned), tag(&borrowed));
    assert_ne!(tag(&owned), [0x0c, 0xae, 0xfa, 0xa3]);
}

#[test]
fn lengths_are_judged_by_init_and_not_by_the_constructor() {
    let mut mac = Gost28147Mac::new();
    assert_eq!(
        mac.init(&Gost28147MacParamsOwned::new(vec![0; 31], IV.to_vec())),
        Err(InitError::InvalidKeyLength(31))
    );
    assert_eq!(
        mac.init(&Gost28147MacParamsOwned::new(KEY.to_vec(), vec![0; 7])),
        Err(InitError::InvalidIvLength(7))
    );
    assert_eq!(
        mac.init(&Gost28147MacParamsOwned::new(KEY.to_vec(), IV.to_vec()).with_s_box(vec![0; 7])),
        Err(InitError::InvalidSBoxLength(7))
    );
}

#[test]
fn zeroize_clears_the_key_the_s_box_and_the_iv() {
    let mut params = Gost28147MacParamsOwned::new(KEY.to_vec(), IV.to_vec());
    params.zeroize();
    assert_eq!(params.key(), &[] as &[u8]);
    assert_eq!(params.s_box(), &[] as &[u8]);
    assert_eq!(params.iv(), &[] as &[u8]);
}

#[test]
fn debug_shows_only_the_lengths() {
    let params = Gost28147MacParamsOwned::new(KEY.to_vec(), IV.to_vec());
    assert_eq!(
        format!("{params:?}"),
        "Gost28147MacParamsOwned { key_len: 32, s_box_len: 128, iv_len: 8 }"
    );
}
