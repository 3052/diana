#![allow(dead_code)]
#![allow(deprecated)] // GenericArray from aes

use aes::{
    Aes128Dec, Block,
    cipher::{BlockDecrypt, KeyInit},
};
use binrw::{BinRead, helpers::until_eof, io::TakeSeekExt};
use playready::{Device, certificate::CertificateChain};
use std::fs::File;

#[derive(BinRead, Debug)]
#[br(big, magic = b"PRKF")]
struct Prkf {
    version: u32,
    length: u32,
    #[br(parse_with = until_eof)]
    tlvs: Vec<Tlv>,
}

#[derive(BinRead, Debug)]
struct Tlv {
    type_: u32,
    length: u32,
    #[br(args { type_, length: length - 8 })]
    value: TlvInner,
}

#[derive(BinRead, Debug)]
#[br(big, import { type_: u32, length: u32 })]
enum TlvInner {
    #[br(pre_assert(type_ == 0x1100e))]
    CertChain(#[br(args(length))] CertChain),
    #[br(pre_assert(type_ == 0x31009))]
    EncryptedKeysContainer(#[br(args(length))] EncryptedKeysContainer),
    Unknown(#[br(count = length)] Vec<u8>),
}

#[derive(BinRead, Debug)]
#[br(big, import(length: u32))]
struct CertChain {
    unknown: [u8; 8],
    #[br(count = length - 8)]
    bytes: Vec<u8>,
}

#[derive(BinRead, Debug)]
#[br(big, import(length: u32))]
struct EncryptedKeysContainer {
    #[br(map_stream = |s| s.take_seek(u64::from(length)), parse_with = until_eof)]
    tlvs: Vec<EncryptedKey>,
}

#[derive(BinRead, Debug)]
#[br(big, assert(type_ == 0x1100a && length == 0xc8 && pub_key_length == 0x40 && priv_key_length == 0x20))]
struct EncryptedKey {
    type_: u32,  // from TLV
    length: u32, // from TLV
    unknown: [u8; 4],
    pub_key_length: u32,
    pub_key: [u8; 0x40],
    xor_array: [u8; 0x10],
    unknown2: [u8; 0x30],
    priv_key_length: u32,
    priv_key: [u8; 0x20],
    unknown3: [u8; 0x14],
}

fn decrypt_key(enc_key: &EncryptedKey) -> [u8; 0x20] {
    let mut plain_key = [0u8; 0x20];
    let mut first_half = *Block::from_slice(&enc_key.priv_key[..0x10]);
    let mut second_half = *Block::from_slice(&enc_key.priv_key[0x10..]);

    let aes = Aes128Dec::new_from_slice(&[
        0x1E, 0x76, 0x19, 0x56, 0x8B, 0x22, 0x2F, 0x0FD, 0x89, 0x8C, 0x42, 0x7F, 0x59, 0x0CF, 0x27,
        0x03,
    ])
    .unwrap();

    aes.decrypt_block(&mut second_half);

    for i in 0..0x10 {
        plain_key[0x10 + i] = first_half[i] ^ second_half[i];
    }

    aes.decrypt_block(&mut first_half);

    for i in 0..0x10 {
        plain_key[i] = first_half[i] ^ enc_key.xor_array[i];
    }

    plain_key
}

fn main() {
    let mut file = File::open("PlayReadykeybox.bin").unwrap();
    let prkf = Prkf::read(&mut file).unwrap();

    let tlv = prkf.tlvs.iter().find(|o| o.type_ == 0x1100e).unwrap();
    let TlvInner::CertChain(cert_chain) = &tlv.value else {
        panic!("Certificate chain not found");
    };

    let cert_chain = CertificateChain::from_bytes(&cert_chain.bytes).unwrap();
    let pub_sign_key = cert_chain.public_signing_key().unwrap();
    let pub_enc_key = cert_chain.public_encryption_key().unwrap();

    println!("Device name: {}", cert_chain.name().unwrap());
    println!("Public signing key: {:02x?}", pub_sign_key);
    println!("Public encryption key: {:02x?}", pub_enc_key);

    let tlv = prkf.tlvs.iter().find(|o| o.type_ == 0x31009).unwrap();
    let TlvInner::EncryptedKeysContainer(keys_container) = &tlv.value else {
        panic!("Encrypted keys container not found");
    };

    let sign_key = keys_container
        .tlvs
        .iter()
        .find(|k| k.pub_key == pub_sign_key)
        .unwrap();
    let enc_key = keys_container
        .tlvs
        .iter()
        .find(|k| k.pub_key == pub_enc_key)
        .unwrap();

    let sign_key = decrypt_key(sign_key);
    let enc_key = decrypt_key(enc_key);

    println!("Private signing key: {:02x?}", sign_key);
    println!("Private encryption key: {:02x?}", enc_key);

    let device = Device::from_slices(None, &enc_key, &sign_key, cert_chain.raw()).unwrap();
    println!("Device verification: {:?}", device.verify());

    device.write_to_file("device.prd").unwrap();
}
