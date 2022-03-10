//! ECDSA test vectors for secp256k1 fixed-size signatures
//!
//! TODO: find better test vectors and document where we got them from!

use crate::ecdsa::TestVector;

/// ECDSA secp256k1 fixed-sized signature test vectors (self-generated, should probably be replaced)
// TODO: Test vectors for ASN.1 encoded signatures
#[rustfmt::skip]
pub const SHA256_FIXED_SIZE_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        sk: b"\x9d\x79\x48\x1a\xf0\xfa\x1e\x7c\xc8\x4f\xc4\xa8\xaa\xcf\x1e\xd2\xee\xb5\x81\xe9\x9b\x58\x38\x88\x8b\xe4\x4d\x28\x35\x31\x16\x9b",
        pk: b"\x03\x22\xb0\xaf\xe7\x2e\x7c\x5f\x63\x53\x1c\x8c\xb4\xfe\x09\x2e\xb7\x75\xcd\x5d\x20\x8e\xbd\x2d\xbe\x7e\xbc\xda\xb1\xcf\x16\x6f\xfc",
        nonce: None, // TODO: find test vectors with 'k' values
        msg: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe",
        sig: b"\xdc\xd0\x37\x67\x2e\xde\x6b\x10\xf6\xab\xf6\xb6\xbb\x01\x85\x37\xbb\xbe\xa4\x86\x05\x83\x84\x76\xad\x75\x81\xb3\x82\x2d\xdc\xc8\x41\xfe\x40\x30\xd8\x58\xf2\x1a\xf5\xd5\xc1\x0f\xe4\x82\xe5\x66\xfb\xbb\x34\x60\x42\xa1\x8a\x70\xa0\xc2\xbb\x62\x77\xba\xc5\x74",
    },
];
