use crate::test_vector::{TestVector, TestVectorAlgorithm};

/// Ed25519 test vectors (from RFC 8032, converted to Rust bytestring literals)
#[rustfmt::skip]
pub const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        alg: TestVectorAlgorithm::Ed25519,
        sk: b"\x9D\x61\xB1\x9D\xEF\xFD\x5A\x60\xBA\x84\x4A\xF4\x92\xEC\x2C\xC4\x44\x49\xC5\x69\x7B\x32\x69\x19\x70\x3B\xAC\x03\x1C\xAE\x7F\x60",
        pk: b"\xD7\x5A\x98\x01\x82\xB1\x0A\xB7\xD5\x4B\xFE\xD3\xC9\x64\x07\x3A\x0E\xE1\x72\xF3\xDA\xA6\x23\x25\xAF\x02\x1A\x68\xF7\x07\x51\x1A",
        nonce: None, // Ed25519 uses deterministic nonces
        msg: b"",
        sig: b"\xE5\x56\x43\x00\xC3\x60\xAC\x72\x90\x86\xE2\xCC\x80\x6E\x82\x8A\x84\x87\x7F\x1E\xB8\xE5\xD9\x74\xD8\x73\xE0\x65\x22\x49\x01\x55\x5F\xB8\x82\x15\x90\xA3\x3B\xAC\xC6\x1E\x39\x70\x1C\xF9\xB4\x6B\xD2\x5B\xF5\xF0\x59\x5B\xBE\x24\x65\x51\x41\x43\x8E\x7A\x10\x0B",
        pass: true
    },
    TestVector {
        alg: TestVectorAlgorithm::Ed25519,
        sk: b"\x4C\xCD\x08\x9B\x28\xFF\x96\xDA\x9D\xB6\xC3\x46\xEC\x11\x4E\x0F\x5B\x8A\x31\x9F\x35\xAB\xA6\x24\xDA\x8C\xF6\xED\x4F\xB8\xA6\xFB",
        pk: b"\x3D\x40\x17\xC3\xE8\x43\x89\x5A\x92\xB7\x0A\xA7\x4D\x1B\x7E\xBC\x9C\x98\x2C\xCF\x2E\xC4\x96\x8C\xC0\xCD\x55\xF1\x2A\xF4\x66\x0C",
        nonce: None,
        msg: b"\x72",
        sig: b"\x92\xA0\x09\xA9\xF0\xD4\xCA\xB8\x72\x0E\x82\x0B\x5F\x64\x25\x40\xA2\xB2\x7B\x54\x16\x50\x3F\x8F\xB3\x76\x22\x23\xEB\xDB\x69\xDA\x08\x5A\xC1\xE4\x3E\x15\x99\x6E\x45\x8F\x36\x13\xD0\xF1\x1D\x8C\x38\x7B\x2E\xAE\xB4\x30\x2A\xEE\xB0\x0D\x29\x16\x12\xBB\x0C\x00",
        pass: true
    },
    TestVector {
        alg: TestVectorAlgorithm::Ed25519,
        sk: b"\xC5\xAA\x8D\xF4\x3F\x9F\x83\x7B\xED\xB7\x44\x2F\x31\xDC\xB7\xB1\x66\xD3\x85\x35\x07\x6F\x09\x4B\x85\xCE\x3A\x2E\x0B\x44\x58\xF7",
        pk: b"\xFC\x51\xCD\x8E\x62\x18\xA1\xA3\x8D\xA4\x7E\xD0\x02\x30\xF0\x58\x08\x16\xED\x13\xBA\x33\x03\xAC\x5D\xEB\x91\x15\x48\x90\x80\x25",
        nonce: None,
        msg: b"\xAF\x82",
        sig: b"\x62\x91\xD6\x57\xDE\xEC\x24\x02\x48\x27\xE6\x9C\x3A\xBE\x01\xA3\x0C\xE5\x48\xA2\x84\x74\x3A\x44\x5E\x36\x80\xD7\xDB\x5A\xC3\xAC\x18\xFF\x9B\x53\x8D\x16\xF2\x90\xAE\x67\xF7\x60\x98\x4D\xC6\x59\x4A\x7C\x15\xE9\x71\x6E\xD2\x8D\xC0\x27\xBE\xCE\xEA\x1E\xC4\x0A",
        pass: true
    },
    TestVector {
        alg: TestVectorAlgorithm::Ed25519,
        sk: b"\xF5\xE5\x76\x7C\xF1\x53\x31\x95\x17\x63\x0F\x22\x68\x76\xB8\x6C\x81\x60\xCC\x58\x3B\xC0\x13\x74\x4C\x6B\xF2\x55\xF5\xCC\x0E\xE5",
        pk: b"\x27\x81\x17\xFC\x14\x4C\x72\x34\x0F\x67\xD0\xF2\x31\x6E\x83\x86\xCE\xFF\xBF\x2B\x24\x28\xC9\xC5\x1F\xEF\x7C\x59\x7F\x1D\x42\x6E",
        nonce: None,
        msg: b"\x08\xB8\xB2\xB7\x33\x42\x42\x43\x76\x0F\xE4\x26\xA4\xB5\x49\x08\x63\x21\x10\xA6\x6C\x2F\x65\x91\xEA\xBD\x33\x45\xE3\xE4\xEB\x98\xFA\x6E\x26\x4B\xF0\x9E\xFE\x12\xEE\x50\xF8\xF5\x4E\x9F\x77\xB1\xE3\x55\xF6\xC5\x05\x44\xE2\x3F\xB1\x43\x3D\xDF\x73\xBE\x84\xD8\x79\xDE\x7C\x00\x46\xDC\x49\x96\xD9\xE7\x73\xF4\xBC\x9E\xFE\x57\x38\x82\x9A\xDB\x26\xC8\x1B\x37\xC9\x3A\x1B\x27\x0B\x20\x32\x9D\x65\x86\x75\xFC\x6E\xA5\x34\xE0\x81\x0A\x44\x32\x82\x6B\xF5\x8C\x94\x1E\xFB\x65\xD5\x7A\x33\x8B\xBD\x2E\x26\x64\x0F\x89\xFF\xBC\x1A\x85\x8E\xFC\xB8\x55\x0E\xE3\xA5\xE1\x99\x8B\xD1\x77\xE9\x3A\x73\x63\xC3\x44\xFE\x6B\x19\x9E\xE5\xD0\x2E\x82\xD5\x22\xC4\xFE\xBA\x15\x45\x2F\x80\x28\x8A\x82\x1A\x57\x91\x16\xEC\x6D\xAD\x2B\x3B\x31\x0D\xA9\x03\x40\x1A\xA6\x21\x00\xAB\x5D\x1A\x36\x55\x3E\x06\x20\x3B\x33\x89\x0C\xC9\xB8\x32\xF7\x9E\xF8\x05\x60\xCC\xB9\xA3\x9C\xE7\x67\x96\x7E\xD6\x28\xC6\xAD\x57\x3C\xB1\x16\xDB\xEF\xEF\xD7\x54\x99\xDA\x96\xBD\x68\xA8\xA9\x7B\x92\x8A\x8B\xBC\x10\x3B\x66\x21\xFC\xDE\x2B\xEC\xA1\x23\x1D\x20\x6B\xE6\xCD\x9E\xC7\xAF\xF6\xF6\xC9\x4F\xCD\x72\x04\xED\x34\x55\xC6\x8C\x83\xF4\xA4\x1D\xA4\xAF\x2B\x74\xEF\x5C\x53\xF1\xD8\xAC\x70\xBD\xCB\x7E\xD1\x85\xCE\x81\xBD\x84\x35\x9D\x44\x25\x4D\x95\x62\x9E\x98\x55\xA9\x4A\x7C\x19\x58\xD1\xF8\xAD\xA5\xD0\x53\x2E\xD8\xA5\xAA\x3F\xB2\xD1\x7B\xA7\x0E\xB6\x24\x8E\x59\x4E\x1A\x22\x97\xAC\xBB\xB3\x9D\x50\x2F\x1A\x8C\x6E\xB6\xF1\xCE\x22\xB3\xDE\x1A\x1F\x40\xCC\x24\x55\x41\x19\xA8\x31\xA9\xAA\xD6\x07\x9C\xAD\x88\x42\x5D\xE6\xBD\xE1\xA9\x18\x7E\xBB\x60\x92\xCF\x67\xBF\x2B\x13\xFD\x65\xF2\x70\x88\xD7\x8B\x7E\x88\x3C\x87\x59\xD2\xC4\xF5\xC6\x5A\xDB\x75\x53\x87\x8A\xD5\x75\xF9\xFA\xD8\x78\xE8\x0A\x0C\x9B\xA6\x3B\xCB\xCC\x27\x32\xE6\x94\x85\xBB\xC9\xC9\x0B\xFB\xD6\x24\x81\xD9\x08\x9B\xEC\xCF\x80\xCF\xE2\xDF\x16\xA2\xCF\x65\xBD\x92\xDD\x59\x7B\x07\x07\xE0\x91\x7A\xF4\x8B\xBB\x75\xFE\xD4\x13\xD2\x38\xF5\x55\x5A\x7A\x56\x9D\x80\xC3\x41\x4A\x8D\x08\x59\xDC\x65\xA4\x61\x28\xBA\xB2\x7A\xF8\x7A\x71\x31\x4F\x31\x8C\x78\x2B\x23\xEB\xFE\x80\x8B\x82\xB0\xCE\x26\x40\x1D\x2E\x22\xF0\x4D\x83\xD1\x25\x5D\xC5\x1A\xDD\xD3\xB7\x5A\x2B\x1A\xE0\x78\x45\x04\xDF\x54\x3A\xF8\x96\x9B\xE3\xEA\x70\x82\xFF\x7F\xC9\x88\x8C\x14\x4D\xA2\xAF\x58\x42\x9E\xC9\x60\x31\xDB\xCA\xD3\xDA\xD9\xAF\x0D\xCB\xAA\xAF\x26\x8C\xB8\xFC\xFF\xEA\xD9\x4F\x3C\x7C\xA4\x95\xE0\x56\xA9\xB4\x7A\xCD\xB7\x51\xFB\x73\xE6\x66\xC6\xC6\x55\xAD\xE8\x29\x72\x97\xD0\x7A\xD1\xBA\x5E\x43\xF1\xBC\xA3\x23\x01\x65\x13\x39\xE2\x29\x04\xCC\x8C\x42\xF5\x8C\x30\xC0\x4A\xAF\xDB\x03\x8D\xDA\x08\x47\xDD\x98\x8D\xCD\xA6\xF3\xBF\xD1\x5C\x4B\x4C\x45\x25\x00\x4A\xA0\x6E\xEF\xF8\xCA\x61\x78\x3A\xAC\xEC\x57\xFB\x3D\x1F\x92\xB0\xFE\x2F\xD1\xA8\x5F\x67\x24\x51\x7B\x65\xE6\x14\xAD\x68\x08\xD6\xF6\xEE\x34\xDF\xF7\x31\x0F\xDC\x82\xAE\xBF\xD9\x04\xB0\x1E\x1D\xC5\x4B\x29\x27\x09\x4B\x2D\xB6\x8D\x6F\x90\x3B\x68\x40\x1A\xDE\xBF\x5A\x7E\x08\xD7\x8F\xF4\xEF\x5D\x63\x65\x3A\x65\x04\x0C\xF9\xBF\xD4\xAC\xA7\x98\x4A\x74\xD3\x71\x45\x98\x67\x80\xFC\x0B\x16\xAC\x45\x16\x49\xDE\x61\x88\xA7\xDB\xDF\x19\x1F\x64\xB5\xFC\x5E\x2A\xB4\x7B\x57\xF7\xF7\x27\x6C\xD4\x19\xC1\x7A\x3C\xA8\xE1\xB9\x39\xAE\x49\xE4\x88\xAC\xBA\x6B\x96\x56\x10\xB5\x48\x01\x09\xC8\xB1\x7B\x80\xE1\xB7\xB7\x50\xDF\xC7\x59\x8D\x5D\x50\x11\xFD\x2D\xCC\x56\x00\xA3\x2E\xF5\xB5\x2A\x1E\xCC\x82\x0E\x30\x8A\xA3\x42\x72\x1A\xAC\x09\x43\xBF\x66\x86\xB6\x4B\x25\x79\x37\x65\x04\xCC\xC4\x93\xD9\x7E\x6A\xED\x3F\xB0\xF9\xCD\x71\xA4\x3D\xD4\x97\xF0\x1F\x17\xC0\xE2\xCB\x37\x97\xAA\x2A\x2F\x25\x66\x56\x16\x8E\x6C\x49\x6A\xFC\x5F\xB9\x32\x46\xF6\xB1\x11\x63\x98\xA3\x46\xF1\xA6\x41\xF3\xB0\x41\xE9\x89\xF7\x91\x4F\x90\xCC\x2C\x7F\xFF\x35\x78\x76\xE5\x06\xB5\x0D\x33\x4B\xA7\x7C\x22\x5B\xC3\x07\xBA\x53\x71\x52\xF3\xF1\x61\x0E\x4E\xAF\xE5\x95\xF6\xD9\xD9\x0D\x11\xFA\xA9\x33\xA1\x5E\xF1\x36\x95\x46\x86\x8A\x7F\x3A\x45\xA9\x67\x68\xD4\x0F\xD9\xD0\x34\x12\xC0\x91\xC6\x31\x5C\xF4\xFD\xE7\xCB\x68\x60\x69\x37\x38\x0D\xB2\xEA\xAA\x70\x7B\x4C\x41\x85\xC3\x2E\xDD\xCD\xD3\x06\x70\x5E\x4D\xC1\xFF\xC8\x72\xEE\xEE\x47\x5A\x64\xDF\xAC\x86\xAB\xA4\x1C\x06\x18\x98\x3F\x87\x41\xC5\xEF\x68\xD3\xA1\x01\xE8\xA3\xB8\xCA\xC6\x0C\x90\x5C\x15\xFC\x91\x08\x40\xB9\x4C\x00\xA0\xB9\xD0",
        sig: b"\x0A\xAB\x4C\x90\x05\x01\xB3\xE2\x4D\x7C\xDF\x46\x63\x32\x6A\x3A\x87\xDF\x5E\x48\x43\xB2\xCB\xDB\x67\xCB\xF6\xE4\x60\xFE\xC3\x50\xAA\x53\x71\xB1\x50\x8F\x9F\x45\x28\xEC\xEA\x23\xC4\x36\xD9\x4B\x5E\x8F\xCD\x4F\x68\x1E\x30\xA6\xAC\x00\xA9\x70\x4A\x18\x8A\x03",
        pass: true
    },
    TestVector {
        alg: TestVectorAlgorithm::Ed25519,
        sk: b"\x83\x3F\xE6\x24\x09\x23\x7B\x9D\x62\xEC\x77\x58\x75\x20\x91\x1E\x9A\x75\x9C\xEC\x1D\x19\x75\x5B\x7D\xA9\x01\xB9\x6D\xCA\x3D\x42",
        pk: b"\xEC\x17\x2B\x93\xAD\x5E\x56\x3B\xF4\x93\x2C\x70\xE1\x24\x50\x34\xC3\x54\x67\xEF\x2E\xFD\x4D\x64\xEB\xF8\x19\x68\x34\x67\xE2\xBF",
        nonce: None,
        msg: b"\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31\x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A\x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD\x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F",
        sig: b"\xDC\x2A\x44\x59\xE7\x36\x96\x33\xA5\x2B\x1B\xF2\x77\x83\x9A\x00\x20\x10\x09\xA3\xEF\xBF\x3E\xCB\x69\xBE\xA2\x18\x6C\x26\xB5\x89\x09\x35\x1F\xC9\xAC\x90\xB3\xEC\xFD\xFB\xC7\xC6\x64\x31\xE0\x30\x3D\xCA\x17\x9C\x13\x8A\xC1\x7A\xD9\xBE\xF1\x17\x73\x31\xA7\x04",
        pass: true
    },
];
