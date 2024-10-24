use alexandria_data_structures::array_ext::ArrayTraitExt;
use ripemd_160::ripemd160;
use ripemd_160::pad_input;


#[test]
fn ripemd160_empty() {
    let (input, padded, out) = TestVectors::ripemd160_empty();
    let (padded_input, n_chunks) = pad_input(input.clone());
    assert_eq!(n_chunks, 1);
    assert_eq!(padded_input, padded);
    assert_eq!(ripemd160(input), out);
}

#[test]
fn ripemd160_abc() {
    let (input, padded, out) = TestVectors::ripemd160_abc();
    let (padded_input, n_chunks) = pad_input(input.clone());
    assert_eq!(n_chunks, 1);
    assert_eq!(padded_input, padded);
    assert_eq!(ripemd160(input), out);
}

#[test]
fn ripemd160_az() {
    let (input, padded, out) = TestVectors::ripemd160_az();
    let (padded_input, n_chunks) = pad_input(input.clone());
    assert_eq!(n_chunks, 1);
    assert_eq!(padded_input, padded);
    assert_eq!(ripemd160(input), out);
}

#[test]
fn ripemd160_32bytes() {
    let (input, out) = TestVectors::ripemd160_32bytes();
    assert_eq!(ripemd160(input), out);
}

#[test]
fn ripemd160_62bytes() {
    let (input, padded, out) = TestVectors::ripemd160_62bytes();
    let (padded_input, n_chunks) = pad_input(input.clone());
    assert_eq!(n_chunks, 2);
    assert_eq!(padded_input, padded);
    assert_eq!(ripemd160(input), out);
}

#[test]
fn ripemd160_186bytes() {
    let (input, out) = TestVectors::ripemd160_186bytes();
    assert_eq!(ripemd160(input), out);
}


/// LEGEND:
/// case 1: TestVectors::<hash_name>::<vector_name>
///         return: (input: Array<u8>, output: Array<u8>)
///
/// case 2: TestVectors::<hash_name>::<vector_name>
///         return: (input: Array<u8>, padding: Span<u32>, output: Array<u8>)
#[generate_trait]
pub impl TestVectors of TestVectorsTrait {
    fn ripemd160_empty() -> (Array<u8>, Span<u32>, Array<u8>) {
        (
            array![],
            array![
                0x80,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00
            ]
                .span(),
            array![
                0x9c,
                0x11,
                0x85,
                0xa5,
                0xc5,
                0xe9,
                0xfc,
                0x54,
                0x61,
                0x28,
                0x08,
                0x97,
                0x7e,
                0xe8,
                0xf5,
                0x48,
                0xb2,
                0x25,
                0x8d,
                0x31
            ]
        )
    }

    fn ripemd160_abc() -> (Array<u8>, Span<u32>, Array<u8>) {
        (
            array!['a', 'b', 'c'],
            array![
                0x80636261,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x18,
                0x00
            ]
                .span(),
            array![
                0x8e,
                0xb2,
                0x08,
                0xf7,
                0xe0,
                0x5d,
                0x98,
                0x7a,
                0x9b,
                0x04,
                0x4a,
                0x8e,
                0x98,
                0xc6,
                0xb0,
                0x87,
                0xf1,
                0x5a,
                0x0b,
                0xfc,
            ]
        )
    }

    fn ripemd160_az() -> (Array<u8>, Span<u32>, Array<u8>) {
        (
            array![
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
                'g',
                'h',
                'i',
                'j',
                'k',
                'l',
                'm',
                'n',
                'o',
                'p',
                'q',
                'r',
                's',
                't',
                'u',
                'v',
                'w',
                'x',
                'y',
                'z',
            ],
            array![
                0x64636261,
                0x68676665,
                0x6c6b6a69,
                0x706f6e6d,
                0x74737271,
                0x78777675,
                0x807a79,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0xd0,
                0x00
            ]
                .span(),
            array![
                0xf7,
                0x1c,
                0x27,
                0x10,
                0x9c,
                0x69,
                0x2c,
                0x1b,
                0x56,
                0xbb,
                0xdc,
                0xeb,
                0x5b,
                0x9d,
                0x28,
                0x65,
                0xb3,
                0x70,
                0x8d,
                0xbc
            ]
        )
    }

    fn ripemd160_62bytes() -> (Array<u8>, Span<u32>, Array<u8>) {
        (
            array![
                'A',
                'B',
                'C',
                'D',
                'E',
                'F',
                'G',
                'H',
                'I',
                'J',
                'K',
                'L',
                'M',
                'N',
                'O',
                'P',
                'Q',
                'R',
                'S',
                'T',
                'U',
                'V',
                'W',
                'X',
                'Y',
                'Z',
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
                'g',
                'h',
                'i',
                'j',
                'k',
                'l',
                'm',
                'n',
                'o',
                'p',
                'q',
                'r',
                's',
                't',
                'u',
                'v',
                'w',
                'x',
                'y',
                'z',
                '0',
                '1',
                '2',
                '3',
                '4',
                '5',
                '6',
                '7',
                '8',
                '9'
            ],
            array![
                0x44434241,
                0x48474645,
                0x4c4b4a49,
                0x504f4e4d,
                0x54535251,
                0x58575655,
                0x62615a59,
                0x66656463,
                0x6a696867,
                0x6e6d6c6b,
                0x7271706f,
                0x76757473,
                0x7a797877,
                0x33323130,
                0x37363534,
                0x803938,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x1f0,
                0x00
            ]
                .span(),
            array![
                0xb0,
                0xe2,
                0x0b,
                0x6e,
                0x31,
                0x16,
                0x64,
                0x02,
                0x86,
                0xed,
                0x3a,
                0x87,
                0xa5,
                0x71,
                0x30,
                0x79,
                0xb2,
                0x1f,
                0x51,
                0x89
            ]
        )
    }

    // bitcoin addresses (RIPEMD-160) https://en.bitcoin.it/wiki/Protocol_documentation#Hashes
    fn ripemd160_32bytes() -> (Array<u8>, Array<u8>) {
        (
            array![
                0x2c,
                0xf2,
                0x4d,
                0xba,
                0x5f,
                0xb0,
                0xa3,
                0x0e,
                0x26,
                0xe8,
                0x3b,
                0x2a,
                0xc5,
                0xb9,
                0xe2,
                0x9e,
                0x1b,
                0x16,
                0x1e,
                0x5c,
                0x1f,
                0xa7,
                0x42,
                0x5e,
                0x73,
                0x04,
                0x33,
                0x62,
                0x93,
                0x8b,
                0x98,
                0x24,
            ],
            array![
                0xb6,
                0xa9,
                0xc8,
                0xc2,
                0x30,
                0x72,
                0x2b,
                0x7c,
                0x74,
                0x83,
                0x31,
                0xa8,
                0xb4,
                0x50,
                0xf0,
                0x55,
                0x66,
                0xdc,
                0x7d,
                0x0f
            ]
        )
    }

    fn ripemd160_186bytes() -> (Array<u8>, Array<u8>) {
        let (bytes_62, _, _) = Self::ripemd160_62bytes();
        (
            bytes_62.concat(@bytes_62).concat(@bytes_62),
            array![
                0x4e,
                0x73,
                0x24,
                0x3b,
                0x1e,
                0x0a,
                0xe4,
                0xd8,
                0xe1,
                0x93,
                0x87,
                0xa7,
                0xb7,
                0xfa,
                0xc0,
                0x10,
                0x29,
                0x4f,
                0x98,
                0xdc,
            ]
        )
    }
}
