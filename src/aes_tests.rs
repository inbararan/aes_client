use super::aes;

#[test]
fn null_test() {
    assert_eq!(0, 0);
}
    
#[test]
fn test_sub_bytes_by_example() {
    let block: aes::Block = [
        [0x01, 0x02, 0x03, 0x04],
        [0x45, 0x46, 0x47, 0x48],
        [0x88, 0x98, 0xa8, 0xb8],
        [0x33, 0x44, 0x55, 0x66]
    ];
    let substituted: aes::Block = [
        [0x7c, 0x77, 0x7b, 0xf2],
        [0x6e, 0x5a, 0xa0, 0x52],
        [0xc4, 0x46, 0xc2, 0x6c],
        [0xc3, 0x1b, 0xfc, 0x33]
    ];
    assert_eq!(substituted, aes::sub_bytes(block));
}

#[test]
fn test_sub_bytes_completeness() {
    let mut sum_block: u128 = 0;
    let mut sum_substituted: u128 = 0;
    for i in 0..16 {
        let mut block: aes::Block = [[0; 4]; 4];
        for col in 0..4 {
            for ind in 0..4 {
                block[col][ind] = u8::try_from(i * 4 * 4 + col * 4 + ind).expect("overflow on block creation");
            }
        }
        let substituted = aes::sub_bytes(block);
        for col in 0..4 {
            for ind in 0..4 {
                sum_block = sum_block.checked_add(block[col][ind] as u128).unwrap();
                sum_substituted = sum_substituted.checked_add(substituted[col][ind] as u128).unwrap();
            }
        }
    }
    assert_eq!(sum_block, 256 * 255 / 2);
    assert_eq!(sum_substituted, 256 * 255 / 2);
}

#[test]
fn test_shift_rows() {
    let block: aes::Block = [
        [0x74, 0x6c, 0xe1, 0x09],
        [0xc5, 0x1e, 0xdd, 0x3b],
        [0xdf, 0x93, 0x79, 0xc7],
        [0x3c, 0x62, 0xb0, 0xe7]
    ];
    let shifted: aes::Block = [
        [0x74, 0x1e, 0x79, 0xe7],
        [0xc5, 0x93, 0xb0, 0x09],
        [0xdf, 0x62, 0xe1, 0x3b],
        [0x3c, 0x6c, 0xdd, 0xc7]
    ];
    assert_eq!(shifted, aes::shift_rows(block));
}

#[test]
fn test_mix_column() {
    assert_eq!([142, 77, 161, 188], aes::mix_column([219, 19, 83, 69], &aes::MIX_MATRIX));
    assert_eq!([159, 220, 88, 157], aes::mix_column([242, 10, 34, 92], &aes::MIX_MATRIX));
}

#[test]
fn test_gf_mult() {
    assert_eq!(aes::gf_mult(0x42, 0xab), 46);
}

#[test]
fn test_rot_word() {
    assert_eq!(aes::rot_word([0x3c, 0x62, 0xb0, 0xe7]), [0xe7, 0x3c, 0x62, 0xb0]);
}

#[test]
fn test_gf_add_column() {
    assert_eq!(aes::gf_add_column(&[0b1101, 0b1111, 0b1011, 0b0],&[0b1101, 0b1010, 0b1110, 0b1001]), [0b0, 0b101, 0b101, 0b1001]);
}

#[test]
fn test_inverses() {
    let block: aes::Block = [
        [0x01, 0x02, 0x03, 0x04],
        [0x45, 0x46, 0x47, 0x48],
        [0x88, 0x98, 0xa8, 0xb8],
        [0x33, 0x44, 0x55, 0x66]
    ];
    let key: aes::Block = [
        [0x74, 0x1e, 0x79, 0xe7],
        [0xc5, 0x93, 0xb0, 0x09],
        [0xdf, 0x62, 0xe1, 0x3b],
        [0x3c, 0x6c, 0xdd, 0xc7]
    ];
    assert_eq!(block, aes::sub_bytes_inverse(aes::sub_bytes(block)), "sub_bytes isn't correctly inverted");
    assert_eq!(block, aes::shift_rows_inverse(aes::shift_rows(block)), "shift_rows isn't correctly inverted");
    assert_eq!(block, aes::mix_columns_inverse(aes::mix_columns(block)), "mix_columns isn't correctly inverted");
    assert_eq!(block, aes::decrypt_block(aes::encrypt_block(block, key), key), "encryption isn't correctly inverted");
}

#[test]
fn test_flatten_blockify() {
    let block: aes::Block = [
        [0x01, 0x02, 0x03, 0x04],
        [0x45, 0x46, 0x47, 0x48],
        [0x88, 0x98, 0xa8, 0xb8],
        [0x33, 0x44, 0x55, 0x66]
    ];
    let flat_block: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04,
        0x45, 0x46, 0x47, 0x48,
        0x88, 0x98, 0xa8, 0xb8,
        0x33, 0x44, 0x55, 0x66
    ];
    assert_eq!(block, aes::blockify(&flat_block), "blockify");
    assert_eq!(flat_block, aes::flatten(block), "flatten");
    assert_eq!(block, aes::blockify(&aes::flatten(block)), "inverse of flatten");
    assert_eq!(flat_block, aes::flatten(aes::blockify(&flat_block)), "inverse of blockify");
}

#[test]
fn test_encrypt_decrypt() {
    let data: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04,
        0x45, 0x46, 0x47, 0x48,
        0x88, 0x98, 0xa8, 0xb8,
        0x33, 0x44, 0x55, 0x66
    ];
    let key: [u8; 16] = [
        0x74, 0x1e, 0x79, 0xe7,
        0xc5, 0x93, 0xb0, 0x09,
        0xdf, 0x62, 0xe1, 0x3b,
        0x3c, 0x6c, 0xdd, 0xc7
    ];
    assert_eq!(data, aes::encrypt(&aes::decrypt(&data, &key), &key));
}
