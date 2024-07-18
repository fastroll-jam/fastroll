use parity_scale_codec::{Encode, Output};

// Encoding and size hint functions for optional values
pub(crate) fn encode_optional_field<T: Encode, W: Output + ?Sized>(
    field: &Option<T>,
    dest: &mut W,
) {
    match field {
        Some(value) => {
            1u8.encode_to(dest); // Encode the presence marker (1)
            value.encode_to(dest); // Encode the value
        }
        None => {
            0u8.encode_to(dest); // Encode the absence marker (0)
        }
    }
}

pub(crate) fn size_hint_optional_field<T: Encode>(field: &Option<T>) -> usize {
    match field {
        Some(value) => 1 + value.size_hint(), // 1 byte for the presence marker + size of the value
        None => 1,                            // 1 byte for the absence marker
    }
}

// Encoding and size hint functions for length-discriminated values
pub(crate) fn encode_length_discriminated_field<T: Encode, W: Output + ?Sized>(
    field: &[T],
    dest: &mut W,
) {
    let length = field.len();
    if length > 255 {
        panic!("Length exceeds maximum value for u8"); // TODO: better handling
    }
    (length as u8).encode_to(dest); // Encode the length discriminator
    field.encode_to(dest); // Encode the value
}

pub(crate) fn size_hint_length_discriminated_field<T: Encode>(field: &[T]) -> usize {
    let length = field.len();
    if length > 255 {
        panic!("Length exceeds maximum value for u8"); // TODO: better handling
    }
    (length as u8).size_hint() + field.size_hint() // Length of the length discriminator + size of the value
}

pub(crate) fn encode_length_discriminated_optional_field<T: Encode, W: Output + ?Sized>(
    field: &[Option<T>],
    dest: &mut W,
) {
    let length = field.len();
    if length > 255 {
        panic!("Length exceeds maximum value for u8"); // TODO: better handling
    }
    (length as u8).encode_to(dest);
    encode_length_discriminated_field(field, dest);
    for item in field {
        encode_optional_field(item, dest);
    }
}

pub(crate) fn size_hint_length_discriminated_optional_field<T: Encode>(
    field: &[Option<T>],
) -> usize {
    1 + field.iter().map(size_hint_optional_field).sum::<usize>()
}

pub(crate) fn encode_length_discriminated_sorted_field<
    T: Encode + Ord + Clone,
    W: Output + ?Sized,
>(
    field: &[T],
    dest: &mut W,
) {
    let mut sorted_field = field.to_vec();
    sorted_field.sort();
    let length = sorted_field.len();
    if length > 65_535 {
        panic!("Length exceeds maximum value for u16"); // TODO: better handling
    }
    (length as u16).encode_to(dest);
    sorted_field.encode_to(dest);
}

pub(crate) fn size_hint_length_discriminated_sorted_field<T: Encode + Ord + Clone>(
    field: &[T],
) -> usize {
    let mut sorted_field = field.to_vec();
    sorted_field.sort();
    let length = sorted_field.len();
    if length > 65_535 {
        panic!("Length exceeds maximum value for u16"); // TODO: better handling
    }
    2 + sorted_field.size_hint() // 2 bytes for the length discriminator (u16)
}
