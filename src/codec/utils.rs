use parity_scale_codec::{Decode, Encode, Error, Input, Output};

enum Length {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl Encode for Length {
    fn size_hint(&self) -> usize {
        match *self {
            Length::U8(_) => 1 + 1,  // Prefix byte + u8
            Length::U16(_) => 1 + 2, // Prefix byte + u16
            Length::U32(_) => 1 + 4, // Prefix byte + u32
            Length::U64(_) => 1 + 8, // Prefix byte + u64
        }
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        match *self {
            Length::U8(v) => {
                0u8.encode_to(dest); // prefix for indicating length discriminator type
                v.encode_to(dest);
            }
            Length::U16(v) => {
                1u8.encode_to(dest); // prefix for indicating length discriminator type
                v.encode_to(dest);
            }
            Length::U32(v) => {
                2u8.encode_to(dest); // prefix for indicating length discriminator type
                v.encode_to(dest);
            }
            Length::U64(v) => {
                3u8.encode_to(dest); // prefix for indicating length discriminator type
                v.encode_to(dest);
            }
        }
    }
}

impl Decode for Length {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let prefix = u8::decode(input)?;
        match prefix {
            0 => Ok(Length::U8(u8::decode(input)?)),
            1 => Ok(Length::U16(u16::decode(input)?)),
            2 => Ok(Length::U32(u32::decode(input)?)),
            3 => Ok(Length::U64(u64::decode(input)?)),
            _ => Err(Error::from("Invalid Length prefix")),
        }
    }
}

fn determine_length_type(length: usize) -> Length {
    if length <= u8::MAX as usize {
        Length::U8(length as u8)
    } else if length <= u16::MAX as usize {
        Length::U16(length as u16)
    } else if length <= u32::MAX as usize {
        Length::U32(length as u32)
    } else if length <= u64::MAX as usize {
        Length::U64(length as u64)
    } else {
        panic!("Length exceeds maximum value for supported types");
    }
}

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

// Decoding function for optional fields
pub(crate) fn decode_optional_field<T: Decode, I: Input>(
    input: &mut I,
) -> Result<Option<T>, Error> {
    let presence_marker = u8::decode(input)?;
    if presence_marker == 1 {
        Ok(Some(T::decode(input)?))
    } else if presence_marker == 0 {
        Ok(None)
    } else {
        Err(Error::from("Invalid presence marker"))
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
    let length_type = determine_length_type(length);
    length_type.encode_to(dest); // Encode the length discriminator with the prefix
    field.encode_to(dest); // Encode the value
}

// Decoding function for length-discriminated fields
pub(crate) fn decode_length_discriminated_field<T: Decode, I: Input>(
    input: &mut I,
) -> Result<Vec<T>, Error> {
    let length_type = Length::decode(input)?;
    let length = match length_type {
        Length::U8(l) => l as usize,
        Length::U16(l) => l as usize,
        Length::U32(l) => l as usize,
        Length::U64(l) => l as usize,
    };
    (0..length).map(|_| T::decode(input)).collect()
}

pub(crate) fn size_hint_length_discriminated_field<T: Encode>(field: &[T]) -> usize {
    let length = field.len();
    let length_type = determine_length_type(length);
    length_type.size_hint() + field.size_hint() // Length of the length discriminator + size of the value
}

// Encoding and size hint functions for length-discriminated optional values
pub(crate) fn encode_length_discriminated_optional_field<T: Encode, W: Output + ?Sized>(
    field: &[Option<T>],
    dest: &mut W,
) {
    let length = field.len();
    let length_type = determine_length_type(length);
    length_type.encode_to(dest);
    for item in field {
        encode_optional_field(item, dest);
    }
}

// Decoding function for length-discriminated optional fields
pub(crate) fn decode_length_discriminated_optional_field<T: Decode, I: Input>(
    input: &mut I,
) -> Result<Vec<Option<T>>, Error> {
    let length_type = Length::decode(input)?;
    let length = match length_type {
        Length::U8(l) => l as usize,
        Length::U16(l) => l as usize,
        Length::U32(l) => l as usize,
        Length::U64(l) => l as usize,
    };
    (0..length).map(|_| decode_optional_field(input)).collect()
}

pub(crate) fn size_hint_length_discriminated_optional_field<T: Encode>(
    field: &[Option<T>],
) -> usize {
    let length = field.len();
    let length_type = determine_length_type(length);
    length_type.size_hint() + field.iter().map(size_hint_optional_field).sum::<usize>()
}

// Encoding and size hint functions for length-discriminated sorted values
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
    let length_type = determine_length_type(length);
    length_type.encode_to(dest); // Encode the length discriminator with the prefix
    sorted_field.encode_to(dest); // Encode the value
}

// Decoding function for length-discriminated sorted fields
pub(crate) fn decode_length_discriminated_sorted_field<T: Decode + Ord, I: Input>(
    input: &mut I,
) -> Result<Vec<T>, Error> {
    let mut result = decode_length_discriminated_field(input)?;
    result.sort();
    Ok(result)
}

pub(crate) fn size_hint_length_discriminated_sorted_field<T: Encode + Ord + Clone>(
    field: &[T],
) -> usize {
    let mut sorted_field = field.to_vec();
    sorted_field.sort();
    let length = sorted_field.len();
    let length_type = determine_length_type(length);
    length_type.size_hint() + sorted_field.size_hint() // Length of the length discriminator + size of the value
}
