/// Used for deriving `ByteEncodable` for `ByteArray<N>` wrapper newtypes.
#[macro_export]
macro_rules! impl_byte_encodable {
    ($t:ty) => {
        impl ByteEncodable for $t {
            fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
            fn to_hex(&self) -> String {
                self.0.to_hex()
            }
            fn from_slice(slice: &[u8]) -> Result<Self, CommonTypeError> {
                Ok(Self(ByteArray::from_slice(slice)?))
            }
            fn from_hex(hex_str: &str) -> Result<Self, CommonTypeError> {
                Ok(Self(ByteArray::from_hex(hex_str)?))
            }
        }
    };
}
