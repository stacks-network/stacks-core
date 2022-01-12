macro_rules! impl_stacks_message_codec_for_int {
    ($typ:ty; $array:expr) => {
        impl StacksMessageCodec for $typ {
            fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
                fd.write_all(&self.to_be_bytes())
                    .map_err(codec_error::WriteError)
            }
            fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, codec_error> {
                let mut buf = $array;
                fd.read_exact(&mut buf).map_err(codec_error::ReadError)?;
                Ok(<$typ>::from_be_bytes(buf))
            }
        }
    };
}

macro_rules! impl_byte_array_message_codec {
    ($thing:ident, $len:expr) => {
        impl ::codec::StacksMessageCodec for $thing {
            fn consensus_serialize<W: std::io::Write>(
                &self,
                fd: &mut W,
            ) -> Result<(), ::codec::Error> {
                fd.write_all(self.as_bytes())
                    .map_err(::codec::Error::WriteError)
            }
            fn consensus_deserialize<R: std::io::Read>(
                fd: &mut R,
            ) -> Result<$thing, ::codec::Error> {
                let mut buf = [0u8; ($len as usize)];
                fd.read_exact(&mut buf).map_err(::codec::Error::ReadError)?;
                let ret = $thing::from_bytes(&buf).expect("BUG: buffer is not the right size");
                Ok(ret)
            }
        }
    };
}

// macro for determining how big an inv bitvec can be, given its bitlen
macro_rules! BITVEC_LEN {
    ($bitvec:expr) => {
        (($bitvec) / 8 + if ($bitvec) % 8 > 0 { 1 } else { 0 }) as u32
    };
}
