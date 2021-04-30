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
