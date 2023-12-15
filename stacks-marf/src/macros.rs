#[macro_export]
macro_rules! impl_marf_trie_id {
    ($thing:ident) => {
        impl MarfTrieId for $thing {
            fn as_bytes(&self) -> &[u8] {
                self.as_ref()
            }
            fn to_bytes(self) -> [u8; 32] {
                self.0
            }
            fn sentinel() -> Self {
                Self(SENTINEL_ARRAY.clone())
            }
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<MARFValue> for $thing {
            fn from(m: MARFValue) -> Self {
                let h = m.0;
                let mut d = [0u8; 32];
                for i in 0..32 {
                    d[i] = h[i];
                }
                for i in 32..h.len() {
                    if h[i] != 0 {
                        panic!(
                            "Failed to convert MARF value into BHH: data stored after 32nd byte"
                        );
                    }
                }
                Self(d)
            }
        }
    };
}