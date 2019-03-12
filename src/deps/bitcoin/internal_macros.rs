// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl<S: ::deps::bitcoin::network::serialize::SimpleEncoder> ::deps::bitcoin::network::encodable::ConsensusEncodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), ::deps::bitcoin::network::serialize::Error> {
                $( self.$field.consensus_encode(s)?; )+
                Ok(())
            }
        }

        impl<D: ::deps::bitcoin::network::serialize::SimpleDecoder> ::deps::bitcoin::network::encodable::ConsensusDecodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, ::deps::bitcoin::network::serialize::Error> {
                use deps::bitcoin::network::encodable::ConsensusDecodable;
                Ok($thing {
                    $( $field: ConsensusDecodable::consensus_decode(d)?, )+
                })
            }
        }
    );
}

macro_rules! impl_newtype_consensus_encoding {
    ($thing:ident) => (
        impl<S: ::deps::bitcoin::network::serialize::SimpleEncoder> ::deps::bitcoin::network::encodable::ConsensusEncodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), ::deps::bitcoin::network::serialize::Error> {
                let &$thing(ref data) = self;
                data.consensus_encode(s)
            }
        }

        impl<D: ::deps::bitcoin::network::serialize::SimpleDecoder> ::deps::bitcoin::network::encodable::ConsensusDecodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, ::deps::bitcoin::network::serialize::Error> {
                Ok($thing(ConsensusDecodable::consensus_decode(d)?))
            }
        }
    );
}

macro_rules! nu_select {
    ($($name:pat = $rx:expr => $code:expr),+) => ({
        nu_select!{ $($name = $rx, recv => $code),+ }
    });
    ($($name:pat = $rx:expr, $meth:ident => $code:expr),+) => ({
        use rustrt::local::Local;
        use rustrt::task::Task;
        use sync::comm::Packet;

        // Is anything already ready to receive? Grab it without waiting.
        $(
            if (&$rx as &Packet).can_recv() {
                let $name = $rx.$meth();
                $code
            }
        )else+
        else {
            // Start selecting on as many as we need to before getting a bite.
            // Keep count of how many, since we need to abort every selection
            // that we started.
            let mut started_count = 0;
            // Restrict lifetime of borrows in `packets`
            {
                let packets = [ $( &$rx as &Packet, )+ ];

                let task: Box<Task> = Local::take();
                task.deschedule(packets.len(), |task| {
                    match packets[started_count].start_selection(task) {
                        Ok(()) => {
                            started_count += 1;
                            Ok(())
                        }
                        Err(task) => Err(task)
                    }
                });
            }

            let mut i = 0;
            let ret = $(
                // Abort the receivers, stopping at the first ready one to get its data.
                if { i += 1; i <= started_count } &&
                     // If start_selection() failed, abort_selection() will fail too,
                     // but it still counts as "data available".
                     ($rx.abort_selection() || i == started_count) {
                    // React to the first
                    let $name = $rx.$meth();
                    $code
                })else+
                else {
                    fail!("we didn't find the ready receiver, but we should have had one");
                };
            // At this point, the first i receivers have been aborted. We need to abort the rest:
            $(if i > 0 {
                i -= 1;
            } else {
                $rx.abort_selection();
            })+
            let _ = i; // Shut up `i -= 1 but i is never read` warning
            // Return
            ret
        }
    })
}

macro_rules! user_enum {
    (
        $(#[$attr:meta])*
        pub enum $name:ident {
            $(#[$doc:meta]
              $elem:ident <-> $txt:expr),*
        }
    ) => (
        $(#[$attr])*
        pub enum $name {
            $(#[$doc] $elem),*
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.pad(match *self {
                    $($name::$elem => $txt),*
                })
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.pad(match *self {
                    $($name::$elem => $txt),*
                })
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = ::std::io::Error;
            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($txt => Ok($name::$elem)),*,
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidInput,
                        format!("Unknown network (type {})", s),
                    )),
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde::Deserializer<'de>,
            {
                use $crate::std::fmt::{self, Formatter};

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("an enum value")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        static FIELDS: &'static [&'static str] = &[$(stringify!($txt)),*];

                        $( if v == $txt { Ok($name::$elem) } )else*
                        else {
                            Err(E::unknown_variant(v, FIELDS))
                        }
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }

                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }
    );
}

macro_rules! impl_array_newtype_encodable {
    ($thing:ident, $ty:ty, $len:expr) => {
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $thing {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde::Deserializer<'de>,
            {
                use $crate::std::fmt::{self, Formatter};

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $thing;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a fixed size array")
                    }

                    #[inline]
                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::SeqAccess<'de>,
                    {
                        let mut ret: [$ty; $len] = [0; $len];
                        for item in ret.iter_mut() {
                            *item = match seq.next_element()? {
                                Some(c) => c,
                                None => return Err($crate::serde::de::Error::custom("end of stream"))
                            };
                        }
                        Ok($thing(ret))
                    }
                }

                deserializer.deserialize_seq(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $thing {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                let &$thing(ref dat) = self;
                (&dat[..]).serialize(serializer)
            }
        }
    }
}

macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {
        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }

    }
}

macro_rules! display_from_debug {
    ($thing:ident) => {
        impl ::std::fmt::Display for $thing {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
                ::std::fmt::Debug::fmt(self, f)
            }
        }
    }
}

#[cfg(test)]
macro_rules! hex_script (($s:expr) => (::deps::bitcoin::blockdata::script::Script::from(::util::hash::hex_bytes($s).unwrap())));

#[cfg(test)]
macro_rules! hex_hash (($s:expr) => (::deps::bitcoin::util::hash::Sha256dHash::from(&::util::hash::hex_bytes($s).unwrap()[..])));

macro_rules! serde_struct_impl {
    ($name:ident, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use $crate::std::fmt::{self, Formatter};
                use $crate::serde::de::IgnoredAny;

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                    type Value = Enum;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a field name")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        match v {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl<'de> $crate::serde::Deserialize<'de> for Enum {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: ::serde::de::Deserializer<'de>,
                    {
                        deserializer.deserialize_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a struct")
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::MapAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        $(let mut $fe = None;)*

                        loop {
                            match map.next_key::<Enum>()? {
                                Some(Enum::Unknown__Field) => {
                                    map.next_value::<IgnoredAny>()?;
                                }
                                $(
                                    Some(Enum::$fe) => {
                                        $fe = Some(map.next_value()?);
                                    }
                                )*
                                None => { break; }
                            }
                        }

                        $(
                            let $fe = match $fe {
                                Some(x) => x,
                                None => return Err(A::Error::missing_field(stringify!($fe))),
                            };
                        )*

                        let ret = $name {
                            $($fe: $fe),*
                        };

                        Ok(ret)
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                use $crate::serde::ser::SerializeStruct;

                // Only used to get the struct length.
                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                $(
                    st.serialize_field(stringify!($fe), &self.$fe)?;
                )*

                st.end()
            }
        }
    )
}
