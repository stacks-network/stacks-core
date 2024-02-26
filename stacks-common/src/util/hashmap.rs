use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use std::iter::{IntoIterator, FromIterator};

//#[cfg(any(test, feature = "testing"))]
use fake::{Dummy, Fake, Faker};

use hashbrown::HashMap;
use rand::Rng;
use speedy::{Context, Endianness, Readable, Reader, Writable, Writer};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StacksHashMap<K, V>(pub HashMap<K, V>)
where
    K: Eq + Hash;

impl<K, V> StacksHashMap<K, V>
where
    K: Eq + Hash
{
    pub fn new() -> Self {
        StacksHashMap(HashMap::new())
    }
}

impl<'a, K, V> Deref for StacksHashMap<K, V>
where
    K: Eq + Hash
{
    type Target = HashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for StacksHashMap<K, V> 
where
    K: Eq + Hash
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> FromIterator<(K, V)> for StacksHashMap<K, V> 
where
    K: Eq + Hash
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = StacksHashMap::new();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
    }
}

impl<'a, C, K, V> Readable<'a, C> for StacksHashMap<K, V>
    where 
        C: Context,
        K: Readable<'a, C> + Eq + Hash,
        V: Readable<'a, C>
{
    #[inline]
    fn read_from< R: Reader<'a, C>>( reader: &mut R ) -> Result< Self, C::Error > {
        let length = speedy::private::read_length( reader )?;
        reader.read_collection( length )
    }

    #[inline]
    fn minimum_bytes_needed() -> usize {
        4
    }
}

impl<C, K, V> Writable<C> for StacksHashMap<K, V>
    where 
        C: Context,
        K: Writable< C > + Eq + Hash,
        V: Writable< C >
{
    #[inline]
    fn write_to< W: ?Sized + Writer<C>>( &self, writer: &mut W ) -> Result< (), C::Error > {
        speedy::private::write_length( self.len(), writer )?;
        writer.write_collection( self.iter() )
    }

    #[inline]
    fn bytes_needed( &self ) -> Result< usize, C::Error > {
        // Borrowed from the `speedy` crate.
        if self.len() as u64 >= 0x7FFFFFFF_FFFFFFFF {
            unsafe { std::hint::unreachable_unchecked() }
        }

        let mut count = std::mem::size_of::< u32 >();
        for (key, value) in self.iter() {
            count += key.bytes_needed()? + value.bytes_needed()?;
        }

        Ok( count )
    }
}

//#[cfg(any(test, feature = "testing"))]
impl<K, V> Dummy<Faker> for StacksHashMap<K, V> 
where
    K: Eq + Hash + Dummy<Faker>,
    V: Dummy<Faker>
{
    fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
        let mut map = HashMap::<K, V>::new();
        for _ in 0..rng.gen_range(1..5) {
            map.insert(Faker.fake(), Faker.fake());
        }
        StacksHashMap(map)
    }
}