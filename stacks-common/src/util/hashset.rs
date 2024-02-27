use std::hash::Hash;
use std::iter::{FromIterator, IntoIterator};
use std::ops::{Deref, DerefMut};

//#[cfg(any(test, feature = "testing"))]
use fake::{Dummy, Fake, Faker};
use hashbrown::HashSet;
use rand::Rng;
use speedy::{Context, Endianness, Readable, Reader, Writable, Writer};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StacksHashSet<T>(pub hashbrown::HashSet<T>)
where
    T: Eq + Hash;

impl<T> StacksHashSet<T>
where
    T: Eq + Hash,
{
    pub fn new() -> Self {
        StacksHashSet(hashbrown::HashSet::new())
    }
}

impl<T> Deref for StacksHashSet<T>
where
    T: Eq + Hash,
{
    type Target = hashbrown::HashSet<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for StacksHashSet<T>
where
    T: Eq + Hash,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> FromIterator<T> for StacksHashSet<T>
where
    T: Eq + Hash,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = StacksHashSet(HashSet::new());
        for item in iter {
            set.insert(item);
        }
        set
    }
}

impl<'a, C, K> Readable<'a, C> for StacksHashSet<K>
where
    C: Context,
    K: Readable<'a, C> + Eq + Hash,
{
    #[inline]
    fn read_from<R: Reader<'a, C>>(reader: &mut R) -> Result<Self, C::Error> {
        let length = speedy::private::read_length(reader)?;
        reader.read_collection(length)
    }

    #[inline]
    fn minimum_bytes_needed() -> usize {
        4
    }
}

impl<C, K> Writable<C> for StacksHashSet<K>
where
    C: Context,
    K: Writable<C> + Eq + Hash,
{
    #[inline]
    fn write_to<W: ?Sized + Writer<C>>(&self, writer: &mut W) -> Result<(), C::Error> {
        speedy::private::write_length(self.len(), writer)?;
        writer.write_collection(self.iter())
    }

    #[inline]
    fn bytes_needed(&self) -> Result<usize, C::Error> {
        // Borrowed from the `speedy` crate.
        if self.len() as u64 >= 0x7FFFFFFF_FFFFFFFF {
            unsafe { std::hint::unreachable_unchecked() }
        }

        let mut count = std::mem::size_of::<u32>();
        for value in self.iter() {
            count += value.bytes_needed()?;
        }

        Ok(count)
    }
}

//#[cfg(any(test, feature = "testing"))]
impl<T> Dummy<Faker> for StacksHashSet<T>
where
    T: Dummy<Faker> + Eq + Hash,
{
    fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
        let len = rng.gen_range(1..5);
        let mut set = StacksHashSet::new();
        for _ in 0..len {
            set.insert(T::dummy_with_rng(&config, rng));
        }
        set
    }
}
