use std::{fmt, io, error};

#[derive(Debug)]
pub enum MarfError {
    NotOpenedError,
    IOError(io::Error),
    SQLError(String),
    DbError(String),
    RequestedIdentifierForExtensionTrie,
    NotFoundError,
    BackptrNotFoundError,
    ExistsError,
    BadSeekValue,
    CorruptionError(String),
    BlockHashMapCorruptionError(Option<Box<MarfError>>),
    ReadOnlyError,
    UnconfirmedError,
    NotDirectoryError,
    PartialWriteError,
    InProgressError,
    WriteNotBegunError,
    CursorError(crate::node::CursorError),
    RestoreMarfBlockError(Box<MarfError>),
    NonMatchingForks([u8; 32], [u8; 32]),
}

impl From<io::Error> for MarfError {
    fn from(err: io::Error) -> Self {
        MarfError::IOError(err)
    }
}

impl fmt::Display for MarfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MarfError::IOError(ref e) => fmt::Display::fmt(e, f),
            MarfError::SQLError(ref e) => fmt::Display::fmt(e, f),
            MarfError::DbError(ref s) => fmt::Display::fmt(s, f),
            MarfError::CorruptionError(ref s) => fmt::Display::fmt(s, f),
            MarfError::CursorError(ref e) => fmt::Display::fmt(e, f),
            MarfError::BlockHashMapCorruptionError(ref opt_e) => {
                f.write_str("Corrupted MARF BlockHashMap")?;
                match opt_e {
                    Some(e) => write!(f, ": {}", e),
                    None => Ok(()),
                }
            }
            MarfError::NotOpenedError => write!(f, "Tried to read data from unopened storage"),
            MarfError::NotFoundError => write!(f, "Object not found"),
            MarfError::BackptrNotFoundError => write!(f, "Object not found from backptrs"),
            MarfError::ExistsError => write!(f, "Object exists"),
            MarfError::BadSeekValue => write!(f, "Bad seek value"),
            MarfError::ReadOnlyError => write!(f, "Storage is in read-only mode"),
            MarfError::UnconfirmedError => write!(f, "Storage is in unconfirmed mode"),
            MarfError::NotDirectoryError => write!(f, "Not a directory"),
            MarfError::PartialWriteError => {
                write!(f, "Data is partially written and not yet recovered")
            }
            MarfError::InProgressError => write!(f, "Write was in progress"),
            MarfError::WriteNotBegunError => write!(f, "Write has not begun"),
            MarfError::RestoreMarfBlockError(_) => write!(
                f,
                "Failed to restore previous open block during block header check"
            ),
            MarfError::NonMatchingForks(_, _) => {
                write!(f, "The supplied blocks are not in the same fork")
            }
            MarfError::RequestedIdentifierForExtensionTrie => {
                write!(f, "BUG: MARF requested the identifier for a RAM trie")
            }
        }
    }
}

impl std::error::Error for MarfError {
    
}

/*impl error::Error for MarfError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            MarfError::IOError(ref e) => Some(e),
            MarfError::SQLError(ref e) => Some(&MarfError::DbError(e.to_string())),
            MarfError::RestoreMarfBlockError(ref e) => Some(e),
            MarfError::BlockHashMapCorruptionError(ref opt_e) => match opt_e {
                Some(ref e) => Some(e),
                None => None,
            },
            _ => None,
        }
    }
}*/