use std::io::{Error, ErrorKind};

pub trait ToIoResult {
    type T;
    fn to_io_result(self, msg: &'static str) -> Result<Self::T, Error>;
}

fn io_error(msg: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, msg)
}

impl<T> ToIoResult for Option<T> {
    type T = T;
    fn to_io_result(self, msg: &'static str) -> Result<Self::T, Error> {
        self.ok_or_else(|| io_error(msg))
    }
}

impl<T, E> ToIoResult for Result<T, E> {
    type T = T;
    fn to_io_result(self, msg: &'static str) -> Result<Self::T, Error> {
        self.map_err(|_| io_error(msg))
    }
}
