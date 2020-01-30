/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::io::prelude::*;
use std::io;
use std::io::{Read, Write};

use util::log;

/// Wrap a Read so that we store a copy of what was read.
/// Used for re-trying reads when we don't know what to expect from the stream.
pub struct RetryReader<'a, R: Read> {
    fd: &'a mut R,
    buf: Vec<u8>,
    i: usize
}

impl<'a, R: Read> RetryReader<'a, R> {
    pub fn new(fd: &'a mut R) -> RetryReader<'a, R> {
        RetryReader {
            fd: fd,
            buf: vec![],
            i: 0
        }
    }

    pub fn set_position(&mut self, offset: usize) -> () {
        if offset <= self.buf.len() {
            self.i = offset
        }
        else {
            self.i = self.buf.len()
        }
    }

    pub fn position(&self) -> usize {
        self.i
    }

    fn read_and_buffer(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nr = self.fd.read(buf)?;
        self.buf.extend_from_slice(buf);
        self.i += buf.len();
        Ok(nr)
    }
}

impl<'a, R: Read> Read for RetryReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nr_buf = 
            if self.i < self.buf.len() {
                // consume from inner buffer
                let bytes_copied = 
                    if buf.len() < self.buf.len() - self.i {
                        buf.len()
                    }
                    else {
                        self.buf.len() - self.i
                    };

                buf.copy_from_slice(&self.buf[self.i..(self.i + bytes_copied)]);
                self.i += bytes_copied;
                bytes_copied
            }
            else {
                0
            };
        
        let nr = self.read_and_buffer(&mut buf[nr_buf..])?;
        Ok(nr + nr_buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_retry_reader() {
        let buf = vec![1,1,1,2,2,2,3,3,3,4,4,4];
        let mut cursor = io::Cursor::new(&buf);
        let mut retry_reader = RetryReader::new(&mut cursor);

        let mut empty_buf = [];
        let nr = retry_reader.read(&mut empty_buf).unwrap();
        assert_eq!(nr, 0);
        
        for i in 1..5 {
            let mut read_buf = [0u8; 3];
            retry_reader.read_exact(&mut read_buf).unwrap();
            assert_eq!(read_buf, [i as u8, i as u8, i as u8]);
        }

        let mut tmp_buf = [0u8; 3];
        let e = retry_reader.read_exact(&mut tmp_buf);
        let e_str = format!("{:?}", &e);
        assert!(e.is_err(), e_str);
        assert!(format!("{:?}", &e.unwrap_err()).find("failed to fill whole buffer").is_some(), e_str);
        
        let res = retry_reader.read(&mut tmp_buf);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 0);

        retry_reader.set_position(0);
        
        for i in 1..5 {
            let mut read_buf = [0u8; 3];
            retry_reader.read_exact(&mut read_buf).unwrap();
            assert_eq!(read_buf, [i as u8, i as u8, i as u8]);
        }
    }
}
