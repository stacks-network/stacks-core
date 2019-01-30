/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

#[macro_use] pub mod log;
#[macro_use] pub mod macros;
pub mod hash;
pub mod pair;
pub mod vrf;

use std::io::Error as io_error;
use std::sync::mpsc::RecvError as recv_error;
use std::fmt;
use std::error;

#[derive(Debug)]
pub enum Error {
    /// Not implemented 
    NotImplemented,
    /// Failed to start a thread 
    ThreadStartFailure(io_error),
    /// Failed to join a thread 
    ThreadJoinFailure,
    /// Failed to receive data 
    RecvError(recv_error),
    /// Failed to send data 
    SendError,
    /// Channel not connected 
    ChannelNotConnected,
    /// Channel source drained 
    ChannelSourceDrained,
    /// Pipeline stage error 
    ProcessError(String)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotImplemented => f.write_str(error::Error::description(self)),
            Error::ThreadStartFailure(ref e) => fmt::Display::fmt(e, f),
            Error::ThreadJoinFailure => f.write_str(error::Error::description(self)),
            Error::RecvError(ref e) => fmt::Display::fmt(e, f),
            Error::SendError => f.write_str(error::Error::description(self)),
            Error::ChannelNotConnected => f.write_str(error::Error::description(self)),
            Error::ChannelSourceDrained => f.write_str(error::Error::description(self)),
            Error::ProcessError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::NotImplemented => None,
            Error::ThreadStartFailure(ref e) => Some(e),
            Error::ThreadJoinFailure => None,
            Error::RecvError(ref e) => Some(e),
            Error::SendError => None,
            Error::ChannelNotConnected => None,
            Error::ChannelSourceDrained => None,
            Error::ProcessError(ref e) => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::NotImplemented => "Not implemented",
            Error::ThreadStartFailure(ref e) => e.description(),
            Error::ThreadJoinFailure => "Failed to join thread",
            Error::RecvError(ref e) => e.description(),
            Error::SendError => "Failed to send",
            Error::ChannelNotConnected => "Channel not connected",
            Error::ChannelSourceDrained => "Channel source drained",
            Error::ProcessError(ref e) => e.as_str()
        }
    }
}
