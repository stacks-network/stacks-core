// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! An event-observer request body, decoded the way the signer's event
//! receiver decodes it (`process_event` in `libsigner/src/events.rs`): JSON
//! into the path's event type, then into a `SignerEvent`. The first input
//! byte picks the path.

#![no_main]

use blockstack_lib::chainstate::stacks::events::{BurnBlockEvent, StackerDBChunksEvent};
use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use libfuzzer_sys::fuzz_target;
use libsigner::v0::messages::SignerMessage;
use libsigner::{EventError, SignerEvent, StacksBlockEvent};
use serde::de::DeserializeOwned;

fn decode<E>(body: &[u8]) -> Result<SignerEvent<SignerMessage>, EventError>
where
    E: DeserializeOwned + TryInto<SignerEvent<SignerMessage>, Error = EventError>,
{
    let event: E =
        serde_json::from_slice(body).map_err(|e| EventError::Deserialize(format!("{e:?}")))?;
    event.try_into()
}

fuzz_target!(|data: &[u8]| {
    let Some((&path, body)) = data.split_first() else {
        return;
    };
    // The receiver reads the body into a `String` first.
    if std::str::from_utf8(body).is_err() {
        return;
    }
    let event = match path % 4 {
        0 => decode::<StackerDBChunksEvent>(body),
        1 => decode::<BlockValidateResponse>(body),
        2 => decode::<BurnBlockEvent>(body),
        _ => decode::<StacksBlockEvent>(body),
    };
    if let Ok(event) = event {
        let _ = format!("{event:?}");
    }
});
