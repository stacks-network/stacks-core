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

// `ClarityVersion` lives in `clarity-types` so that lower-level crates (e.g.
// `stacks-codec`) can name it without taking on the full `clarity` dependency.
// Existing callers that imported `clarity::vm::ClarityVersion` continue to work
// via this re-export.
pub use clarity_types::version::ClarityVersion;
