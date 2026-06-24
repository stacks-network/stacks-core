// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use diesel::prelude::*;
use diesel::sql_types::Integer;
// Define a struct to map the PRAGMA result
#[derive(QueryableByName, Debug)]
pub struct CheckpointResult {
    #[diesel(sql_type = Integer)]
    #[diesel(column_name = "busy")]
    pub busy: i32,
    #[diesel(sql_type = Integer)]
    #[diesel(column_name = "log")]
    pub log: i32,
    #[diesel(sql_type = Integer)]
    #[diesel(column_name = "checkpointed")]
    pub checkpointed: i32,
}
