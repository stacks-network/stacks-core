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

pub struct CliTheme;

impl cliclack::Theme for CliTheme {
    fn progress_chars(&self) -> String {
        "⣿⣾⣽⣻⢿⡿⣟⣯⣷⣀".to_string()
    }

    // fn default_progress_template(&self) -> String {
    //     "{spinner:.cyan} {msg:20} {percent:>3}% |{bar:30.cyan/blue}| {pos:>7}/{len:7} • {per_sec:>10} • ETA {eta_precise}".to_string()
    // }
}
