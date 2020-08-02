/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

pub const STACKS_BOOT_CODE_CONTRACT_ADDRESS : &'static str = "ST000000000000000000002AMW42H";

pub const STACKS_BOOT_CODE : &'static [&'static str] = &[
    std::include_str!("pox.clar"),
    std::include_str!("lockup.clar")
];

pub const STACKS_BOOT_CODE_CONTRACT_NAMES : &'static [&'static str] = &[
    "pox",
    "lockup"
];

#[cfg(test)]
mod test {
    
