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

//! Rules of a deploy that need no Wasm parser (ABI 3.4, 3.5): the custom
//! sections a module may carry, and the reasons a deploy is rejected.

use std::fmt;

/// The custom section that holds the module's interface (ABI 4). Required,
/// and validated by the chain.
pub const INTERFACE_SECTION: &str = "abi.interface";
/// The custom section that holds the declared types. Optional; the chain
/// bounds it only by the module size and never decodes it.
pub const TYPES_SECTION: &str = "abi.types";
/// The custom section the toolchain that produced the module owns.
/// Optional; the chain bounds it only by the module size and never decodes
/// it.
pub const PROVENANCE_SECTION: &str = "abi.provenance";

/// Why a module's custom sections are not those the ABI allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustomSectionError {
    /// A section has another name than the three the ABI allows. The
    /// standard `name` section is such a section.
    Unknown,
    /// A section appears more than once.
    Duplicate,
    /// The module has no `abi.interface` section.
    MissingInterface,
}

impl CustomSectionError {
    /// Every reason, in the order the rules are checked.
    pub const ALL: [CustomSectionError; 3] = [
        CustomSectionError::Unknown,
        CustomSectionError::Duplicate,
        CustomSectionError::MissingInterface,
    ];

    /// A stable identifier for the reason, used by the vectors.
    pub const fn as_str(self) -> &'static str {
        match self {
            CustomSectionError::Unknown => "unknown",
            CustomSectionError::Duplicate => "duplicate",
            CustomSectionError::MissingInterface => "missing-interface",
        }
    }
}

impl fmt::Display for CustomSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CustomSectionError {}

/// Checks the names of a module's custom sections, given in the order of the
/// module: each is one of the three the ABI allows and appears once, and
/// `abi.interface` is among them.
///
/// The first section that breaks a rule decides the reason; a missing
/// interface is judged last.
pub fn check_custom_sections<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), CustomSectionError> {
    const ALLOWED: [&str; 3] = [INTERFACE_SECTION, TYPES_SECTION, PROVENANCE_SECTION];
    let mut seen = [false; ALLOWED.len()];
    for name in names {
        let index = ALLOWED
            .iter()
            .position(|allowed| *allowed == name)
            .ok_or(CustomSectionError::Unknown)?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(CustomSectionError::Duplicate);
        }
    }
    if !seen[0] {
        return Err(CustomSectionError::MissingInterface);
    }
    Ok(())
}

stacks_common::define_named_enum!(
    /// Why a deploy is rejected before the module runs (ABI 3.5 steps 1 and
    /// 2), in the order the chain checks. Its name is the one a receipt
    /// carries. The serde form is the Rust variant name, not that name: a
    /// receipt carries `get_name_str()`.
    #[derive(Copy)]
    DeployRejection {
        /// The module is larger than the module size limit (ABI 9.3).
        ModuleSize("module-size"),
        /// The bytes are not a valid Wasm module.
        InvalidWasm("invalid-wasm"),
        /// The module is outside the Wasm profile, or its memory is not as
        /// required (ABI 3.1, 3.2).
        Profile("profile"),
        /// An import is not a host function with its name and type
        /// (ABI 3.2).
        Imports("imports"),
        /// The custom sections are not those the ABI allows (ABI 3.4).
        CustomSections("custom-sections"),
        /// The `abi.interface` section is not a valid interface (ABI 4.1).
        Interface("interface"),
        /// The interface's `abi-version` does not match the import module
        /// (ABI 11).
        AbiVersion("abi-version"),
        /// The exports do not match the interface (ABI 3.3).
        Exports("exports"),
        /// The engine rejects the module.
        Engine("engine"),
    }
);
