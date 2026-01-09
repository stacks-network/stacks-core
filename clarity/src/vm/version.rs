use std::fmt;
use std::str::FromStr;

use stacks_common::types::StacksEpochId;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum ClarityVersion {
    Clarity1,
    Clarity2,
    Clarity3,
    Clarity4,
    Clarity5,
}

impl fmt::Display for ClarityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClarityVersion::Clarity1 => write!(f, "Clarity 1"),
            ClarityVersion::Clarity2 => write!(f, "Clarity 2"),
            ClarityVersion::Clarity3 => write!(f, "Clarity 3"),
            ClarityVersion::Clarity4 => write!(f, "Clarity 4"),
            ClarityVersion::Clarity5 => write!(f, "Clarity 5"),
        }
    }
}

impl ClarityVersion {
    pub fn latest() -> ClarityVersion {
        ClarityVersion::Clarity4
    }

    pub const ALL: &'static [ClarityVersion] = &[
        ClarityVersion::Clarity1,
        ClarityVersion::Clarity2,
        ClarityVersion::Clarity3,
        ClarityVersion::Clarity4,
        ClarityVersion::Clarity5,
    ];

    pub fn default_for_epoch(epoch_id: StacksEpochId) -> ClarityVersion {
        match epoch_id {
            StacksEpochId::Epoch10 => {
                warn!("Attempted to get default Clarity version for Epoch 1.0 where Clarity does not exist");
                ClarityVersion::Clarity1
            }
            StacksEpochId::Epoch20 => ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05 => ClarityVersion::Clarity1,
            StacksEpochId::Epoch21 => ClarityVersion::Clarity2,
            StacksEpochId::Epoch22 => ClarityVersion::Clarity2,
            StacksEpochId::Epoch23 => ClarityVersion::Clarity2,
            StacksEpochId::Epoch24 => ClarityVersion::Clarity2,
            StacksEpochId::Epoch25 => ClarityVersion::Clarity2,
            StacksEpochId::Epoch30 => ClarityVersion::Clarity3,
            StacksEpochId::Epoch31 => ClarityVersion::Clarity3,
            StacksEpochId::Epoch32 => ClarityVersion::Clarity3,
            StacksEpochId::Epoch33 => ClarityVersion::Clarity4,
            StacksEpochId::Epoch34 => ClarityVersion::Clarity5,
        }
    }
}

impl FromStr for ClarityVersion {
    type Err = &'static str;

    fn from_str(version: &str) -> Result<ClarityVersion, &'static str> {
        let s = version.to_string().to_lowercase();
        if s == "clarity1" {
            Ok(ClarityVersion::Clarity1)
        } else if s == "clarity2" {
            Ok(ClarityVersion::Clarity2)
        } else if s == "clarity3" {
            Ok(ClarityVersion::Clarity3)
        } else if s == "clarity4" {
            Ok(ClarityVersion::Clarity4)
        } else if s == "clarity5" {
            Ok(ClarityVersion::Clarity5)
        } else {
            Err("Invalid clarity version. Valid versions are: Clarity1, Clarity2, Clarity3, Clarity4, Clarity5.")
        }
    }
}
