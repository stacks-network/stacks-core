use crate::core::StacksEpochId;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd)]
pub enum ClarityVersion {
    Clarity1,
    Clarity2,
}

impl ClarityVersion {
    pub fn latest() -> ClarityVersion {
        ClarityVersion::Clarity2
    }
    pub fn default_for_epoch(epoch_id: StacksEpochId) -> ClarityVersion {
        match epoch_id {
            StacksEpochId::Epoch10 => {
                warn!("Attempted to get default Clarity version for Epoch 1.0 where Clarity does not exist");
                ClarityVersion::Clarity1
            }
            StacksEpochId::Epoch20 => ClarityVersion::Clarity1,
            StacksEpochId::Epoch21 => ClarityVersion::Clarity2,
        }
    }
}
