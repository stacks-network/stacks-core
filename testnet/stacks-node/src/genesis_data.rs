use stx_genesis::GenesisData;

#[cfg(any(not(test), feature = "prod-genesis-chainstate"))]
lazy_static! {
    pub static ref GENESIS_DATA: GenesisData = GenesisData::new(false);
}

#[cfg(all(test, not(feature = "prod-genesis-chainstate")))]
lazy_static! {
    pub static ref GENESIS_DATA: GenesisData = GenesisData::new(true);
}
