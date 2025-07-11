// Copyright (C) 2025 Stacks Open Internet Foundation
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

use stacks::types::chainstate::{StacksPrivateKey, StacksPublicKey};

use super::miner_db::MinerDB;

#[test]
fn miner_db_units() {
    let miner_db = MinerDB::open(":memory:").unwrap();
    let sk_0 = StacksPrivateKey::from_seed(&[0, 1, 2, 0]);
    let pk_0 = StacksPublicKey::from_private(&sk_0);
    let sk_1 = StacksPrivateKey::from_seed(&[1, 2, 0, 1]);
    let pk_1 = StacksPublicKey::from_private(&sk_1);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_0, 0).unwrap(), None);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_0, 1).unwrap(), None);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_1, 0).unwrap(), None);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_1, 1).unwrap(), None);

    miner_db.set_latest_chunk_version(&pk_0, 0, 10).unwrap();
    miner_db.set_latest_chunk_version(&pk_0, 1, 20).unwrap();
    miner_db.set_latest_chunk_version(&pk_1, 0, 30).unwrap();
    miner_db.set_latest_chunk_version(&pk_1, 1, 40).unwrap();

    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_0, 0).unwrap(),
        Some(10)
    );
    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_0, 1).unwrap(),
        Some(20)
    );
    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_1, 0).unwrap(),
        Some(30)
    );
    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_1, 1).unwrap(),
        Some(40)
    );

    miner_db.set_latest_chunk_version(&pk_0, 0, 110).unwrap();
    miner_db.set_latest_chunk_version(&pk_0, 1, 120).unwrap();
    miner_db.set_latest_chunk_version(&pk_1, 0, 130).unwrap();
    miner_db.set_latest_chunk_version(&pk_1, 1, 140).unwrap();

    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_0, 0).unwrap(),
        Some(110)
    );
    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_0, 1).unwrap(),
        Some(120)
    );
    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_1, 0).unwrap(),
        Some(130)
    );
    assert_eq!(
        miner_db.get_latest_chunk_version(&pk_1, 1).unwrap(),
        Some(140)
    );

    assert_eq!(miner_db.get_latest_chunk_version(&pk_0, 10).unwrap(), None);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_0, 11).unwrap(), None);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_1, 10).unwrap(), None);
    assert_eq!(miner_db.get_latest_chunk_version(&pk_1, 11).unwrap(), None);
}
