use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
};

use libflate::deflate;
use sha2::{Digest, Sha256};

fn main() {
    verify_genesis_integrity();
    write_archives().expect("failed to write archives");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=chainstate.txt.sha256");
    println!("cargo:rerun-if-changed=chainstate.txt");
}

fn open_chainstate_file() -> File {
    File::open("chainstate.txt").unwrap()
}

pub fn write_archives() -> std::io::Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    {
        let chainstate_file = open_chainstate_file();
        let reader = BufReader::new(chainstate_file);
        let balances_file_path = Path::new(&out_dir).join("account_balances.gz");
        let balances_file = File::create(balances_file_path)?;
        let mut balances_encoder = deflate::Encoder::new(balances_file);

        for line in reader
            .lines()
            .map(|line| line.unwrap())
            .skip_while(|line| !line.eq(&"-----BEGIN STX BALANCES-----"))
            // skip table header line "address,balance"
            .skip(2)
            .take_while(|line| !line.eq(&"-----END STX BALANCES-----"))
        {
            balances_encoder.write_all(&[line.as_bytes(), &[b'\n']].concat())?;
        }

        let mut balances_file = balances_encoder.finish().into_result().unwrap();
        balances_file.flush()?;
    }
    {
        let chainstate_file = open_chainstate_file();
        let reader = BufReader::new(chainstate_file);
        let vesting_file_path = Path::new(&out_dir).join("account_vesting.gz");
        let vesting_file = File::create(vesting_file_path)?;
        let mut vesting_encoder = deflate::Encoder::new(vesting_file);

        for line in reader
            .lines()
            .map(|line| line.unwrap())
            .skip_while(|line| !line.eq(&"-----BEGIN STX VESTING-----"))
            // skip table header line "address,value,blocks"
            .skip(2)
            .take_while(|line| !line.eq(&"-----END STX VESTING-----"))
        {
            vesting_encoder.write_all(&[line.as_bytes(), &[b'\n']].concat())?;
        }

        let mut vesting_file = vesting_encoder.finish().into_result().unwrap();
        vesting_file.flush()?;
    }
    Ok(())
}

fn sha256_digest<R: Read>(mut reader: R) -> String {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    encode_hex(&hasher.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn verify_genesis_integrity() {
    let genesis_data_sha = sha256_digest(open_chainstate_file());
    let expected_genesis_sha = fs::read_to_string("chainstate.txt.sha256").unwrap();
    if !genesis_data_sha.eq_ignore_ascii_case(&expected_genesis_sha) {
        panic!(
            "FATAL ERROR: chainstate.txt hash mismatch, expected {}, got {}",
            expected_genesis_sha, genesis_data_sha
        );
    }
}
