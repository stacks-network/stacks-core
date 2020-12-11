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
    verify_genesis_integrity().expect("failed to verify and output chainstate.txt.sha256 hash");
    write_archives().expect("failed to write archives");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=chainstate.txt.sha256");
    println!("cargo:rerun-if-changed=chainstate.txt");
}

fn open_chainstate_file() -> File {
    File::open("chainstate.txt").unwrap()
}

fn write_archive(output_file_name: &str, section_name: &str) -> std::io::Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let chainstate_file = open_chainstate_file();
    let reader = BufReader::new(chainstate_file);
    let out_file_path = Path::new(&out_dir).join(output_file_name);
    let out_file = File::create(out_file_path)?;
    let mut encoder = deflate::Encoder::new(out_file);

    let section_header = "-----BEGIN ".to_owned() + section_name + "-----";
    let section_footer = "-----END ".to_owned() + section_name + "-----";

    for line in reader
        .lines()
        .map(|line| line.unwrap())
        .skip_while(|line| !line.eq(&section_header))
        // skip table header line
        .skip(2)
        .take_while(|line| !line.eq(&section_footer))
    {
        encoder.write_all(&[line.as_bytes(), &[b'\n']].concat())?;
    }

    let mut out_file = encoder.finish().into_result().unwrap();
    out_file.flush()?;
    Ok(())
}

pub fn write_archives() -> std::io::Result<()> {
    write_archive("account_balances.gz", "STX BALANCES")?;
    write_archive("account_lockups.gz", "STX VESTING")?;
    write_archive("namespaces.gz", "NAMESPACES")?;
    write_archive("names.gz", "NAMES")?;
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

fn verify_genesis_integrity() -> std::io::Result<()> {
    let genesis_data_sha = sha256_digest(open_chainstate_file());
    let expected_genesis_sha = fs::read_to_string("chainstate.txt.sha256").unwrap();
    if !genesis_data_sha.eq_ignore_ascii_case(&expected_genesis_sha) {
        panic!(
            "FATAL ERROR: chainstate.txt hash mismatch, expected {}, got {}",
            expected_genesis_sha, genesis_data_sha
        );
    }
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let chainstate_hash_file_path = Path::new(&out_dir).join("chainstate.txt.sha256");
    let mut chainstate_hash_file = File::create(chainstate_hash_file_path)?;
    chainstate_hash_file.write_all(genesis_data_sha.as_bytes())?;
    chainstate_hash_file.flush()?;
    Ok(())
}
