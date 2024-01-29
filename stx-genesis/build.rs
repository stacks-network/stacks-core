use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::{env, fs};

use libflate::deflate;
use sha2::{Digest, Sha256};

pub static CHAINSTATE_FILE: &str = "chainstate.txt";
pub static CHAINSTATE_SHA256_FILE: &str = "chainstate.txt.sha256";

pub static CHAINSTATE_TEST_FILE: &str = "chainstate-test.txt";
pub static CHAINSTATE_TEST_SHA256_FILE: &str = "chainstate-test.txt.sha256";

pub static NAME_ZONEFILES_FILE: &str = "name_zonefiles.txt";
pub static NAME_ZONEFILES_SHA256_FILE: &str = "name_zonefiles.txt.sha256";

pub static NAME_ZONEFILES_TEST_FILE: &str = "name_zonefiles-test.txt";
pub static NAME_ZONEFILES_TEST_SHA256_FILE: &str = "name_zonefiles-test.txt.sha256";

fn main() {
    verify_name_zonefiles_integrity(true)
        .expect("failed to verify and output name_zonefiles.txt.sha256 hash");
    verify_name_zonefiles_integrity(false)
        .expect("failed to verify and output name_zonefiles-test.txt.sha256 hash");
    verify_genesis_integrity(true)
        .expect("failed to verify and output chainstate-test.txt.sha256 hash");
    verify_genesis_integrity(false)
        .expect("failed to verify and output chainstate.txt.sha256 hash");
    write_chainstate_archives(true).expect("failed to write chainstate test data archives");
    write_chainstate_archives(false).expect("failed to write chainstate prod data archives");
    write_name_zonefiles_archive(true).expect("failed to write name zonefiles test data archive");
    write_name_zonefiles_archive(false).expect("failed to write name zonefiles prod data archive");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=chainstate-test.txt.sha256");
    println!("cargo:rerun-if-changed=chainstate-test.txt");
    println!("cargo:rerun-if-changed=chainstate.txt.sha256");
    println!("cargo:rerun-if-changed=chainstate.txt");
    println!("cargo:rerun-if-changed=name_zonefiles.txt.sha256");
    println!("cargo:rerun-if-changed=name_zonefiles.txt");
}

fn open_chainstate_file(test_data: bool) -> File {
    File::open(if test_data {
        CHAINSTATE_TEST_FILE
    } else {
        CHAINSTATE_FILE
    })
    .unwrap()
}

pub fn write_chainstate_archives(test_data: bool) -> std::io::Result<()> {
    write_chainstate_archive(test_data, "account_balances", "STX BALANCES")?;
    write_chainstate_archive(test_data, "account_lockups", "STX VESTING")?;
    write_chainstate_archive(test_data, "namespaces", "NAMESPACES")?;
    write_chainstate_archive(test_data, "names", "NAMES")?;
    Ok(())
}

fn write_chainstate_archive(
    test_data: bool,
    output_file_name: &str,
    section_name: &str,
) -> std::io::Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let chainstate_file = open_chainstate_file(test_data);
    let reader = BufReader::new(chainstate_file);
    let out_file_name = if test_data {
        output_file_name.to_owned() + "-test"
    } else {
        output_file_name.to_owned()
    };
    let out_file_path = Path::new(&out_dir).join(out_file_name + ".gz");
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

fn write_name_zonefiles_archive(test_data: bool) -> std::io::Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let zonefiles_file = File::open(if test_data {
        NAME_ZONEFILES_TEST_FILE
    } else {
        NAME_ZONEFILES_FILE
    })
    .unwrap();
    let mut reader = BufReader::new(zonefiles_file);
    let out_file_name = if test_data {
        "name_zonefiles-test"
    } else {
        "name_zonefiles"
    };
    let out_file_path = Path::new(&out_dir).join(out_file_name.to_owned() + ".gz");
    let out_file = File::create(out_file_path)?;
    let mut encoder = deflate::Encoder::new(out_file);
    std::io::copy(&mut reader, &mut encoder).unwrap();
    let mut out_file = encoder.finish().into_result().unwrap();
    out_file.flush()?;
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

fn verify_genesis_integrity(test_data: bool) -> std::io::Result<()> {
    let genesis_data_sha = sha256_digest(open_chainstate_file(test_data));
    let expected_genesis_sha_file = if test_data {
        CHAINSTATE_TEST_SHA256_FILE
    } else {
        CHAINSTATE_SHA256_FILE
    };
    let expected_genesis_sha = fs::read_to_string(expected_genesis_sha_file).unwrap();
    if !genesis_data_sha.eq_ignore_ascii_case(&expected_genesis_sha) {
        panic!(
            "FATAL ERROR: chainstate.txt hash mismatch, expected {}, got {}",
            expected_genesis_sha, genesis_data_sha
        );
    }
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_file = if test_data {
        "chainstate-test.txt.sha256"
    } else {
        "chainstate.txt.sha256"
    };
    let chainstate_hash_file_path = Path::new(&out_dir).join(out_file);
    let mut chainstate_hash_file = File::create(chainstate_hash_file_path)?;
    chainstate_hash_file.write_all(genesis_data_sha.as_bytes())?;
    chainstate_hash_file.flush()?;
    Ok(())
}

fn verify_name_zonefiles_integrity(test_data: bool) -> std::io::Result<()> {
    let zonefiles_data_sha = sha256_digest(
        File::open(if test_data {
            NAME_ZONEFILES_TEST_FILE
        } else {
            NAME_ZONEFILES_FILE
        })
        .unwrap(),
    );
    let expected_zonefiles_sha = fs::read_to_string(if test_data {
        NAME_ZONEFILES_TEST_SHA256_FILE
    } else {
        NAME_ZONEFILES_SHA256_FILE
    })
    .unwrap();
    if !zonefiles_data_sha.eq_ignore_ascii_case(&expected_zonefiles_sha) {
        panic!(
            "FATAL ERROR: name_zonefiles.txt hash mismatch, expected {}, got {}",
            expected_zonefiles_sha, zonefiles_data_sha
        );
    }
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let zonefile_hash_file_path = Path::new(&out_dir).join(if test_data {
        NAME_ZONEFILES_TEST_SHA256_FILE
    } else {
        NAME_ZONEFILES_SHA256_FILE
    });
    let mut zonefile_hash_file = File::create(zonefile_hash_file_path)?;
    zonefile_hash_file.write_all(zonefiles_data_sha.as_bytes())?;
    zonefile_hash_file.flush()?;
    Ok(())
}
