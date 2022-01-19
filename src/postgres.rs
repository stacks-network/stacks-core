extern crate postgres;
use postgres::{Client, NoTls, Error};

fn main() -> Result<(), Error> {
    let mut client = Client::connect("postgresql://postgres:postgres@localhost/temp_database", NoTls)?;
    
    client.execute(
        "INSERT INTO mempool_tx_attempt (tx_id, status, comment) VALUES ($1, $2, $3)",
        &[&"id3", &"status3", &"comment3"],
    )?;

    Ok(())

}
