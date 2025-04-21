use anyhow::Result;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::read_next;
use std::io::Cursor;

fn main() -> Result<()> {
    // Fetch the block data
    let url = "https://stacks-node-api.mainnet.stacks.co/v3/blocks/height/999129";
    let response = reqwest::blocking::get(url)?;
    let block_bytes = response.bytes()?;

    // Parse the block
    let mut cursor = Cursor::new(block_bytes);
    let block: NakamotoBlock = read_next(&mut cursor)?;

    // print block as json
    println!("{}", serde_json::to_string(&block)?);

    Ok(())
}
