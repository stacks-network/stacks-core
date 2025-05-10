use std::io::Cursor;

use anyhow::Result;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::read_next;

use crate::utils::config;

pub async fn fetch_nakamoto_block(height: u64) -> Result<NakamotoBlock> {
    let node_url = config::get_node_url();
    let response = reqwest::get(&format!("{}/v3/blocks/height/{}", node_url, height)).await?;
    let block_bytes = response.bytes().await?;

    let mut cursor = Cursor::new(block_bytes);
    let block: NakamotoBlock = read_next(&mut cursor)?;

    Ok(block)
}

