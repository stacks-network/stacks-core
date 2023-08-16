use events::{NewBlockEventListener, WaitableCounter};

mod events;

pub struct ProducerState {
    burn_block_counter: WaitableCounter,
}

fn main() {
    let block_listener = NewBlockEventListener::new();
    let _listener_thread = block_listener.serve();

    loop {
        block_listener.burn_blocks_processed.wait_for_bump();
        // we've woken up, build a block!
        eprintln!("wakeup!");
        let client = reqwest::blocking::Client::new();
        let path = format!("{}/v2/make_block_template", "http://127.0.0.1:40000");

        // let res = client.get(path)
        //     .send()
        //     .and_then(|resp| resp.json::<serde_json::Value>());
        // match res {
        //     Ok(block) => eprintln!("Assembled: {}", block),
        //     Err(e) => eprintln!("Error producing template, will try later: {}", e),
        // }
    }
}
