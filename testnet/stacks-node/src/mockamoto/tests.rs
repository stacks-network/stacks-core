use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::config::EventKeyType;
use crate::config::EventObserverConfig;
use crate::tests::neon_integrations::test_observer;
use crate::Config;
use crate::ConfigFile;

use super::MockamotoNode;

#[test]
fn observe_100_blocks() {
    let mut conf = Config::from_config_file(ConfigFile::mockamoto()).unwrap();
    conf.node.mockamoto_time_ms = 10;

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut mockamoto = MockamotoNode::new(&conf).unwrap();
    let globals = mockamoto.globals.clone();
    let start = Instant::now();

    let node_thread = thread::Builder::new()
        .name("mockamoto-main".into())
        .spawn(move || mockamoto.run())
        .expect("FATAL: failed to start mockamoto main thread");

    // complete within 2 minutes or abort
    let completed = loop {
        if Instant::now().duration_since(start) > Duration::from_secs(120) {
            break false;
        }
        let latest_block = test_observer::get_blocks().pop();
        thread::sleep(Duration::from_secs(1));
        let Some(ref latest_block) = latest_block else {
            info!("No block observed yet!");
            continue;
        };
        let stacks_block_height = latest_block.get("block_height").unwrap().as_u64().unwrap();
        info!("Block height observed: {stacks_block_height}");
        if stacks_block_height >= 100 {
            break true;
        }
    };

    globals.signal_stop();
    assert!(
        completed,
        "Mockamoto node failed to produce and announce 100 blocks before timeout"
    );
    node_thread
        .join()
        .expect("Failed to join node thread to exit");
}
