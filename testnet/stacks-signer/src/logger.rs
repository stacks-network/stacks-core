use tracing::info;
use tracing_subscriber;

pub fn setup() {
    tracing_subscriber::fmt::init();
}
