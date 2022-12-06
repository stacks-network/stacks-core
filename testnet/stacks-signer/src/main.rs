use stacks_signer::config::{Config};
use slog::{Drain, o, info, Logger};

fn main() {
    let log = make_logger();
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!(log, "{:?}", config);
}

fn make_logger() -> Logger {
    let decorator = slog_term::PlainDecorator::new(std::io::stdout());
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, o!());
    log
}
