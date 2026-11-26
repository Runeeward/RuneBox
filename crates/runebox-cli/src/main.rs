//! `runebox`: policy, approvals, and signed audit for AI agents.

use std::io::Write;

/// Stack for the thread that runs the command. Windows gives the main
/// thread 1 MiB, which debug builds outgrow; this matches the Unix default.
const MAIN_STACK: usize = 8 * 1024 * 1024;

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: start async runtime: {e}");
            std::process::exit(1);
        }
    };
    let args = std::env::args_os().skip(1).collect();
    let spawned = std::thread::Builder::new()
        .name("runebox-main".into())
        .stack_size(MAIN_STACK)
        .spawn(move || {
            let code = runtime.block_on(runebox_cli::execute(args));
            let _ = std::io::stdout().flush();
            // Exit without dropping the runtime: a pending blocking read of
            // stdin (an attached terminal) must not hold the process open.
            std::process::exit(code);
        });
    match spawned.map(std::thread::JoinHandle::join) {
        // The thread exits the process itself; returning means it panicked,
        // so keep Rust's panic exit code.
        Ok(_) => std::process::exit(101),
        Err(e) => {
            eprintln!("error: start main thread: {e}");
            std::process::exit(1);
        }
    }
}
