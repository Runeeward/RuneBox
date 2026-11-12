//! `runebox-browser`: the in-sandbox stateful browser driver.

fn main() {
    std::process::exit(runebox_browser::cli::main(
        std::env::args().skip(1).collect(),
    ));
}
