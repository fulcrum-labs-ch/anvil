//! `anvil` entry point. All logic lives in the library; `main` only maps a
//! result into a process exit code (R100).

fn main() {
    match fulcrum_anvil::cli::run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    }
}
