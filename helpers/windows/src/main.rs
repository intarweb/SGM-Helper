fn main() {
    if let Err(err) = sgm_windows_helper::run() {
        sgm_windows_helper::record_fatal_error(&err);
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
