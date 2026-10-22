fn main() {
    if let Err(err) = sgm_steamdeck_helper::run() {
        sgm_steamdeck_helper::record_fatal_error(&err);
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
