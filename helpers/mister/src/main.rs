fn main() {
    if let Err(err) = sgm_mister_helper::run() {
        sgm_mister_helper::record_fatal_error(&err);
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
