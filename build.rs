use copy_to_output::copy_to_output;

fn main() {
    let profile = &std::env::var("PROFILE").unwrap();
    copy_to_output("raw", profile).expect("Failed to copy raw files");
}
