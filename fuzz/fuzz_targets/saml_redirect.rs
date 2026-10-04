#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| rustid_fuzz::saml_redirect(data));
