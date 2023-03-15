
extern crate mbedtls;

extern crate sgx_isa;


use sgx_isa::{Report, Targetinfo};

use mbedtls::cipher::{Cipher, raw::{CipherId, CipherMode}};


#[test]
fn verify_mac() {
    let targetinfo = Targetinfo::from(Report::for_self());
    let report = Report::for_target(&targetinfo, &[0; 64]);

    assert!(report.verify(|key, data, mac| {
        let mut mac_out = [0u8; 16];
        Cipher::new(CipherId::Aes, CipherMode::ECB, 128).unwrap()
            .cmac(&key[..], data, &mut mac_out).unwrap();
        &mac_out == mac
    }));
}
