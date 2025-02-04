use std::fs::File;
use std::io::BufReader;

use hex;
use isahc::ReadResponseExt;
use widevine::{Cdm, Device, LicenseType, Pssh};

const WVD_PATH: &str = "src/device.wvd";

fn main() {
    // Load the Widevine device
    let device = Device::read_wvd(BufReader::new(File::open(&WVD_PATH).unwrap())).unwrap();
    let cdm = Cdm::new(device);

    // Create a license request
    let pssh = Pssh::from_b64("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==").unwrap();
    let request = cdm
        .open()
        .get_license_request(pssh, LicenseType::STREAMING)
        .unwrap();
    let challenge = request.challenge().unwrap();

    // Send the request to the proxy
    let mut resp = isahc::post("https://cwip-shaka-proxy.appspot.com/no_auth", challenge).unwrap();
    let resp_data = resp.bytes().unwrap();

    // Parse the response and extract the keys
    let keys = request.get_keys(&resp_data).unwrap();
    for key in keys.of_type(widevine::KeyType::CONTENT) {
        println!("--key {}:{}", hex::encode(&key.kid), hex::encode(&key.key));
    }
}
