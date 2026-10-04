use base64::{engine::general_purpose::STANDARD, Engine as _};

fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn public_blob(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, pubkey);
    blob
}

pub(super) fn authorized_line(pubkey: &[u8; 32]) -> String {
    format!("ssh-ed25519 {}", STANDARD.encode(public_blob(pubkey)))
}

pub(super) fn private_pem(private: &[u8; 64], pubkey: &[u8; 32], checkint: u32) -> String {
    let mut out = Vec::new();
    out.extend_from_slice(b"openssh-key-v1\0");
    ssh_string(&mut out, b"none");
    ssh_string(&mut out, b"none");
    ssh_string(&mut out, b"");
    out.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut out, &public_blob(pubkey));

    let mut sec = Vec::new();
    sec.extend_from_slice(&checkint.to_be_bytes());
    sec.extend_from_slice(&checkint.to_be_bytes());
    ssh_string(&mut sec, b"ssh-ed25519");
    ssh_string(&mut sec, pubkey);
    ssh_string(&mut sec, private);
    ssh_string(&mut sec, b"");
    let mut pad: u8 = 1;
    while sec.len() % 8 != 0 {
        sec.push(pad);
        pad += 1;
    }
    ssh_string(&mut out, &sec);

    let body = STANDARD.encode(out);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in body.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}
