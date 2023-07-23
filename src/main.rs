mod aes;
#[cfg(test)]
mod aes_tests;

use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::io::{stdin, stdout, Write};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 16];
    let key: &[u8] = "A 16-bytes key!!".as_bytes();

    stream.read(&mut buffer).unwrap();

    // println!("Request bytes: {:?}", buffer);
    let decrypted = aes::decrypt(&buffer, key);
    // println!("Request decrypted bytes: {:?}", decrypted);

    println!("Request: {}", String::from_utf8_lossy(&decrypted[..]));

    let mut s=String::new();
    print!("Please enter response: ");
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("Did not enter a correct string");
    // use std::str;
    let to_encrypt = s.strip_suffix("\r\n").expect("no \\r\\n at end of string").as_bytes();
    let encrypted = aes::encrypt(&to_encrypt, key);
    stream.write(&encrypted).expect("Couldn't write to socket buffer");
    // println!("Message after enc: {:?}", encrypted);
    // println!("Message after enc+dec: {}", str::from_utf8(&aes::decrypt(&encrypted, key)).unwrap());
}