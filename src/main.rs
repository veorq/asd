use std::env;
use std::fs::File;
use std::io::{self, Read, Write, Cursor};
use std::path::Path;
use tar::{Archive, Builder};
use walkdir::WalkDir;
use aes_gcm::{ aead::{Aead, AeadCore, KeyInit, generic_array::GenericArray}, Aes128Gcm};
use argon2::Argon2;
use rpassword::read_password;
use rand::{rngs::OsRng};
use zeroize::Zeroize;
use aead::consts::U16;

fn kdf(password: &[u8], salt: &[u8; 16]) -> GenericArray<u8, U16> {
    let mut okm = [0u8; 16];
    Argon2::default().hash_password_into(password, salt, &mut okm).unwrap();
    GenericArray::clone_from_slice(&okm)
}

fn seal(dir_path: &Path, password: &[u8]) -> io::Result<()> {

    let mut tardata = Vec::new();
    {
        let mut archive = Builder::new(&mut tardata);

        for entry in WalkDir::new(dir_path) {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                archive.append_path(path)?;
            } 
        }
        archive.finish()?;
    }

    let salt = rand::random::<[u8; 16]>(); 
    let mut key = kdf(password, &salt);
    let cipher = Aes128Gcm::new(&key);
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, tardata.as_ref()).expect("encryption failure");
    key.zeroize();

    let asd_path = dir_path.with_extension("asd");
    let mut encrypted_file = File::create(&asd_path)?;
    encrypted_file.write_all(&nonce)?;
    encrypted_file.write_all(&salt)?;
    encrypted_file.write_all(&ciphertext)?;

    Ok(())
}

fn unseal(file_path: &Path, password: &[u8]) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut nonce = [0u8; 12];
    let mut salt = [0u8; 16];
    file.read_exact(&mut nonce)?;
    file.read_exact(&mut salt)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let mut key = kdf(password, &salt);

    let cipher = Aes128Gcm::new(&key);
    let noncega = GenericArray::from_slice(&nonce);
    let plaintext = cipher.decrypt(noncega, ciphertext.as_ref()).expect("decryption failure");
    key.zeroize();

    let cursor = Cursor::new(plaintext);
    let mut archive = Archive::new(cursor);
    archive.unpack(".")?; 

    Ok(())
}


fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let arg = args.get(1).expect("provide a directory to seal or file to unseal").as_str();

    let cli_path = Path::new(arg);

    if cli_path.is_dir() {
        println!("password pls");
        let mut password = read_password().expect("read failure");
        println!("password again pls");
        let confirm_password = read_password().expect("read failure");

        if password != confirm_password {
            println!("passwords dont match");
            return Ok(());
        }

        seal(cli_path, password.as_bytes())?;
        password.zeroize();

    } else if cli_path.is_file() {
        println!("password pls");
        let mut password = read_password().expect("read failure");
        unseal(cli_path, password.as_bytes())?;
        password.zeroize();
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path is neither a valid directory nor a file"));
    }

    Ok(())
}
