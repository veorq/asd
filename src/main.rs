use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};
use walkdir::{WalkDir, DirEntry};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, generic_array::GenericArray},
    Aes128Gcm, Key};
use argon2::Argon2;
use rpassword::read_password;
use rand::{rngs::OsRng};
use zeroize::Zeroize;

fn is_hidden(entry: &DirEntry) -> bool {
    entry.file_name()
         .to_str()
         .map(|s| s.starts_with('.'))
         .unwrap_or(false)
}

fn encrypt_file(file_path: &Path, password: &[u8]) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let salt = rand::random::<[u8; 16]>(); 
    let mut okm = [0u8; 16];
    // yolo
    let _ = Argon2::default().hash_password_into(password, &salt, &mut okm); 
    let key = Key::<Aes128Gcm>::from_slice(&okm);

    let cipher = Aes128Gcm::new(key);
    let noncega = Aes128Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&noncega, buffer.as_ref()).expect("encryption failed");
    okm.zeroize();

    let mut encrypted_file = File::create(format!("{}", file_path.display()))?;
    encrypted_file.write_all(&noncega)?;
    encrypted_file.write_all(&salt)?;
    encrypted_file.write_all(&ciphertext)?;

    Ok(())
}

fn decrypt_file(file_path: &Path, password: &[u8]) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut nonce = [0u8; 12];
    let mut salt = [0u8; 16];
    file.read_exact(&mut nonce)?;
    file.read_exact(&mut salt)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let mut okm = [0u8; 16];
    // yolo
    let _ = Argon2::default().hash_password_into(password, &salt, &mut okm);
    let key = Key::<Aes128Gcm>::from_slice(&okm);

    let cipher = Aes128Gcm::new(key);
    let noncega = GenericArray::from_slice(&nonce);
    let plaintext = cipher.decrypt(noncega, ciphertext.as_ref()).expect("decryption failed");
    okm.zeroize();

    let mut decrypted_file = File::create("asdtmp")?;
    decrypted_file.write_all(&plaintext)?;

    Ok(())
}

fn zeroize_delete(file_path: &Path) -> io::Result<()> {
    if file_path.is_file() {
        let metadata = fs::metadata(file_path)?;
        let file_len = metadata.len();
        let mut file = OpenOptions::new().write(true).open(file_path)?;
        file.write_all(&vec![0; file_len as usize])?;
        file.sync_all()?; 
        fs::remove_file(file_path)?;
    }

    Ok(())
}

fn create_archive(dir_path: &Path, archive_path: &Path) -> io::Result<()> {
    let file = File::create(archive_path)?;
    let mut archive = Builder::new(file);

    for entry in WalkDir::new(dir_path).into_iter().filter_entry(|e| !is_hidden(e)) {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            archive.append_path_with_name(path, path)?;
            zeroize_delete(path)?;
        } 
    }
    archive.finish()?;
    Ok(())
}

fn extract_archive(archive_path: &Path, output_dir: &Path) -> io::Result<()> {
    let file = File::open(archive_path)?;
    let mut archive = Archive::new(file);

    for file in archive.entries()? {
        let mut file = file?;
        let path = file.path()?;
        let full_path = output_dir.join(path);

        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        file.unpack(&full_path)?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let arg = args.get(1).expect("No path provided").as_str();

    let cli_path = Path::new(arg);

    if cli_path.is_dir() {
        println!("password pls");
        let mut password = read_password().expect("failed to read password");
        println!("password again pls");
        let confirm_password = read_password().expect("failed to read password");

        if password != confirm_password {
            println!("passwords dont match");
            return Ok(());
        }

        let mut archive_path = PathBuf::from(cli_path);
        archive_path.set_extension("asd");

        create_archive(cli_path, archive_path.as_path())?;
        fs::remove_dir_all(cli_path)?;
        encrypt_file(archive_path.as_path(), password.as_bytes())?;
        password.zeroize();

    } else if cli_path.is_file() {
        println!("password pls");
        let password = read_password().expect("failed to read password");
        decrypt_file(cli_path, password.as_bytes())?;
        let archive = Path::new("./asdtmp");
        let out_dir = Path::new("./");
        extract_archive(archive, out_dir)?;
        zeroize_delete(archive)?;
        zeroize_delete(cli_path)?;
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path is neither a valid directory nor a file"));
    }

    Ok(())
}

