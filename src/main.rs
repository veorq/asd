use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use tar::Builder;
use walkdir::WalkDir;
use aes_gcm::{Aes256Gcm, aead::{Aead, NewAead, generic_array::GenericArray}};
use argon2::{self, Config};
use rpassword::read_password;
use rand::{rngs::OsRng, RngCore};

fn encrypt_file(file_path: &Path, password: &[u8]) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Derive a key from the password
    let salt = rand::random::<[u8; 16]>(); // Generate a random salt
    let config = Config::default();
    let key = argon2::hash_raw(password, &salt, &config).unwrap();
    let key = GenericArray::from_slice(&key);

    // Encrypt the file contents
    let cipher = Aes256Gcm::new(key);
    let nonce = rand::random::<[u8; 12]>(); // Generate a random nonce
    let nonce = GenericArray::from_slice(&nonce);
    let encrypted_data = cipher.encrypt(nonce, buffer.as_ref()).expect("encryption failure");

    // Save the encrypted data to a new file
    let mut encrypted_file = File::create(format!("{}.enc", file_path.display()))?;
    encrypted_file.write_all(&nonce)?;
    encrypted_file.write_all(&salt)?;
    encrypted_file.write_all(&encrypted_data)?;

    Ok(())
}

fn decrypt_file(file_path: &Path, password: &[u8]) -> io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut nonce = [0u8; 12];
    let mut salt = [0u8; 16];
    file.read_exact(&mut nonce)?;
    file.read_exact(&mut salt)?;

    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    let config = Config::default();
    let key = argon2::hash_raw(password, &salt, &config).unwrap();
    let key = GenericArray::from_slice(&key);

    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref()).expect("decryption failure");

    let mut decrypted_file = File::create(format!("{}.tar", file_path.display()))?;
    decrypted_file.write_all(&decrypted_data)?;

    Ok(())
}

fn secure_delete(file_path: &Path) -> io::Result<()> {
    if file_path.is_file() {
        let metadata = fs::metadata(file_path)?;
        let file_len = metadata.len();

        let mut file = OpenOptions::new().write(true).open(file_path)?;
        file.write_all(&vec![0; file_len as usize])?;
        file.sync_all()?; // Ensure the write is flushed to disk

        println!("rm {}", file_path.display());
        fs::remove_file(file_path)?;
    }

    Ok(())
}

fn create_uncompressed_archive(dir_path: &Path, archive_path: &Path) -> io::Result<()> {
    let file = File::create(archive_path)?;
    let mut archive = Builder::new(file);

    for entry in WalkDir::new(dir_path) {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            // Adjust the path to be relative to dir_path
            //let relative_path = path.strip_prefix(dir_path).unwrap();
            archive.append_path_with_name(path, path)?;
            println!("process file {}", path.display());

            // Securely delete the file
            secure_delete(path)?;
        } 
    }
    archive.finish()?;
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let cli_path = match args.get(1) {
        Some(path) => Path::new(path),
        None => Path::new("."),
    };

    // Check if the provided path is a valid directory
    if cli_path.is_dir() {
        println!("Enter password for encryption:");
        let password = read_password().expect("Failed to read password");
        println!("Confirm password:");
        let confirm_password = read_password().expect("Failed to read password");

        if password != confirm_password {
            println!("Passwords do not match.");
            return Ok(());
        }

        // rename to ".plu"
        let mut archive_path = PathBuf::from(dir_path);
        archive_path.set_extension("plum");

        create_uncompressed_archive(dir_path, archive_path)?;
        fs::remove_dir_all(dir_path)?;
        encrypt_file(archive_path, password)?;
        secure_delete(archive_path)?;
    }

    if cli_path.is_file() {
    let password = read_password().expect("Failed to read password");

            decrypt_file(file_path, password.as_bytes())?;
    }

    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Provided path is neither a valid directory nor a file."));


    Ok(())
}


