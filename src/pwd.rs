
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use blake3::{Hash, Hasher};

use crate::{FileError, DataError, open_for_read, open_for_write};

const PWD_FILE_HEADERS: [&str; 2] = ["uname", "hash"];

/** Represents a password authorization database, which persists as
    a .csv file on disk.
    
    Operations that change the state of the database (basically everything
    except checking a password) are _not_ automatically written to disk;
    instead, the database will be internally flagged as "dirty" (that is,
    out of sync with the data on disk) until it is explicitly written.
*/
#[derive(Debug)]
pub struct PwdAuth {
    hashes: RwLock<HashMap<String, Hash>>,
    ufile:  PathBuf,
    udirty: RwLock<bool>,
}

impl PwdAuth {
    
    /**
    Create a new password authorization database that will save its data
    to a .csv file at the supplied path.
    */
    pub fn new(pwd_file: &dyn AsRef<Path>) -> Result<Self, FileError> {
        let pwd_file = pwd_file.as_ref();

        if Path::exists(pwd_file) {
            let estr = pwd_file.to_string_lossy().to_string();
            return Err(FileError::Exists(estr));
        }
        
        let f = open_for_write(pwd_file)?;
        let mut w = csv::Writer::from_writer(f);
        
        if let Err(e) = w.write_record(&PWD_FILE_HEADERS) {
            let estr = format!("{}: {}", pwd_file.to_string_lossy(), &e);
            return Err(FileError::Write(estr));
        }
        if let Err(e) = w.flush() {
            let estr = format!("{}: {}", pwd_file.to_string_lossy(), &e);
            return Err(FileError::Write(estr));
        }
        
        let pwd_a = PwdAuth {
            hashes: RwLock::new(HashMap::new()),
            ufile:  PathBuf::from(pwd_file),
            udirty: RwLock::new(false),
        };
        
        return Ok(pwd_a);
    }
    
    /**
    Open password authorization database with data from the .csv
    file in the given path.
        
    If the database is updated and saved, this is also where changes
    will be written to disk.
    */
    pub fn open(pwd_file: &dyn AsRef<Path>) -> Result<Self, FileError> {
        let pwd_file = pwd_file.as_ref();
        
        let f = open_for_read(pwd_file)?;
        let mut new_users: HashMap<String, Hash> = HashMap::new();
        let mut r = csv::Reader::from_reader(f);
        for (n, result) in r.records().enumerate() {
            match result {
                Err(e) => {
                    eprintln!("WARNING: reading {}, record {}: {}",
                        pwd_file.to_string_lossy(), n, &e);
                },
                Ok(record) => {
                    if record.len() != 2 {
                        eprintln!("WARNING: reading {}, record {}: record wrong length ({})",
                            pwd_file.to_string_lossy(), n, record.len());
                        continue;
                    }
                    let uname = String::from(record.get(0).unwrap());
                    let keystr = record.get(1).unwrap();
                    let key = match Hash::from_hex(keystr) {
                        Ok(x) => x,
                        Err(e) => {
                            eprintln!("WARNING: reading {}, record {}: can't parse \"{}\" as Hash: {}",
                                pwd_file.to_string_lossy(), n, keystr, &e);
                            continue;
                        },
                    };
                    
                    if let Some(_) = new_users.insert(uname.clone(), key) {
                        eprintln!("WARNING: reading {}: user \"{}\" has multiple entries.",
                            pwd_file.to_string_lossy(), &uname);
                    }
                },
            }
        }
        
        let pwd_a = PwdAuth {
            hashes: RwLock::new(new_users),
            ufile:  PathBuf::from(pwd_file),
            udirty: RwLock::new(false),
        };
        
        return Ok(pwd_a);
    }
    
    /**
    Add a user with the given name and password, with the password hash
    salted by the supplied salt data.
        
    Marks the database as "dirty".
        
    Returns `Err()` when a user with the given name already exists.
    */
    pub fn add_user(
        &mut self,
        uname: &str,
        password: &str,
        salt: &[u8]
    ) -> Result<(), DataError> {
        
        let hash = hash_with_salt(password, salt);
        
        let mut hashes = self.hashes.write().unwrap();
        if hashes.contains_key(uname) { return Err(DataError::UserExists); }
        let _ = hashes.insert(uname.to_string(), hash);
        
        let mut dirty = self.udirty.write().unwrap();
        *dirty = true;
        
        return Ok(());
    }
    
    /**
    Delete the user with the given name.
    
    Marks the database as "dirty".
        
    Returns `Err()` if the user doesn't exist.
    */
    pub fn delete_user(&mut self, uname: &str) -> Result<(), DataError> {
        let mut hashes = self.hashes.write().unwrap();
        match hashes.remove(uname) {
            None => Err(DataError::NoSuchUser),
            Some(_) => {
                let mut dirty = self.udirty.write().unwrap();
                *dirty = true;
                Ok(())
            },
        }
    }
    
    /**
    Changes the password of the given user.
    
    Marks the database as "dirty".
        
    Returns `Err()` if the user doesn't exist.
    */
    pub fn change_password(
        &mut self,
        uname: &str,
        password: &str,
        salt: &[u8]
    ) -> Result<(), DataError> {
        
        let hash = hash_with_salt(password, salt);
        
        let mut hashes = self.hashes.write().unwrap();
        if !hashes.contains_key(uname) { return Err(DataError::NoSuchUser); }
        let _ = hashes.insert(uname.to_string(), hash);
        
        return Ok(());
    }
    
    /**
    Checks whether the given password/salt combination is correct for
    the given user. This is the meat, here.
        
    Returns an error if the password is bad or the user doesn't exist.
    */
    pub fn check_password(
        &self,
        uname: &str,
        password: &str,
        salt: &[u8]
    ) -> Result<(), DataError> {
        
        let hash = hash_with_salt(password, salt);
        
        let hashes = self.hashes.read().unwrap();
        match hashes.get(uname) {
            None => Err(DataError::NoSuchUser),
            Some(h) => {
                if *h == hash {
                    Ok(())
                } else {
                    Err(DataError::BadPassword)
                }
            },
        }
    }
    
    /**
    Check whether the supplied user name is in the database.
    */
    pub fn user_exists(&self, uname: &str) -> Result<(), DataError> {
        let hashes = self.hashes.read().unwrap();
        match hashes.get(uname) {
            None => Err(DataError::NoSuchUser),
            Some(_) => Ok(()),
        }
    }
    
    /**
    Returns whether the in-memory database is "dirty", that is, whether it's
    out of sync with the persistent data on disk.
    
    If this function returns `true`, you must call `.save()` before the
    `PwdAuth` drops in order to ensure the data persists.
    */
    pub fn is_dirty(&self) -> bool {
        let dirty = self.udirty.read().unwrap();
        return *dirty;
    }
    
    /**
    Writes the current state of the database to disk, marking the database
    as no longer dirty.
    */
    pub fn save(&mut self) -> Result<(), FileError> {
        /* We secure the _write_ lock here to ensure multiple threads aren't
           writing to the file simultaneously. */
        let hashes = self.hashes.write().unwrap();
        let f = open_for_write(&(self.ufile))?;
        let mut w = csv::Writer::from_writer(f);
        if let Err(e) = w.write_record(&PWD_FILE_HEADERS) {
            let estr = format!("{}: {}", &(self.ufile).to_string_lossy(), &e);
            return Err(FileError::Write(estr));
        }
        for (uname, hash) in hashes.iter() {
            let hash_hex = hash.to_hex();
            let record: [&str; 2] = [uname, &hash_hex];
            if let Err(e) = w.write_record(&record) {
                let estr = format!("{}: {}", &(self.ufile).to_string_lossy(), &e);
                return Err(FileError::Write(estr));
            }
        }
        
        let mut dirty = self.udirty.write().unwrap();
        *dirty = false;
        
        return Ok(());
    }
}

/** Hashes the given password with the supplied salt data. */
fn hash_with_salt(pwd: &str, salt: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(pwd.as_bytes());
    hasher.update(salt);
    hasher.finalize()
}