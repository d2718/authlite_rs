
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use rand::{Rng, distributions};
use serde::{Serialize, Deserialize};

use crate::{FileError, DataError, open_for_read, open_for_write};

const DEFAULT_KEY_LENGTH: usize = 32;
const DEFAULT_KEY_CHARS: &str = 
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/?:;[]{}|-_#^";
const DEFAULT_KEY_LIFE_SECS: u64 = 20 * 60; 
const ONE_YEAR: Duration = Duration::from_secs(3600 * 24 * 364);

#[derive(Debug, Serialize, Deserialize)]
struct KeyRW {
    key: String,
    #[serde(with ="humantime_serde")]
    expiry: SystemTime,
    uname: String,
}

#[derive(Debug)]
struct KeyMeta {
    uname: String,
    expiry: SystemTime,
}

impl KeyMeta {
    fn from_rw(krw: KeyRW) -> (String, Self) {
        let (k, u, exp) = (krw.key, krw.uname, krw.expiry);
        return (k, KeyMeta { uname: u, expiry: exp });
    }
    
    fn to_rw(&self, key_string: &str) -> KeyRW {
        return KeyRW {
            uname: self.uname.clone(),
            key: key_string.to_string(),
            expiry: self.expiry,            // SystemTime is Copy
        };
    }
}

/** Represents a "session key" authorization database, which can persist
    as a .csv file on disk.
    
    Keys are just strings of random characters; there's no hashing or salts
    involved, but they _do_ have to be matched with the right user name,
    and they will time out and become invalid after a given amount of time.
    
    Operations that change the state of the database (such as issuing,
    refreshing, or culling expired keys) are _not_ automatically written to
    disk; instead, the database will be internally flagged as "dirty"
    (that is, out of sync with the data on disk) until it is explicitly
    written.
*/
#[derive(Debug)]
pub struct KeyAuth {
    keys:   RwLock<HashMap<String, KeyMeta>>,
    kfile:  PathBuf,
    kdirty: RwLock<bool>,
    klen:   usize,
    kchars: Vec<char>,
    klife:  Duration,
}

impl KeyAuth {
    /**
    Create a new key authorization database that will save its data to
    a .csv file at the supplied path.
    */
    pub fn new(key_file: &dyn AsRef<Path>) -> Result<Self, FileError> {
        let key_file = key_file.as_ref();
        
        if Path::exists(key_file) {
            let estr = key_file.to_string_lossy().to_string();
            return Err(FileError::Exists(estr));
        }
        
        let kv: Vec<KeyMeta> = Vec::new();
        let f = open_for_write(key_file)?;
        let mut w = csv::Writer::from_writer(f);
        
        for k in kv.iter() {
            /* kv should be empty; this should happen zero times */
            let krw = k.to_rw("");
            w.serialize(krw).unwrap();
        }
        if let Err(e) = w.flush() {
            let estr = format!("{}: {}", key_file.to_string_lossy(), &e);
            return Err(FileError::Write(estr));
        }
        
        let a = KeyAuth {
            keys:   RwLock::new(HashMap::new()),
            kfile:  PathBuf::from(key_file),
            kdirty: RwLock::new(false),
            klen:   DEFAULT_KEY_LENGTH,
            kchars: DEFAULT_KEY_CHARS.chars().collect(),
            klife:  Duration::from_secs(DEFAULT_KEY_LIFE_SECS),
        };
        
        return Ok(a);
    }
    
    /**
    Open a key authorization database with data from the .csv file in the
    given path.
    
    If the database is updated and saved, this is also where the changes
    will be written to disk.
    
    Saved keys that have expired at the time of reading will not be added
    to the in-memory database.
    */
    pub fn open(key_file: &dyn AsRef<Path>) -> Result<Self, FileError> {
        let key_file = key_file.as_ref();
        
        let now = SystemTime::now();
        let f = open_for_read(key_file)?;
        let mut new_keys: HashMap<String, KeyMeta> = HashMap::new();
        let mut r = csv::Reader::from_reader(f);
        for (n, result) in r.deserialize().enumerate() {
            match result {
                Err(e) => {
                    eprintln!("WARNING: reading {}, record {}: {}",
                        key_file.to_string_lossy(), n, &e);
                },
                Ok(krw) => {
                    let (key, kmeta) = KeyMeta::from_rw(krw);
                    if now < kmeta.expiry {
                        if let Some(_) = new_keys.insert(key.clone(), kmeta) {
                            eprintln!("WARNING: duplicate key entry for \"{}\"", key);
                        }
                    }
                },
            }
        }
        
        let a = KeyAuth {
            keys:   RwLock::new(new_keys),
            kfile:  PathBuf::from(key_file),
            kdirty: RwLock::new(false),
            klen:   DEFAULT_KEY_LENGTH,
            kchars: DEFAULT_KEY_CHARS.chars().collect(),
            klife:  Duration::from_secs(DEFAULT_KEY_LIFE_SECS),
        };
        
        return Ok(a);
    }
    
    /** Change the length of the generated key from the default 32. */
    pub fn length(&mut self, key_length: usize) { self.klen = key_length; }
    
    /**
    Change the characters used to generate keys. The default is
    
    `"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/?:;[]{}|-_#^"`
    
    Will panic if the new key's expiration time is unrepresentable by the
    system.
    */
    pub fn chars(&mut self, key_chars: &dyn AsRef<str>) {
        self.kchars = key_chars.as_ref().chars().collect();
    }
    
    /** Change the life of issued keys from the default of 20 minutes. */
    pub fn life(&mut self, key_life: Duration) { self.klife = key_life; }
    
    /**
    Generate a new key and store it in the database, associating it with
    the supplied user name and setting it to expire at the appropriate
    time in the future.
    
    Will panic if `self.chars()` has been set to an empty set of characters,
    or the expiration time is far enough in the future that it can't be
    represented by the underlying system.
    */
    pub fn issue_key(&mut self, uname: &str) -> String {
        let dist = distributions::Slice::new(&self.kchars).unwrap();
        let rng = rand::thread_rng();
        let new_key: String = rng.sample_iter(&dist).take(self.klen).collect();
        
        let new_kmeta = KeyMeta {
            uname:  uname.to_string(),
            expiry: SystemTime::now().add(self.klife),
        };
        
        let mut keys = self.keys.write().unwrap();
        let _ = keys.insert(new_key.clone(), new_kmeta);
        
        let mut dirty = self.kdirty.write().unwrap();
        *dirty = true;
        
        return new_key;
    }
    
    /**
    Sets the expiry time of the given key in the past, so it is no longer
    valid.
    */
    pub fn invalidate_key(&mut self, key: &str) -> Result<(), DataError> {
        let now = SystemTime::now();
        let mut keys = self.keys.write().unwrap();
        match keys.get_mut(key) {
            None => Err(DataError::NoSuchKey),
            Some(kmeta) => {
                if kmeta.expiry < now {
                    Err(DataError::KeyExpired)
                } else {
                    kmeta.expiry = now.sub(ONE_YEAR);
                    let mut dirty = self.kdirty.write().unwrap();
                    *dirty = true;
                    Ok(())
                }
            },
        }
    }
    
    /**
    Remove the given key from the database and mark it dirty, if present.
    
    Returns an error if the supplied key isn't present.
    */
    pub fn remove_key(&mut self, key: &str) -> Result<(), DataError> {
        let mut keys = self.keys.write().unwrap();
        match keys.remove(key) {
            Some(_) => {
                let mut dirty = self.kdirty.write().unwrap();
                *dirty = true;
                Ok(())
            },
            None => Err(DataError::NoSuchKey),
        }
    }
    
    /**
    Returns `Ok(())` if the given key is still valid and was issued to the
    supplied user.
    
    Otherwise returns one of `DataError::{NoSuchKey, BadUsername, KeyExpired}`.
    */
    pub fn check_key(&self, key: &str, uname: &str) -> Result<(), DataError> {
        let keys = self.keys.read().unwrap();
        match keys.get(key) {
            None => Err(DataError::NoSuchKey),
            Some(kmeta) => {
                if kmeta.uname != uname {
                    Err(DataError::BadUsername)
                } else if kmeta.expiry < SystemTime::now() {
                    Err(DataError::KeyExpired)
                } else {
                    Ok(())
                }
            }
        }
    }
    
    /**
    Sets the life of the provided key as if it were newly issued.
    
    Returns an error if the key is not found.
    */
    pub fn refresh_key(&mut self, key: &str) -> Result<(), DataError> {
        let new_time = SystemTime::now().add(self.klife);
        let mut keys = self.keys.write().unwrap();
        match keys.get_mut(key) {
            None => Err(DataError::NoSuchKey),
            Some(kmeta) => {
                kmeta.expiry = new_time;
                Ok(())
            },
        }
    }
    
    /**
    If the supplied key is found and valid, resets its life as if it were
    newly issued, otherwise returns an error.
    */
    pub fn check_and_refresh_key(
        &mut self,
        key: &str,
        uname: &str
    ) -> Result<(), DataError> {
        let now = SystemTime::now();
        let new_time = now.add(self.klife);
        
        let mut keys = self.keys.write().unwrap();
        match keys.get_mut(key) {
            None => Err(DataError::NoSuchKey),
            Some(kmeta) => {
                if kmeta.uname != uname {
                    Err(DataError::BadUsername)
                } else if kmeta.expiry < now {
                    Err(DataError::KeyExpired)
                } else {
                    kmeta.expiry = new_time;
                    Ok(())
                }
            },
        }
    }
    
    /**
    Removes expired keys from the database if there are any.
    
    Marks the database as dirty if any keys are removed.
    */
    pub fn cull_keys(&mut self) {
        let mut to_remove: Vec<String> = Vec::new();
        {
            let now = SystemTime::now();
            let keys = self.keys.read().unwrap();
            for (key, kmeta) in keys.iter() {
                if kmeta.expiry < now {
                    to_remove.push(String::from(key));
                }
            }
        }
        
        if to_remove.len() > 0 {
            let mut keys = self.keys.write().unwrap();
            for key in to_remove.iter() {
                let _ = keys.remove(key);
            }
            let mut dirty = self.kdirty.write().unwrap();
            *dirty = true;
        }
    }

    /**
    Returns whether the in-memory database is "dirty", that is, whether it's
    out of sync with the persistent data on disk.
    
    If this function returns `true`, you must call `.save()` before the
    `PwdAuth` drops in order to ensure the data persists.
    */
    pub fn is_dirty(&self) -> bool {
        let dirty = self.kdirty.read().unwrap();
        return *dirty;
    }

    /**
    Writes data about all unexpired keys in the database to disk.
    
    The state of the database written will be like that of the current
    database after having called `.cull_keys()`, except it isn't marked
    as dirty.
    */
    pub fn save(&mut self) -> Result<(), FileError> {
        let now = SystemTime::now();
        
        let keys = self.keys.write().unwrap();
        let f = open_for_write(&self.kfile)?;
        let mut w = csv::Writer::from_writer(f);
        for (key, kmeta) in keys.iter() {
            if kmeta.expiry > now {
                let krw = kmeta.to_rw(key);
                if let Err(e) = w.serialize(krw) {
                    let estr = format!("{}: {}", self.kfile.to_string_lossy(), &e);
                    return Err(FileError::Write(estr));
                }
            }
        }
        
        if let Err(e) = w.flush() {
            let estr = format!("{}: {}", self.kfile.to_string_lossy(), &e);
            return Err(FileError::Write(estr));
        }
        
        let mut dirty = self.kdirty.write().unwrap();
        *dirty = false;
        
        return Ok(());
    }
}