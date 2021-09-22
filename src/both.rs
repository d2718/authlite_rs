use std::path::Path;
use std::time::Duration;

use crate::{KeyAuth, PwdAuth, FileError, DataError};

/** A combined authorization system that offers all the features of a
    `PwdAuth` and a `Keyauth` as well as some combined functionality unique
    to the combination.
    
    The undocumented methods here just directly call the underlying
    `PwdAuth` or `KeyAuth` method of the same name.
    
    The use case for this combined authorization system is one where a user
    initially logs in with a password and is then issued a temporary
    "session key" to be used for the rest of the session, so that the user's
    password need not be remembered or typed, transmitted, or checked
    over and over again.
*/
pub struct BothAuth {
    pwdauth: PwdAuth,
    keyauth: KeyAuth,
}

impl BothAuth {
    /**
    Create a new joint authorization system storing password and key
    information in the supplied pathnames.
    */
    pub fn new(
        pwd_file: &dyn AsRef<Path>,
        key_file: &dyn AsRef<Path>
    )-> Result<Self, FileError> {
        let new_pa = PwdAuth::new(pwd_file)?;
        let new_ka = KeyAuth::new(key_file)?;
        
        let ba = BothAuth {
            pwdauth: new_pa,
            keyauth: new_ka,
        };
        
        return Ok(ba);
    }
    
    /**
    Open a saved joint authorization system using the given password and
    key files.
    */
    pub fn open(
        pwd_file: &dyn AsRef<Path>,
        key_file: &dyn AsRef<Path>
    ) -> Result<Self, FileError> {
        let pa = PwdAuth::open(pwd_file)?;
        let ka = KeyAuth::open(key_file)?;
        
        let ba = BothAuth {
            pwdauth: pa,
            keyauth: ka,
        };
        
        return Ok(ba);
    }
    
    /* PwdAuth methods */
    
    pub fn add_user(&mut self, uname: &str, password: &str, salt: &[u8])
    -> Result<(), DataError> { self.pwdauth.add_user(uname, password, salt) }
    
    pub fn delete_user(&mut self, uname: &str)
    -> Result<(), DataError> { self.pwdauth.delete_user(uname) }
    
    pub fn change_password(&mut self, uname: &str, password: &str, salt: &[u8])
    -> Result<(), DataError> { self.pwdauth.change_password(uname, password, salt) }
    
    pub fn check_password(&self, uname: &str, password: &str, salt: &[u8])
    -> Result<(), DataError> { self.pwdauth.check_password(uname, password, salt) }
    
    pub fn user_exists(&self, uname: &str)
    -> Result<(), DataError> { self.pwdauth.user_exists(uname) }
    
    /* KeyAuth methods */
    
    pub fn length(&mut self, key_length: usize) { self.keyauth.length(key_length) }
    
    pub fn chars(&mut self, key_chars: &dyn AsRef<str>) { self.keyauth.chars(key_chars) }
    
    pub fn life(&mut self, key_life: Duration) { self.keyauth.life(key_life) }
    
    pub fn issue_key(&mut self, uname: &str)
    -> String { self.keyauth.issue_key(uname) }
    
    pub fn invalidate_key(&mut self, key: &str)
    -> Result<(), DataError> { self.keyauth.invalidate_key(key) }
    
    pub fn remove_key(&mut self, key: &str)
    -> Result<(), DataError> { self.keyauth.remove_key(key) }
    
    pub fn check_key(&self, key:&str, uname: &str)
    -> Result<(), DataError> { self.keyauth.check_key(key, uname) }
    
    pub fn refresh_key(&mut self, key: &str)
    -> Result<(), DataError> { self.keyauth.refresh_key(key) }
    
    pub fn check_and_refresh_key(&mut self, key: &str, uname: &str)
    -> Result<(), DataError> { self.keyauth.check_and_refresh_key(key, uname) }
    
    pub fn cull_keys(&mut self) { self.keyauth.cull_keys() }
    
    /* Unique methods */
    
    /**
    Issue a key only if the given username is in the password authorization
    database.
    */
    pub fn issue_user_key(&mut self, uname: &str) -> Result<String, DataError> {
        self.pwdauth.user_exists(uname)?;
        Ok(self.keyauth.issue_key(uname))
    }
    
    /**
    Checks to see whether the username/password/salt combo is valid, and
    if so, issue a key associated with that user name.
    */
    pub fn check_password_and_issue_key(
        &mut self,
        uname: &str,
        password: &str,
        salt: &[u8]
    ) -> Result<String, DataError> {
        self.pwdauth.check_password(uname, password, salt)?;
        Ok(self.keyauth.issue_key(uname))
    }

    /** Return whether the password database is dirty. */
    pub fn pwd_dirty(&self) -> bool { self.pwdauth.is_dirty() }
    /** Return whether the key database is dirty. */
    pub fn key_dirty(&self) -> bool { self.keyauth.is_dirty() }
    
    /**
    Checks independently to see if each authorization database is dirty,
    and will write it to disk if so.
    */
    pub fn save_if_dirty(&mut self) -> Result<(), FileError> {
        let dirty = self.pwdauth.is_dirty();
        if dirty { self.pwdauth.save()?; }
        let dirty = self.keyauth.is_dirty();
        if dirty { self.keyauth.save()?; }
        
        Ok(())
    }
}