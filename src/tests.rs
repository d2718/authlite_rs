#![cfg(test)]
use std::collections::HashMap;
use std::path::Path;

use serial_test::serial;

use super::*;

static NEW_USERS_FILE: &str = "test/new_users.csv";
static NEW_KEYS_FILE:  &str = "test/new_keys.csv";

static UNAMES_AND_PWDS: &[[&str; 2]] = &[
    ["ted", "frogs"],
    ["eyes2", "google"],
    ["qwert", "asdfjkl;"],
];

fn ensure_delete(p: &dyn AsRef<Path>) {
    let p = p.as_ref();
    if Path::exists(p) {
        std::fs::remove_file(p).unwrap();
    }
}

#[test]
#[serial]
fn pwd_auth() {
    let salt = "xslt";
    ensure_delete(&NEW_USERS_FILE);
    
    let mut a = PwdAuth::new(&NEW_USERS_FILE).unwrap();
    for unp in UNAMES_AND_PWDS.iter() {
        a.add_user(unp[0], unp[1], salt.as_bytes()).unwrap();
    }
    
    let uname = UNAMES_AND_PWDS[0][0];
    assert_eq!(a.add_user(uname, "doesn't matter", "same".as_bytes()),
               Err(DataError::UserExists));
    
    assert_eq!(a.is_dirty(), true);
    a.save().unwrap();
    assert_eq!(a.is_dirty(), false);
    
    let mut a = PwdAuth::open(&NEW_USERS_FILE).unwrap();
    for unp in UNAMES_AND_PWDS.iter() {
        a.check_password(unp[0], unp[1], salt.as_bytes()).unwrap();
    }
    
    a.delete_user(uname).unwrap();
    assert_eq!(a.delete_user(uname), Err(DataError::NoSuchUser));

    assert_eq!(a.is_dirty(), true);
    a.save().unwrap();
    assert_eq!(a.is_dirty(), false);
    
    let a = PwdAuth::open(&NEW_USERS_FILE).unwrap();
    assert_eq!(a.is_dirty(), false);
    assert_eq!(a.check_password(uname, UNAMES_AND_PWDS[0][1], salt.as_bytes()),
               Err(DataError::NoSuchUser));
    
    let (uname, pass) = (UNAMES_AND_PWDS[1][0], UNAMES_AND_PWDS[1][1]);
    a.check_password(uname, pass, salt.as_bytes()).unwrap();
    assert_eq!(a.check_password(uname, "wrong password", salt.as_bytes()),
               Err(DataError::BadPassword));
    assert_eq!(a.check_password(uname, pass, "wrong salt".as_bytes()),
               Err(DataError::BadPassword));
    assert_eq!(a.is_dirty(), false);
}

#[test]
#[serial]
fn key_auth() {
    ensure_delete(&NEW_KEYS_FILE);
    
    let mut keyz: HashMap<String, String> = HashMap::new();
    
    let mut a = KeyAuth::new(&NEW_KEYS_FILE).unwrap();
    assert_eq!(a.is_dirty(), false);
    for unp in UNAMES_AND_PWDS.iter() {
        let u = unp[0];
        let k = a.issue_key(u);
        keyz.insert(u.to_string(), k);
    }
    
    let uname = UNAMES_AND_PWDS[0][0];
    let key   = keyz.get(uname).unwrap().clone();
    a.check_key(keyz.get(uname).unwrap(), uname).unwrap();
    a.invalidate_key(&key).unwrap();
    assert_eq!(a.check_key(&key, &uname), Err(DataError::KeyExpired));
    
    assert_eq!(a.is_dirty(), true);
    a.save().unwrap();
    assert_eq!(a.is_dirty(), false);
    
    let mut a = KeyAuth::open(&NEW_KEYS_FILE).unwrap();
    assert_eq!(a.check_key(&key, &uname), Err(DataError::NoSuchKey));
    
    let uname = UNAMES_AND_PWDS[1][0];
    let key   = keyz.get(uname).unwrap().clone();
    a.check_key(&key, &uname).unwrap();
    assert_eq!(a.is_dirty(), false);
    a.invalidate_key(&key).unwrap();
    assert_eq!(a.is_dirty(), true);
    assert_eq!(a.check_key(&key, &uname), Err(DataError::KeyExpired));

    a.cull_keys();
    assert_eq!(a.check_key(&key, &uname), Err(DataError::NoSuchKey));
    
    let uname = UNAMES_AND_PWDS[2][0];
    let key   = keyz.get(uname).unwrap().clone();
    a.remove_key(&key).unwrap();
    assert_eq!(a.is_dirty(), true);
    assert_eq!(a.check_key(&key, &uname), Err(DataError::NoSuchKey));
}

#[test]
#[serial]
fn both_auth() {
    let salt = "node";
    
    for p in [NEW_USERS_FILE, NEW_KEYS_FILE].iter() {
        ensure_delete(p);
    }
    
    let mut a = BothAuth::new(&NEW_USERS_FILE, &NEW_KEYS_FILE).unwrap();
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), false);
    for unp in UNAMES_AND_PWDS.iter() {
        a.add_user(unp[0], unp[1], salt.as_bytes()).unwrap();
    }
    assert_eq!(a.pwd_dirty(), true);
    assert_eq!(a.key_dirty(), false);
    
    a.save_if_dirty().unwrap();
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), false);
    
    for unp in UNAMES_AND_PWDS.iter() {
        a.delete_user(unp[0]).unwrap();
    }
    for unp in UNAMES_AND_PWDS.iter() {
        assert_eq!(a.check_password(unp[0], unp[1], salt.as_bytes()),
                   Err(DataError::NoSuchUser));
    }
    assert_eq!(a.pwd_dirty(), true);
    assert_eq!(a.key_dirty(), false);
    
    let mut a = BothAuth::open(&NEW_USERS_FILE, &NEW_KEYS_FILE).unwrap();
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), false);
    
    let mut keyz: HashMap<String, String> = HashMap::new();
    for unp in UNAMES_AND_PWDS.iter() {
        let k = a.check_password_and_issue_key(unp[0], unp[1], salt.as_bytes()).unwrap();
        keyz.insert(unp[0].to_string(), k);
    }
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), true);
    a.save_if_dirty().unwrap();
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), false);
    
    let (uname, _pass) = (UNAMES_AND_PWDS[0][0], UNAMES_AND_PWDS[0][1]);
    a.invalidate_key(keyz.get(uname).unwrap()).unwrap();
    assert_eq!(a.check_key(keyz.get(uname).unwrap(), uname),
               Err(DataError::KeyExpired));
    a.remove_key(keyz.get(uname).unwrap()).unwrap();
    assert_eq!(a.check_key(keyz.get(uname).unwrap(), uname),
               Err(DataError::NoSuchKey));
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), true);
    
    let mut a = BothAuth::open(&NEW_USERS_FILE, &NEW_KEYS_FILE).unwrap();
    assert_eq!(a.pwd_dirty(), false);
    assert_eq!(a.key_dirty(), false);
    for unp in UNAMES_AND_PWDS.iter() {
        a.check_key(keyz.get(unp[0]).unwrap(), unp[0]).unwrap();
    }
    
    assert_eq!(a.add_user(uname, "doesn't matter", salt.as_bytes()),
                Err(DataError::UserExists));
    assert_eq!(a.check_key("This will not be a key.", uname),
               Err(DataError::NoSuchKey)); 

}