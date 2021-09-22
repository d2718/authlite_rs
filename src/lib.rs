/*!
a lightweight authorization library that stores data in .csv files

This is a rusty reimplementation of my
[authlite](https://github.com/d2718/authlite) Go module.

**authlite** is intended to be lightweight and easy to use, for small,
non-critical systems that don't require enterprise security. Please do
not use this for public-facing systems that interact with people's personal
or financial data.

Features:

  * Data is stored in two human-readable .csv files; no database configuration
    necessary (this is simple and convenient, but doesn't scale).
  * Uses the [`BLAKE3`](https://github.com/BLAKE3-team/BLAKE3/) cryptographic
    algorithm, because why not?
  * Supports salted passwords plus the ability to issue temporary,
    time-limited "keys" for session management.
*/
use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;

mod pwd;
mod key;
mod both;
pub use pwd::PwdAuth;
pub use key::KeyAuth;
pub use both::BothAuth;

/** Conditions encountered when loading or saving a database is unsuccessful. */
#[derive(Debug, PartialEq)]
pub enum FileError {
    Exists(String),
    DoesNotExist(String),
    Write(String),
    Read(String),
}

/** Non-`Ok()` conditions that can be encountered when checking
    passwords/keys or updating a database.
*/
#[derive(Debug, PartialEq)]
pub enum DataError {
    UserExists,
    NoSuchUser,
    BadPassword,
    KeyExpired,
    NoSuchKey,
    BadUsername,
}

/**
Truncates and opens the given file for writing, translating
`std::io::Error`s into `FileError`s.
*/
fn open_for_write(p: &Path) -> Result<File, FileError> {
    let f = match File::create(p) {
        Ok(f) => f,
        Err(e) => match e.kind() {
            ErrorKind::PermissionDenied => {
                let estr = format!("permission denied: {}", p.to_string_lossy());
                return Err(FileError::Read(estr));
            },
            e @ _ => {
                let estr = format!("{}: {:?}", p.to_string_lossy(), &e);
                return Err(FileError::Read(estr));
            },
        },
    };
    return Ok(f);
}

/**
Opens the given file for reading, translating
`std::io::Error`s into `FileError`s.
*/
fn open_for_read(p: &Path) -> Result<File, FileError> {
    let f = match File::open(p) {
        Ok(f) => f,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                return Err(FileError::DoesNotExist(p.to_string_lossy().to_string()));
            },
            ErrorKind::PermissionDenied => {
                let estr = format!("permission denied: {}", p.to_string_lossy());
                return Err(FileError::Read(estr));
            },
            e @ _ => {
                let estr = format!("{}: {:?}", p.to_string_lossy(), &e);
                return Err(FileError::Read(estr));
            },
        },
    };
    return Ok(f);
}

mod tests;