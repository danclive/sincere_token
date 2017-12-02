use std::error;
use std::fmt;
use std::string;

use serde_json;
use ring;
use data_encoding;

#[derive(Debug)]
pub enum JwtError {
    Decode,
    Verify
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Token decode error")
    }
}

impl error::Error for JwtError {
    fn description(&self) -> &str {
        "Token decode error"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
    Crypto(ring::error::Unspecified),
    Base64(data_encoding::DecodeError),
    FromUtf8Error(string::FromUtf8Error),
    JwtError(JwtError)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Json(ref err) => write!(f, "Json error: {}", err),
            Error::Crypto(ref err) => write!(f, "Crypto error: {}", err),
            Error::Base64(ref err) => write!(f, "Base64 error: {}", err),
            Error::FromUtf8Error(ref err) => write!(f, "FromUtf8 error: {}", err),
            Error::JwtError(ref err) => write!(f, "Jwt error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Json(ref err) => err.description(),
            Error::Crypto(ref err) => err.description(),
            Error::Base64(ref err) => err.description(),
            Error::FromUtf8Error(ref err) => err.description(),
            Error::JwtError(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Json(ref err) => Some(err),
            Error::Crypto(ref err) => Some(err),
            Error::Base64(ref err) => Some(err),
            Error::FromUtf8Error(ref err) => Some(err),
            Error::JwtError(ref err) => Some(err)
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(err: ring::error::Unspecified) -> Self {
        Error::Crypto(err)
    }
}

impl From<data_encoding::DecodeError> for Error {
    fn from(err: data_encoding::DecodeError) -> Self {
        Error::Base64(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Self {
        Error::FromUtf8Error(err)
    } 
}

impl From<JwtError> for Error {
    fn from(err: JwtError) -> Self {
        Error::JwtError(err)
    }
}
