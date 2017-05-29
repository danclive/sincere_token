extern crate ring;
extern crate base64;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use std::result;

use serde::Serialize;
use serde::de::DeserializeOwned;

use ring::digest;
use ring::hmac;

mod error;

type Result<T> = result::Result<T, error::Error>;

pub enum Algorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512
}

#[derive(Serialize, Deserialize, Debug)]
struct Header {
    alg: String,
    typ: String
}

impl Header {
    fn new(alg: Algorithm) -> Header {
        
        let algorithm = match alg {
            Algorithm::SHA1 => "HS1".to_string(),
            Algorithm::SHA256 => "HS256".to_string(),
            Algorithm::SHA384 => "HS384".to_string(),
            Algorithm::SHA512 => "HS512".to_string()
        };

        Header{
            alg: algorithm,
            typ: "JWT".to_string(),
        }
    }

    fn algorithm(&self) -> &'static digest::Algorithm {

        match &*self.alg {
            "HS1" => &digest::SHA1,
            "HS256" => &digest::SHA256,
            "HS384" => &digest::SHA384,
            "HS512" => &digest::SHA512,
            _ => &digest::SHA256
        }
    }

    fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn from_str(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    fn encode_base64(&self) -> Result<String> {
        Ok(base64::encode_config(&self.to_string()?, base64::URL_SAFE_NO_PAD))
    }

    fn decode_base64(base: &str) -> Result<Self> {
        let _json = base64::decode_config(base, base64::URL_SAFE_NO_PAD)?;
        Header::from_str(&String::from_utf8(_json)?)
    }
}

pub trait Message: Serialize + DeserializeOwned {
    fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn from_str(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    fn encode_base64(&self) -> Result<String> {
        Ok(base64::encode_config(&self.to_string()?, base64::URL_SAFE_NO_PAD))
    }

    fn decode_base64(base: &str) -> Result<Self> {
        let _json = base64::decode_config(base, base64::URL_SAFE_NO_PAD)?;
        Message::from_str(&String::from_utf8(_json)?)
    }
}

pub fn encode<M>(key: &str, message: M, alg: Algorithm) -> Result<String> where M: Message {
    let message_base64 = message.encode_base64()?;

    let header = Header::new(alg);

    let unsigned_token = header.encode_base64()? + "." + &message_base64;

    let signature = hmac::sign(
        &hmac::SigningKey::new(header.algorithm(), key.as_bytes()),
        unsigned_token.as_bytes()
    );

    let signature_base64 = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

    Ok(unsigned_token + "." + &signature_base64)
}

pub fn decode<M>(key: &str, token: String) -> Result<M> where M: Message {
    let token_split: Vec<&str> = token.split('.').collect();

    if token_split.len() != 3 {
        return Err(error::JwtError::Decode.into())
    }

    let header_base64 = token_split[0];
    let message_base64 = token_split[1];

    hmac::verify(
        &hmac::VerificationKey::new(
            Header::decode_base64(&header_base64)?.algorithm(),
            key.as_bytes()
        ), 
        (header_base64.to_string() + "." + &message_base64).as_bytes(),
        &base64::decode_config(token_split[2], base64::URL_SAFE_NO_PAD)?
    ).or(Err(error::JwtError::Verify))?;

    Message::decode_base64(message_base64)
}

/*
impl Message for Messages {}

#[derive(Serialize, Deserialize, Debug)]
struct Messages {
    user_id: i64,
    date: i64,
}

fn main() {
    let key = "123ABC";

    let message = Messages {
        user_id: 10000,
        date: 123456789,
    };

    let token = encode(key, message, Algorithm::SHA256).unwrap();

    println!("{:?}", token);

    let result = decode::<Messages>(key, token);

    println!("{:?}", result);
}
*/