use crypto::*;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::sha3::Sha3;
use crypto::sha3::Sha3Mode;
use primitive_types::{U128, U256, H160};
use crypto::*;
use std::str::FromStr;
use std::array::TryFromSliceError;
use std::convert::TryInto;

pub struct PRF {
    _key: Option<U256>,
}

impl PRF {
    pub fn new(_key: U256) -> PRF {
        PRF { _key: Some(_key) }
    }
    pub fn f(&self, _x: usize, _y: usize) -> Option<U256> {
        match self._key {
            None => None,
            Some(_key) => {
                let mut _key_bytes = [0u8; 32];
                let _x_bytes: Vec<u8> = _x.to_be_bytes().to_vec();
                let _y_bytes: Vec<u8> = _y.to_be_bytes().to_vec();
                _key.to_big_endian(&mut _key_bytes.to_vec());
                let mut hmac = Hmac::new(Sha256::new(), &_key_bytes);
                hmac.input(&_x_bytes);
                hmac.input(&_key_bytes);
                hmac.input(&_y_bytes);
                println!("HMAC digest: {:?}", hmac.result().code().to_vec());
                Some(U256::from(hmac.result().code()))
            }
        }

    }
    //fn pop20(arr: &[u8]) -> &[u8; 20] {
    //    arr.try_into().expect("slice with incorrect length")
    //}

    pub fn s(&self, _search: String) -> Option<H160> {
        match self._key {
            None => None,
            Some(_key) => {
                let mut _key_bytes = [0u8; 32];
                let mut _res_bytes = [0u8; 20];
                _key.to_big_endian(&mut _key_bytes.to_vec());
                let mut hmac = Hmac::new(Sha3::shake_128(), &_key_bytes);
                hmac.input(&_search.into_bytes());
                let result: Result<[u8; 20], TryFromSliceError> = hmac.result().code().try_into();
                match result.ok() {
                    None => None,
                    Some(code) => Some(H160::from(&code)),
                }
            }
        }

    }
}

#[cfg(test)]
mod tests {
    use primitive_types::U256;
    use std::str::FromStr;
    use super::*;

    #[test]
    fn prf_works() {
        let key = U256::from_dec_str("12345678909876543210").ok().unwrap();
        let _prf = PRF::new(key);
        let _ct = _prf.f(5000000, 10);
        println!("{:?}", _ct);
    }
}
