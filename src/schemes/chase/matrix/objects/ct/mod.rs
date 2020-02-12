use mongodb::oid::ObjectId;
use primitive_types::U256;
use rulinalg::matrix::Matrix;
use rust_hope::schemes::she::hope::hopeCiphertext;
use serde::{Serialize, Deserialize};

/// A structured encryption key
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SEKey {
    pub _k1: U256,
    pub _k2: U256,
    pub _k3: U256,
}

/// A structured encryption ciphertext
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SECiphertext {
    pub _gamma: Matrix<U256>, // first 12 byte for (ObjectId xor PRP:F_k(x,y)) then 20 byte for Hash_k(w)
    pub _vertex: Vec<SECTVertex>,
    pub _edge: Vec<SECTEdge>,
}


#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum SECTObject {
    Edge(SECTEdge),
    Vertex(SECTVertex),
}

/// An AC17 Public Key (PK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SECTVertex {
    pub _id: ObjectId,
    pub _coord: SECTCoord,
    pub _meta: AESCiphertext,
}

/// An AC17 Public Key (PK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SECTEdge {
    pub _id: ObjectId,
    pub _length: hopeCiphertext,
    pub _oneway: i8,
    pub _meta: AESCiphertext,
}

/// An AC17 Public Key (PK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SECTCoord {
    pub _long: hopeCiphertext,
    pub _lat: hopeCiphertext,
}

/// An AC17 Public Key (PK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct AESCiphertext {
    //pub _length: hopeCiphertext,
    pub _iv: U256,
    pub _ct: Vec<u8>,
}


impl SECTEdge {
    pub fn new(_length: hopeCiphertext, _oneway: i8, _meta: AESCiphertext) -> SECTEdge {
        SECTEdge {
            _id: ObjectId::new().unwrap(),
            _length: _length,
            _oneway: _oneway,
            _meta: _meta,
        }
    }
}

impl SECTVertex {
    pub fn new(_long: hopeCiphertext, _lat: hopeCiphertext, _meta: AESCiphertext) -> SECTVertex {
        SECTVertex {
            _id: ObjectId::new().unwrap(),
            _coord: SECTCoord::new(_long, _lat),
            _meta: _meta,
        }
    }
}

impl SECTCoord {
    pub fn new(_long: hopeCiphertext, _lat: hopeCiphertext) -> SECTCoord {
        SECTCoord {
            _long: _long,
            _lat: _lat,
        }
    }
}
