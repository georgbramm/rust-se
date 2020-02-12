/*use mongodb::oid::ObjectId;
use primitive_types::U256;
use rulinalg::matrix::Matrix;
use rabe::schemes::she::hOPE::hOPECiphertext;

/// A SE Plaintext (PT)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SEPlaintext {
    pub _gamma: Matrix<(usize, [u8; 20])>, // <(i, hash_160(word))>
    pub _vertex: Vec<SEVertex>,
    pub _edge: Vec<SEEdge>,
}

/// A SE Plaintext Edge (SEPTEdge)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SEPTEdge {
    pub _length: f64,
    pub _name: String,
}

/// A SE Plaintext Vertext (SEPTVertex)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SEPTVertex {
    pub _coord: SEPTCoord,
    pub _meta: Vec<u8>,
}

/// A SE Plaintext Coordinate (SEPTCoord))
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SEPTCoord {
    pub _lon: f64,
    pub _lat: f64,
}

impl SEPTEdge {
    pub fn new(_length: f64, _meta: &Vec<u8>) -> SEPTEdge {
        SEPTEdge {
            _id: ObjectId::new(),
            _length: _length,
            _meta: _meta,
        }
    }
    pub fn calculate(_start: (f64, f64), _end: (f64, f64), _meta: &Vec<u8>) -> SEPTEdge {
        SEPTEdge {
            _id: ObjectId::new(),
            _length: ((_end.2 - _start.2).powf(2) + (_end.1 - _start.1).powf(2)).sqrt(),
            _meta: _meta,
        }
    }
}

impl SEPTVertex {
    pub fn new(_coord: (f64, f64), _meta: &Vec<u8>) -> SEPTVertex {
        SEPTVertex {
            _id: ObjectId::new(),
            _coord: SEPTCoord::new(_coord.1, _coord.2),
            _meta: _meta,
        }
    }
}

impl SEPTCoord {
    pub fn new(_x: f64, _y: f64) -> SEPTCoord {
        SEPTCoord { _x: _x, _y: _y }
    }
}
*/
