use mongodb::oid::ObjectId;
use primitive_types::{H160, U256};
use rulinalg::matrix::Matrix;
use rust_hope::schemes::she::hope::hopeCiphertext;
use serde::{Serialize, Deserialize};

/// A SE Token for an Edge (SETokenEdge)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SETokenEdge {
    pub _s: U256,
    pub _alpha: usize,
    pub _beta: usize,
}

/// A SE Token for a Vertex (SETokenVertex)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SEToken {
    pub _s: H160,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum Token {
    Edge(SETokenEdge),
    All(SEToken),
}

impl SETokenEdge {
    pub fn new(_s: U256, _alpha: usize, _beta: usize) -> SETokenEdge {
        SETokenEdge {
            _s: _s,
            _alpha: _alpha,
            _beta: _beta,
        }
    }
}

impl SEToken {
    pub fn new(_s: H160) -> SEToken {
        SEToken { _s: _s }
    }
}
