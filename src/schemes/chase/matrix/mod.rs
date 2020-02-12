//! This is the documentation for the `chase` scheme.
//!
//! * Developped by Melissa Chase, "Structured Encryption and Controlled Disclousure", see Section 3
//! * Published in Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security 2017
//! * Available from https://eprint.iacr.org/2017/807.pdf
//! * Type: encryption (structured)
//! * Setting: PRP, PRF
//! * Authors: Georg Bramm
//! * Date: 12/2019
//!
//! # Examples
//!
extern crate serde;
extern crate serde_json;

use rand::*;
use primitive_types::*;
//use serde::ser::{Serialize, Serializer, SerializeSeq, SerializeMap};
use serde::{Serialize, Deserialize};
use mongodb::oid::ObjectId;
use crypto::*;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use crate::utils::prp::*;
use crate::utils::prf::*;
use rulinalg::matrix::Matrix;
use rulinalg::matrix::BaseMatrix;
use rulinalg::matrix::BaseMatrixMut;
use rand::*;
use std::fs::File;
use rust_hope::schemes::she::hope::hope;


pub mod objects;
use objects::*;
use objects::comm::*;
use objects::ct::*;

/// An AC17 Public Key (PK)
#[derive(Serialize, Deserialize, Clone)]
pub struct SE {
    pub _key: Option<SEKey>,
    pub _hope: hope,
    pub _ct: Option<SECiphertext>,
}

impl SE {
    pub fn new(_name: String) -> SE {
        SE {
            _key: None,
            _hope: hope::new(_name, 4),
            _ct: None,
        }
    }
    pub fn keygen() -> Option<SEKey> {
        let mut rng = rand::thread_rng();
        return Some(SEKey {
            _k1: rng.gen::<U256>(),
            _k2: rng.gen::<U256>(),
            _k3: rng.gen::<U256>(),
        });
    }
    pub fn get_key(&self) -> Option<SEKey> {
        match &self._key {
            None => None,
            Some(_key) => {
                return Some(_key.clone());
            }
        }
    }
    pub fn get_sp(&self) -> hope {
        self._hope.clone()
    }
    pub fn set_key(&mut self, _key: SEKey)  {
        self._key = Some(_key.clone());
    }
    pub fn get_ct(&self) -> Option<SECiphertext> {
        match &self._ct {
            None => None,
            Some(_ct) => {
                return Some(_ct.clone());
            }
        }
    }
    pub fn encrypt(&self, _input: &osm::OSM) -> Option<SECiphertext> {
        let mut rng = rand::thread_rng();
        let _rows = _input.ways.len();
        let _len_ways = _rows * _rows;
        let _len_nodes = _input.nodes.len();
        let mut _ct_gamma: Matrix<U256> =
            Matrix::new(_rows, _rows, Vec::<U256>::with_capacity(_len_ways));
        let mut _ct_vertex: Vec<SECTVertex> = Vec::with_capacity(_len_nodes);
        let mut _ct_edge: Vec<SECTEdge> = Vec::with_capacity(_len_ways);
        match &self._key {
            None => return None,
            Some(key) => {
                let prf_k1 = PRF::new(key._k1);
                let prp_k2 = PRP::new(key._k2);
                let _k4: U256 = rng.gen::<U256>();
                let prp_k4 = PRP::new(_k4);
                for (_i, _way) in _input.ways.iter().enumerate() {}
                // permutated order
			    //let orig: Vec<usize> = (0.._len_all).collect();
			    //let _permutated_new_objs = prp_k4.g(&orig);
			    //let _permutated_new_gamma = prp_k2.p::<U256>(_new_gamma);
			    	/*
	        	for (_i, _row) in _input._gamma.row_iter().enumerate() {
	        		for (_j, _item) in _row.col_iter().enumerate() {
				        let _i_objs = _permutated_new_objs[(_i * _j) + _j];
		        		match _item {
		        			SEObject::EnumEdge(e) => {
				        		let (_id, _label) = _item;
				        		_ct_gamma_content[_i_permutated] = SE::encode(_id.clone(), &_label);	        				
				    			let _edge: SECTEdge = SECTEdge::new( , );
				    			_new_objs[_i_permutated] = SECTObject::EnumEdge(_edge);
		        			},
		        			SEObject::EnumVertex(v) => {
				        		let _vertex: SECTVertex = SECTVertex::new();
				    			_new_objs[_i_permutated] = SECTObject::EnumVertex(_vertex);	        			
		        			},
		        			_ => {}
		        		}
	        		}
	        	
	        		
	        		for (_j, _item) in _row.col_iter().enumerate() {
		    			let _permutated_index = _permutated_new_objs[(_i * _cols) + _j];
		    			let _permutated_matrix = _permutated_new_objs[(_i * _cols) + _j];   			

		    			return Some(SECiphertext {
						    _gamma: _new_gamma,
						    _objs: _new_objs
						});
			    		//let _content: U256 = U256::from(encode(_i, _v) ^ prf.f(_i, _j))
	        		}*/

                //}
                return Some(SECiphertext {
                    _gamma: _ct_gamma,
                    _edge: _ct_edge,
                    _vertex: _ct_vertex,
                });
            }
        }
        None
    }
    pub fn token_edge(&self, _alpha: usize, _beta: usize, _len: usize) -> Option<SETokenEdge> {
        match &self._key {
            None => return None,
            Some(key) => {
                let prf = PRF::new(key._k1);
                let prp = PRP::new(key._k2);
                let s = prf.f(_alpha, _beta).unwrap();
                let (_alpha_prime, _beta_prime) = prp.p_xy(_alpha, _beta, _len);
                return Some(SETokenEdge::new(s, _alpha_prime, _beta_prime));
            }
        }
        return None;
    }
    pub fn token(&self, _search: String) -> Option<SEToken> {
        match &self._key {
            None => return None,
            Some(key) => {
                let prf = PRF::new(key._k1 ^ key._k2);
                match prf.s(_search) {
                    None => None,
                    Some(_prf) => Some(SEToken::new(_prf)),
                };
            }
        }
        return None;
    }
    /*
    pub fn lookup(&self, _ciphertext: &SECiphertext, _token: Token) -> Option<SECTObject> {
        unsafe {
        	match _token {
        		Token::Edge(e) => {
        			let y: U256 = _ciphertext._gamma.get_unchecked([e._alpha, e._beta]).clone();
        			let (_id, _v) = &SE::decode(e._s ^ y);
		        	for _obj in _ciphertext._edge.iter() {
		        		if _obj._id.eq(e._id) {
		        			return Some(SECTObject::Edge(_obj.clone()));	
		    			}
		    		}
        		}
        		Token::All(a) => {
		        	for (_i, _obj) in _ciphertext._vertex.iter().enumerate() {
		        		let (_id, _v) = &SE::decode(a._s ^ U256::from(_i));
		        		if _obj._id.eq(a._id) {
		        			return Some(SECTObject::Vertex(_v.clone()));	
		    			}
		    		}
		        	for (_i, _row) in _ciphertext._gamma.row_iter().enumerate() {
		        		for (_j, _col) in _row.col_iter().enumerate() {
			        		let y: U256 = _ciphertext._gamma.get_unchecked([_i, _j]).clone();
		        			let (_id, _v) = &SE::decode(a._s ^ y);
			        		if _obj._id.eq(a._id) {
			        			return Some(SECTObject::Vertex(_obj.clone()));	
			    			}		        			
		        		}
		    		}		        	
        		}
        	}
        }
        return None;
    } 
    pub fn decrypt<R>(&self, _obj: SEObject) -> Option<R> {
        if _obj
    }
    */
    pub fn encode(_i: ObjectId, _v: H160) -> U256 {
        U256::from(SE::concat_u8(&_i.bytes(), _v.as_bytes()).as_slice())
    }
    pub fn decode(_node: U256) -> (ObjectId, H160) {
        let mut _id_b: [u8; 12] = [0u8; 12];
        let mut _v_b: [u8; 20] = [0u8; 20];
        for i in 0..12 {
            _id_b[i] = _node.byte(i);
        }
        for i in 0..20 {
            _v_b[i] = _node.byte(i + 12);
        }
        (ObjectId::with_bytes(_id_b), H160::from(_v_b))
    }
    pub fn concat_u8(one: &[u8], two: &[u8]) -> Vec<u8> {
        [one, two].concat()
    }
}

#[cfg(test)]
mod tests {
    use mongodb::oid::ObjectId;
    use std::mem;
    use std::mem::*;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
        println!(
            "size of ObjectId : {:?}",
            mem::size_of_val(&ObjectId::new().unwrap())
        );
    }
}
