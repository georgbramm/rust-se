use rulinalg::matrix::Matrix;
use rulinalg::matrix::PermutationMatrix;
use rulinalg::matrix::BaseMatrix;
use rulinalg::matrix::BaseMatrixMut;
use crypto::*;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use primitive_types::U256;
use std::convert::TryInto;
use mongodb::oid::ObjectId;
use std::str::FromStr;
use num_traits::identities::Zero;

pub struct PRP {
    _key: U256,
}

impl PRP {
    pub fn new(_key: U256) -> PRP {
        PRP { _key: _key }
    }
    pub fn p_x(&self, _x: usize, _len: usize) -> usize {
        let vec: Vec<usize> = (0..(_len + 1)).collect();
        let ref _rows: PermutationMatrix<usize> = PermutationMatrix::identity(_len);
        // create a SHA3-256 object
        let mut hasher = Sha3::sha3_256();
        // write input message
        hasher.input_str(&self._key.to_string());
        let _hash1: U256 = U256::from_str(&hasher.result_str()).ok().unwrap();
        let prp1 = PRP::new(_hash1);
        let prp1g = prp1.g(&vec);
        let ref _rows: PermutationMatrix<usize> = PermutationMatrix::from_array(prp1g).unwrap();
        _rows.map_row(_x)
    }
    pub fn p_xy(&self, _x: usize, _y: usize, _len: usize) -> (usize, usize) {
        let vec: Vec<usize> = (0.._len).collect();
        let ref _rows: PermutationMatrix<usize> = PermutationMatrix::identity(_len);
        let mut _cols: PermutationMatrix<usize> = PermutationMatrix::identity(_len);
        // create a SHA3-256 object
        let mut hasher = Sha3::sha3_256();
        // write input message
        hasher.input_str(&self._key.to_string());
        let _hash1: U256 = U256::from_str(&hasher.result_str()).ok().unwrap();
        hasher.reset();
        hasher.input_str(&self._key.to_string().chars().rev().collect::<String>());
        let _hash2: U256 = U256::from_str(&hasher.result_str()).ok().unwrap();
        // prps
        let prp1 = PRP::new(_hash1);
        let prp1g = prp1.g(&vec);
        let prp2 = PRP::new(_hash2);
        let prp2g = prp2.g(&vec);
        let ref _rows: PermutationMatrix<usize> = PermutationMatrix::from_array(prp1g).unwrap();
        let ref _cols: PermutationMatrix<usize> = PermutationMatrix::from_array(prp2g).unwrap();
        (_rows.map_row(_x), _cols.map_row(_y))
    }

    // we assume that _data is a quadratic matrix
    pub fn p<T>(&self, _data: &Matrix<T>) -> Matrix<T>
    where
        T: std::marker::Copy,
        T: std::fmt::Debug,
        T: num_traits::Num,
        T: num_traits::identities::Zero,
    {
        let mut _length = _data.rows();
        let vec: Vec<usize> = (0..(_length + 1)).collect();
        let ref _rows: PermutationMatrix<T> = PermutationMatrix::identity(_length);
        let mut _cols: PermutationMatrix<T> = PermutationMatrix::identity(_length);
        // create a SHA3-256 object
        let mut hasher = Sha3::sha3_256();
        // write input message
        hasher.input_str(&self._key.to_string());
        let _hash1: U256 = U256::from_str(&hasher.result_str()).ok().unwrap();
        hasher.reset();
        hasher.input_str(&self._key.to_string().chars().rev().collect::<String>());
        let _hash2: U256 = U256::from_str(&hasher.result_str()).ok().unwrap();
        // prps
        let prp1 = PRP::new(_hash1);
        let prp1g = prp1.g(&vec);
        let prp2 = PRP::new(_hash2);
        let prp2g = prp2.g(&vec);
        let ref _rows = PermutationMatrix::from_array(prp1g).unwrap();
        let ref _cols = PermutationMatrix::from_array(prp2g).unwrap();
        _rows * _data * _cols
    }

    pub fn g(&self, _data: &Vec<usize>) -> Vec<usize> {
        let mut _x = self._key.clone();
        let _n = _data.len();
        let mut _y: Vec<usize> = (1.._n).collect();
        for _i in 1usize.._n {
            let _t = (self._key % _i).as_usize();
            _x = _x / _i;
            _y[_i - 1] = _i - 1;
            _y[_i - 1] = _y[_t];
            _y[_t] = _i - 1;
        }
        _y
    }
}

#[cfg(test)]
mod tests {

    use primitive_types::U256;
    use rulinalg::matrix::Matrix;
    use std::str::FromStr;
    use super::*;

    #[test]
    fn prp_works() {
        let key = U256::from_dec_str("12345678909876543210").ok().unwrap();
        let vec: Vec<usize> = (0..20).collect();
        let prf = PRP::new(key);
        let permutated = prf.g(&vec);
        assert_eq!(
            vec![
                18,
                10,
                7,
                16,
                2,
                12,
                11,
                3,
                6,
                8,
                15,
                5,
                4,
                9,
                13,
                0,
                1,
                14,
                17,
            ],
            permutated
        );
    }

    #[test]
    fn prp_matrix_works() {
        let key = U256::from_dec_str("12345678909876543210").ok().unwrap();
        let ref m: Matrix<i32> =
            Matrix::<i32>::new(4, 4, (1..17).map(|x| x as i32).collect::<Vec<i32>>());
        let prp = PRP::new(key);
        let permutated: Matrix<i32> = prp.p::<i32>(m);
        let trapdoor_x = prp.p_x(3, 4);
        let trapdoor_y = prp.p_x(2, 4);
        let target: Vec<i32> = vec![2, 1, 4, 3, 10, 9, 12, 11, 14, 13, 16, 15, 6, 5, 8, 7];
        let target_m: Matrix<i32> = Matrix::<i32>::new(4, 4, target);
        //println!("{:?} -> {:?} -> {:?}", &permutated, &m, &m_orig);
        println!("{:?} -> {:?}", &permutated, &m);
        assert_eq!(permutated, target_m);
        assert_eq!(trapdoor_x, 4);
        assert_eq!(trapdoor_y, 3);
    }

    #[test]
    fn prp_xy_works() {
        let key = U256::from_dec_str("12345678909876543210").ok().unwrap();
        let ref m: Matrix<i32> =
            Matrix::<i32>::new(4, 4, (1..17).map(|x| x as i32).collect::<Vec<i32>>());
        let prp = PRP::new(key);
        let permutated: Matrix<i32> = prp.p::<i32>(m);
        let (_t1_x, _t1_y) = prp.p_xy(0, 3, 4);
        let (_t2_x, _t2_y) = prp.p_xy(1, 2, 4);
        let (_t3_x, _t3_y) = prp.p_xy(2, 1, 4);
        let (_t4_x, _t4_y) = prp.p_xy(3, 0, 4);
        println!("orig=(0,1) t=({:?}, {:?})", _t1_x, _t1_y);
        println!("orig=(0,0) t=({:?}, {:?})", _t2_x, _t2_y);
        println!("orig=(1,0) t=({:?}, {:?})", _t3_x, _t3_y);
        println!("orig=(2,2) t=({:?}, {:?})", _t4_x, _t4_y);
    }
}
