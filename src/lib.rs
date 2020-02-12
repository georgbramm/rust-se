//! This is the documentation for the SE library.
//!
//! * Developped by Georg Bramm
//! * Type: encryption (structured)
//! * Setting: PRP, PRF
//! * Date: 12/2019
//!
#![allow(dead_code)]
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate crypto;
extern crate bincode;
extern crate rand;
extern crate rust_hope;
extern crate mongodb;
#[macro_use]
extern crate rulinalg;
#[macro_use]
extern crate primitive_types;
extern crate fpe;
extern crate num_traits;
extern crate osm_xml as osm;

pub mod utils;
pub mod schemes;
