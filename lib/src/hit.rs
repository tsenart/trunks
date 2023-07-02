// use csv::ReaderBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use std::{
    io::{Read, Write},
    time::{Duration, SystemTime},
};

use eyre::Result;

// Hit contains the hits of a single Target hit.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub attack: String,
    pub seq: u64,
    pub code: u16,
    pub timestamp: SystemTime,
    pub latency: Duration,
    // pub bytes_out: u64,
    // pub bytes_in: u64,
    // pub error: String,
    pub body: Vec<u8>,
    pub method: String,
    pub url: String,
    // pub headers: HashMap<String, Vec<String>>, // Using HashMap instead of http.Header
}

impl Hit {
    // End returns the time at which a Hit ended.
    pub fn end(&self) -> SystemTime {
        self.timestamp + self.latency
    }
}

pub trait Codec<R: Read, W: Write> {
    fn encode(&self, writer: &mut W, hit: &Hit) -> Result<()>;
    fn decode(&self, reader: &mut R) -> Result<Hit>;
}

pub struct JsonCodec;

impl<R: Read, W: Write> Codec<R, W> for JsonCodec {
    fn encode(&self, writer: &mut W, hit: &Hit) -> Result<()> {
        serde_json::to_writer(writer, hit).map_err(|e| eyre::eyre!(e))
    }

    fn decode(&self, reader: &mut R) -> Result<Hit> {
        let mut deserializer = Deserializer::from_reader(reader);
        Hit::deserialize(&mut deserializer).map_err(|e| eyre::eyre!(e))
    }
}

// pub struct CsvCodec;

// impl<R: Read, W: Write> Codec<R, W> for CsvCodec {
//     fn encode(&self, writer: &mut W, hit: &Hit) -> Result<()> {
//         let mut wtr = csv::Writer::from_writer(writer);
//         wtr.serialize(hit).map_err(|e| eyre::eyre!(e))
//     }

//     fn decode(&self, reader: &mut R) -> Result<Hit> {
//         let mut rdr = ReaderBuilder::new().from_reader(reader);
//         rdr.deserialize().next().unwrap_or_else(|| {
//             Err(eyre::eyre!("No record found"))
//         })
//     }
// }
