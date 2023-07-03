// use csv::ReaderBuilder;
use async_trait::async_trait;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _};

// Hit contains the hits of a single Target hit.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub attack: String,
    pub seq: u64,
    pub code: u16,
    #[serde(with = "humantime_serde")]
    pub timestamp: SystemTime,
    #[serde(with = "duration_as_nanos")]
    pub latency: Duration,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub error: String,
    #[serde(with = "bytes_as_base64")]
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

#[async_trait]
pub trait Codec {
    async fn encode<W: AsyncWrite + Unpin + Send>(&self, writer: &mut W, hit: &Hit) -> Result<()>;
    async fn decode<R: AsyncBufRead + Unpin + Send>(&self, reader: &mut R) -> Result<Hit>;
}

pub struct JsonCodec;

#[async_trait]
impl Codec for JsonCodec {
    async fn encode<W: AsyncWrite + Unpin + Send>(&self, writer: &mut W, hit: &Hit) -> Result<()> {
        writer.write_all(&serde_json::to_vec(hit)?).await?;
        writer.write(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }

    async fn decode<R: AsyncBufRead + Unpin + Send>(&self, reader: &mut R) -> Result<Hit> {
        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;
        serde_json::from_slice(&buf).map_err(|e| eyre::eyre!(e))
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

mod duration_as_nanos {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nanos = duration.as_nanos() as u64;
        serializer.serialize_u64(nanos)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let nanos = u64::deserialize(deserializer)?;
        Ok(Duration::from_nanos(nanos))
    }
}

mod bytes_as_base64 {
    use base64_simd::STANDARD;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode_to_string(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode_to_vec(&s).map_err(D::Error::custom)
    }
}
