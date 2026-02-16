use async_trait::async_trait;
use base64_simd::STANDARD;
use csv::ReaderBuilder;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }

    async fn decode<R: AsyncBufRead + Unpin + Send>(&self, reader: &mut R) -> Result<Hit> {
        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;
        serde_json::from_slice(&buf).map_err(|e| eyre::eyre!(e))
    }
}

pub struct CsvCodec;

#[async_trait]
impl Codec for CsvCodec {
    async fn encode<W: AsyncWrite + Unpin + Send>(&self, writer: &mut W, hit: &Hit) -> Result<()> {
        let timestamp = hit
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i128;
        let body_b64 = STANDARD.encode_to_string(&hit.body);

        let mut buf = Vec::new();
        {
            let mut wtr = csv::Writer::from_writer(&mut buf);
            wtr.write_record(&[
                timestamp.to_string(),
                hit.code.to_string(),
                hit.latency.as_nanos().to_string(),
                hit.bytes_out.to_string(),
                hit.bytes_in.to_string(),
                hit.error.clone(),
                body_b64,
                hit.attack.clone(),
                hit.seq.to_string(),
                hit.method.clone(),
                hit.url.clone(),
                String::new(), // response headers placeholder
            ])?;
            wtr.flush()?;
        }

        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn decode<R: AsyncBufRead + Unpin + Send>(&self, reader: &mut R) -> Result<Hit> {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await?;

        let mut rdr = ReaderBuilder::new()
            .has_headers(false)
            .from_reader(line.as_slice());

        let record = rdr
            .records()
            .next()
            .ok_or_else(|| eyre::eyre!("no CSV record found"))??;

        if record.len() < 11 {
            return Err(eyre::eyre!(
                "expected at least 11 CSV fields, got {}",
                record.len()
            ));
        }

        let nanos: u128 = record[0].parse()?;
        let timestamp = UNIX_EPOCH + Duration::from_nanos(nanos as u64);

        let code: u16 = record[1].parse()?;
        let latency = Duration::from_nanos(record[2].parse()?);
        let bytes_out: u64 = record[3].parse()?;
        let bytes_in: u64 = record[4].parse()?;
        let error = record[5].to_string();
        let body = STANDARD
            .decode_to_vec(&record[6])
            .map_err(|e| eyre::eyre!(e))?;
        let attack = record[7].to_string();
        let seq: u64 = record[8].parse()?;
        let method = record[9].to_string();
        let url = record[10].to_string();

        Ok(Hit {
            attack,
            seq,
            code,
            timestamp,
            latency,
            bytes_out,
            bytes_in,
            error,
            body,
            method,
            url,
        })
    }
}

pub mod duration_as_nanos {
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
        STANDARD.decode_to_vec(s).map_err(D::Error::custom)
    }
}
