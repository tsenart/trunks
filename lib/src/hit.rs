use async_trait::async_trait;
use base64_simd::STANDARD;
use csv::ReaderBuilder;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub headers: HashMap<String, Vec<String>>,
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
        let headers_b64 = headers_to_mime_base64(&hit.headers);

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
                headers_b64,
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
        let headers = if record.len() > 11 {
            mime_base64_to_headers(&record[11])
        } else {
            HashMap::new()
        };

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
            headers,
        })
    }
}

pub struct MsgpackCodec;

#[async_trait]
impl Codec for MsgpackCodec {
    async fn encode<W: AsyncWrite + Unpin + Send>(&self, writer: &mut W, hit: &Hit) -> Result<()> {
        let data = rmp_serde::to_vec(hit)?;
        let len = (data.len() as u32).to_be_bytes();
        writer.write_all(&len).await?;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn decode<R: AsyncBufRead + Unpin + Send>(&self, reader: &mut R) -> Result<Hit> {
        use tokio::io::AsyncReadExt;
        const MAX_MSGPACK_FRAME: usize = 64 * 1024 * 1024; // 64MB
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MSGPACK_FRAME {
            eyre::bail!(
                "msgpack frame too large: {} bytes (max {})",
                len,
                MAX_MSGPACK_FRAME
            );
        }
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await?;
        rmp_serde::from_slice(&data).map_err(|e| eyre::eyre!(e))
    }
}

pub mod duration_as_nanos {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn msgpack_round_trip() {
        let hit = Hit {
            attack: "test".to_string(),
            seq: 42,
            code: 200,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(123),
            bytes_out: 64,
            bytes_in: 512,
            error: String::new(),
            body: vec![1, 2, 3, 4],
            method: "POST".to_string(),
            url: "http://localhost:8080/api".to_string(),
            headers: HashMap::new(),
        };

        let mut buf = Vec::new();
        MsgpackCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = MsgpackCodec
            .decode(&mut reader)
            .await
            .expect("decode failed");

        assert_eq!(hit, decoded);
    }

    #[tokio::test]
    async fn msgpack_round_trip_with_error() {
        let hit = Hit {
            attack: "err-test".to_string(),
            seq: 1,
            code: 0,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(5000),
            bytes_out: 0,
            bytes_in: 0,
            error: "connection refused".to_string(),
            body: vec![],
            method: "GET".to_string(),
            url: "http://unreachable:9999/".to_string(),
            headers: HashMap::new(),
        };

        let mut buf = Vec::new();
        MsgpackCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = MsgpackCodec
            .decode(&mut reader)
            .await
            .expect("decode failed");

        assert_eq!(hit, decoded);
    }

    #[tokio::test]
    async fn json_round_trip() {
        let mut headers = HashMap::new();
        headers.insert("X-Request-Id".to_string(), vec!["abc-123".to_string()]);
        let hit = Hit {
            attack: "json-test".to_string(),
            seq: 7,
            code: 201,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(50),
            bytes_out: 128,
            bytes_in: 256,
            error: String::new(),
            body: vec![10, 20, 30],
            method: "PUT".to_string(),
            url: "http://localhost:8080/json".to_string(),
            headers,
        };

        let mut buf = Vec::new();
        JsonCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = JsonCodec.decode(&mut reader).await.expect("decode failed");

        assert_eq!(hit, decoded);
    }

    #[tokio::test]
    async fn csv_round_trip() {
        let hit = Hit {
            attack: "csv-test".to_string(),
            seq: 3,
            code: 200,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(75),
            bytes_out: 32,
            bytes_in: 1024,
            error: String::new(),
            body: vec![5, 6, 7],
            method: "GET".to_string(),
            url: "http://localhost:8080/csv".to_string(),
            headers: HashMap::new(),
        };

        let mut buf = Vec::new();
        CsvCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = CsvCodec.decode(&mut reader).await.expect("decode failed");

        assert_eq!(hit, decoded);
    }

    #[tokio::test]
    async fn csv_round_trip_with_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );
        let hit = Hit {
            attack: "csv-hdr".to_string(),
            seq: 1,
            code: 200,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(10),
            bytes_out: 0,
            bytes_in: 0,
            error: String::new(),
            body: vec![],
            method: "GET".to_string(),
            url: "http://localhost/".to_string(),
            headers: headers.clone(),
        };

        let mut buf = Vec::new();
        CsvCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = CsvCodec.decode(&mut reader).await.expect("decode failed");

        assert_eq!(decoded.headers, headers);
    }

    #[tokio::test]
    async fn codec_with_error_field() {
        let hit = Hit {
            attack: "err".to_string(),
            seq: 0,
            code: 0,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(100),
            bytes_out: 0,
            bytes_in: 0,
            error: "connection refused".to_string(),
            body: vec![],
            method: "GET".to_string(),
            url: "http://unreachable/".to_string(),
            headers: HashMap::new(),
        };

        let mut buf = Vec::new();
        JsonCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = JsonCodec.decode(&mut reader).await.expect("decode failed");

        assert_eq!(decoded.error, "connection refused");
    }

    #[tokio::test]
    async fn codec_with_empty_body() {
        let hit = Hit {
            attack: "empty-body".to_string(),
            seq: 0,
            code: 204,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(1),
            bytes_out: 0,
            bytes_in: 0,
            error: String::new(),
            body: vec![],
            method: "DELETE".to_string(),
            url: "http://localhost/resource".to_string(),
            headers: HashMap::new(),
        };

        let mut buf = Vec::new();
        CsvCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = CsvCodec.decode(&mut reader).await.expect("decode failed");

        assert!(decoded.body.is_empty());
    }

    #[tokio::test]
    async fn json_codec_with_special_chars() {
        let hit = Hit {
            attack: "special".to_string(),
            seq: 0,
            code: 0,
            timestamp: UNIX_EPOCH + Duration::from_secs(1700000000),
            latency: Duration::from_millis(500),
            bytes_out: 0,
            bytes_in: 0,
            error: "timeout: \"dial tcp\"".to_string(),
            body: vec![],
            method: "GET".to_string(),
            url: "http://localhost/".to_string(),
            headers: HashMap::new(),
        };

        let mut buf = Vec::new();
        JsonCodec
            .encode(&mut buf, &hit)
            .await
            .expect("encode failed");

        let mut reader = &buf[..];
        let decoded = JsonCodec.decode(&mut reader).await.expect("decode failed");

        assert_eq!(decoded.error, "timeout: \"dial tcp\"");
    }

    #[tokio::test]
    async fn msgpack_decode_rejects_oversized_length() {
        // A malicious/corrupted input with length prefix = 128MB should be rejected.
        let huge_len: u32 = 128 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.extend_from_slice(&huge_len.to_be_bytes());
        buf.extend_from_slice(&[0u8; 64]); // some garbage data
        let mut reader = &buf[..];
        let result = MsgpackCodec.decode(&mut reader).await;
        assert!(
            result.is_err(),
            "should reject msgpack frame with 128MB length prefix"
        );
    }

    #[test]
    fn duration_as_nanos_saturates_instead_of_wrapping() {
        // Duration > u64::MAX nanos (~584 years) should saturate to u64::MAX
        let huge = Duration::new(u64::MAX / 1_000_000_000 + 1, 0);
        assert!(
            huge.as_nanos() > u64::MAX as u128,
            "test precondition: duration must exceed u64 range"
        );
        let json = serde_json::to_string(&huge.as_nanos()).unwrap();
        // Serialize through our module
        #[derive(serde::Serialize)]
        struct Wrapper {
            #[serde(serialize_with = "duration_as_nanos::serialize")]
            d: Duration,
        }
        let w = Wrapper { d: huge };
        let serialized = serde_json::to_string(&w).unwrap();
        // Should contain u64::MAX, not a truncated/wrapped value
        assert!(
            serialized.contains(&u64::MAX.to_string()),
            "expected u64::MAX saturation, got: {}",
            serialized
        );
        let _ = json; // suppress unused
    }
}

fn headers_to_mime_base64(headers: &HashMap<String, Vec<String>>) -> String {
    if headers.is_empty() {
        return String::new();
    }
    let mut keys: Vec<&String> = headers.keys().collect();
    keys.sort();
    let mut mime = Vec::new();
    for key in keys {
        for value in &headers[key] {
            mime.extend_from_slice(key.as_bytes());
            mime.extend_from_slice(b": ");
            mime.extend_from_slice(value.as_bytes());
            mime.extend_from_slice(b"\r\n");
        }
    }
    mime.extend_from_slice(b"\r\n");
    STANDARD.encode_to_string(&mime)
}

fn mime_base64_to_headers(encoded: &str) -> HashMap<String, Vec<String>> {
    if encoded.is_empty() {
        return HashMap::new();
    }
    let bytes = match STANDARD.decode_to_vec(encoded) {
        Ok(b) => b,
        Err(_) => return HashMap::new(),
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(": ") {
            map.entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }
    }
    map
}

mod bytes_as_base64 {
    use base64_simd::STANDARD;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
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
