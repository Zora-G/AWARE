//! Immutable, replayable in-memory chunks for complete large-message transcripts.
use openssl::symm::{Cipher, Crypter, Mode};
use std::{
    io::{self, Read, Write},
    ops::{Index, IndexMut},
    sync::Arc,
};
pub const CHUNK_BYTES: usize = 1024 * 1024;
#[derive(Clone)]
pub struct Payload {
    chunks: Arc<Vec<Vec<u8>>>,
    len: usize,
}
impl From<Vec<u8>> for Payload {
    fn from(b: Vec<u8>) -> Self {
        Self {
            len: b.len(),
            chunks: Arc::new(vec![b]),
        }
    }
}
impl From<&[u8]> for Payload {
    fn from(b: &[u8]) -> Self {
        b.to_vec().into()
    }
}
impl Payload {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        for b in self.chunks.iter() {
            w.write_all(b)?
        }
        Ok(())
    }
    pub fn reader(&self) -> impl Read + '_ {
        ChunkReader {
            data: self,
            chunk: 0,
            offset: 0,
        }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.len);
        self.write_to(&mut b).unwrap();
        b
    }
}
struct ChunkReader<'a> {
    data: &'a Payload,
    chunk: usize,
    offset: usize,
}
impl Read for ChunkReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.chunk < self.data.chunks.len() {
            let b = &self.data.chunks[self.chunk];
            let n = out.len().min(b.len() - self.offset);
            if n > 0 {
                out[..n].copy_from_slice(&b[self.offset..self.offset + n]);
                self.offset += n;
                return Ok(n);
            }
            self.chunk += 1;
            self.offset = 0
        }
        Ok(0)
    }
}
impl Index<usize> for Payload {
    type Output = u8;
    fn index(&self, mut i: usize) -> &u8 {
        for b in self.chunks.iter() {
            if i < b.len() {
                return &b[i];
            }
            i -= b.len()
        }
        panic!("payload index")
    }
}
impl IndexMut<usize> for Payload {
    fn index_mut(&mut self, mut i: usize) -> &mut u8 {
        for b in Arc::make_mut(&mut self.chunks) {
            if i < b.len() {
                return &mut b[i];
            }
            i -= b.len()
        }
        panic!("payload index")
    }
}
pub fn encrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    input: &mut impl Read,
    len: usize,
) -> io::Result<Payload> {
    let mut cipher = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(iv))?;
    let mut chunks = vec![iv.to_vec()];
    let mut remaining = len;
    let mut buf = vec![0; CHUNK_BYTES];
    while remaining > 0 {
        let n = remaining.min(CHUNK_BYTES);
        input.read_exact(&mut buf[..n])?;
        let mut out = vec![0; n + 16];
        let used = cipher.update(&buf[..n], &mut out)?;
        out.truncate(used);
        chunks.push(out);
        remaining -= n
    }
    let mut tail = vec![0; 16];
    let used = cipher.finalize(&mut tail)?;
    tail.truncate(used);
    chunks.push(tail);
    let mut tag = vec![0; 16];
    cipher.get_tag(&mut tag)?;
    chunks.push(tag);
    Ok(Payload {
        chunks: Arc::new(chunks),
        len: len + 32,
    })
}
/// Success authenticates the full plaintext. A caller-owned sink commits only
/// after this function returns success, as in the retained Java streaming API.
pub fn decrypt(key: &[u8; 32], payload: &Payload, out: &mut dyn Write) -> io::Result<usize> {
    if payload.len() < 32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut input = payload.reader();
    let mut iv = [0; 16];
    input.read_exact(&mut iv)?;
    let mut cipher = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(&iv))?;
    let len = payload.len() - 32;
    let mut remaining = len;
    let mut buf = vec![0; CHUNK_BYTES];
    let mut plain = vec![0; CHUNK_BYTES + 16];
    while remaining > 0 {
        let n = remaining.min(CHUNK_BYTES);
        input.read_exact(&mut buf[..n])?;
        let used = cipher.update(&buf[..n], &mut plain)?;
        out.write_all(&plain[..used])?;
        remaining -= n
    }
    let mut tag = [0; 16];
    input.read_exact(&mut tag)?;
    cipher.set_tag(&tag)?;
    let used = cipher.finalize(&mut plain)?;
    out.write_all(&plain[..used])?;
    Ok(len)
}
