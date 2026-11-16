use std::io::{self, Write};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Canonical,
    Long,
}
impl Frame {
    fn integer(self, n: u64) -> Vec<u8> {
        match self {
            Self::Canonical => (u32::try_from(n).expect("AWCE length"))
                .to_be_bytes()
                .to_vec(),
            Self::Long => n.to_be_bytes().to_vec(),
        }
    }
}
pub fn header(kind: &str, count: usize, frame: Frame) -> Vec<u8> {
    let mut out = match frame {
        Frame::Canonical => b"AWCE".to_vec(),
        Frame::Long => b"AWCL".to_vec(),
    };
    out.extend(1u32.to_be_bytes());
    out.extend(frame.integer(kind.len() as u64));
    out.extend(kind.as_bytes());
    out.extend(frame.integer(count as u64));
    out
}
pub fn encode(kind: &str, fields: &[&[u8]]) -> Vec<u8> {
    encode_frame(kind, fields, Frame::Canonical)
}
pub fn encode_frame(kind: &str, fields: &[&[u8]], frame: Frame) -> Vec<u8> {
    let mut out = header(kind, fields.len(), frame);
    for f in fields {
        out.extend(frame.integer(f.len() as u64));
        out.extend_from_slice(f)
    }
    out
}
pub fn decode<'a>(
    kind: &str,
    bytes: &'a [u8],
    count: usize,
) -> Result<Vec<&'a [u8]>, &'static str> {
    decode_frame(kind, bytes, count, Frame::Canonical)
}
pub fn decode_frame<'a>(
    kind: &str,
    bytes: &'a [u8],
    count: usize,
    frame: Frame,
) -> Result<Vec<&'a [u8]>, &'static str> {
    let h = header(kind, count, frame);
    if !bytes.starts_with(&h) {
        return Err("encoding type/version/count");
    }
    let width = match frame {
        Frame::Canonical => 4,
        Frame::Long => 8,
    };
    let mut pos = h.len();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let word = bytes.get(pos..pos + width).ok_or("field length")?;
        let len = match frame {
            Frame::Canonical => u32::from_be_bytes(word.try_into().unwrap()) as usize,
            Frame::Long => usize::try_from(u64::from_be_bytes(word.try_into().unwrap()))
                .map_err(|_| "field length range")?,
        };
        pos += width;
        let end = pos.checked_add(len).ok_or("field length range")?;
        out.push(bytes.get(pos..end).ok_or("field bytes")?);
        pos = end
    }
    if pos != bytes.len() {
        return Err("trailing bytes");
    }
    Ok(out)
}
#[derive(Clone)]
pub struct Transcript {
    state: blake3::Hasher,
    frame: Frame,
}
impl Transcript {
    pub fn new(kind: &str, count: usize, frame: Frame) -> Self {
        let mut state = blake3::Hasher::new();
        state.update(&header(kind, count, frame));
        Self { state, frame }
    }
    pub fn field(&mut self, b: &[u8]) {
        self.state.update(&self.frame.integer(b.len() as u64));
        self.state.update(b);
    }
    pub fn finish(self) -> [u8; 32] {
        *self.state.finalize().as_bytes()
    }
}
pub fn digest(kind: &str, fields: &[&[u8]], frame: Frame) -> [u8; 32] {
    let mut t = Transcript::new(kind, fields.len(), frame);
    for f in fields {
        t.field(f)
    }
    t.finish()
}

struct DigestSink<'a>(&'a mut blake3::Hasher);
impl Write for DigestSink<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Transcript {
    pub fn field_with(
        &mut self,
        len: usize,
        write: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()> {
        self.state.update(&self.frame.integer(len as u64));
        write(&mut DigestSink(&mut self.state))
    }
}
pub fn field_header(out: &mut dyn Write, frame: Frame, len: usize) -> io::Result<()> {
    out.write_all(&frame.integer(len as u64))
}
pub fn encoded_len(kind: &str, lengths: &[usize], frame: Frame) -> usize {
    header(kind, lengths.len(), frame).len()
        + lengths
            .iter()
            .map(|n| {
                n + match frame {
                    Frame::Canonical => 4,
                    Frame::Long => 8,
                }
            })
            .sum::<usize>()
}
