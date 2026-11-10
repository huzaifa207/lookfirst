//! Git's "pkt-line" framing: a 4-digit hex length, then that many bytes less the 4.

use super::*;
use std::io::Read;

pub(super) enum Pkt<'a> {
    Flush,
    Delim,
    Data(&'a [u8]),
}

/// Git's "pkt-line" framing: a 4-digit hex length, then that many bytes less the 4.
pub(super) fn pkts(mut data: &[u8]) -> Result<Vec<Pkt<'_>>, String> {
    let bad = || "the server's answer wasn't what Git sends".to_string();
    let mut out = Vec::new();
    while !data.is_empty() {
        let head = std::str::from_utf8(data.get(..4).ok_or_else(bad)?).map_err(|_| bad())?;
        let len = usize::from_str_radix(head, 16).map_err(|_| bad())?;
        match len {
            0 => out.push(Pkt::Flush),
            1 => out.push(Pkt::Delim),
            2 => {}
            3 => return Err(bad()),
            n => out.push(Pkt::Data(data.get(4..n).ok_or_else(bad)?)),
        }
        data = &data[len.max(4)..];
    }
    Ok(out)
}

pub(super) fn pkt(out: &mut Vec<u8>, line: &str) {
    out.extend(format!("{:04x}{line}", line.len() + 4).bytes());
}

/// Reads packets up to the one that ends an answer (a flush), keeping the framing.
pub(super) fn read_answer(input: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let bad = || std::io::Error::other("the server's answer wasn't what Git sends");
    let mut out = Vec::new();
    loop {
        let mut head = [0u8; 4];
        input.read_exact(&mut head)?;
        let len = usize::from_str_radix(std::str::from_utf8(&head).map_err(|_| bad())?, 16).map_err(|_| bad())?;
        out.extend(head);
        match len {
            0 => return Ok(out),
            1 | 2 => {}
            3 => return Err(bad()),
            n => {
                let mut payload = vec![0; n - 4];
                input.read_exact(&mut payload)?;
                let error = payload.starts_with(b"ERR ");
                out.extend(payload);
                if error {
                    return Ok(out);
                }
            }
        }
        if out.len() as u64 > MAX_RESPONSE {
            return Err(std::io::Error::other("the answer is too big"));
        }
    }
}
