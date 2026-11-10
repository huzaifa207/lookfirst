//! Git's pack and object formats, read defensively: every byte comes from a stranger.
use super::*;
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use std::io::Read;

/// A single object bigger than this isn't a hook or a settings file, so it's never inflated.
pub(super) const MAX_OBJECT: u64 = 32 * 1024 * 1024;

pub(super) const COMMIT: u8 = 1;

pub(super) const TREE: u8 = 2;

pub(super) const BLOB: u8 = 3;

pub(super) const TAG: u8 = 4;

/// An object's id: the SHA-1 of its type, size and contents.
pub(super) fn object_id(kind: u8, body: &[u8]) -> Oid {
    let name = match kind {
        COMMIT => "commit",
        TREE => "tree",
        BLOB => "blob",
        _ => "tag",
    };
    let mut hash = Sha1::new();
    hash.update(format!("{name} {}\0", body.len()));
    hash.update(body);
    hash.finalize().into()
}

/// Where each object starts in a pack, found by reading the pack through. Bytes are skipped, not kept.
pub(super) fn pack_offsets(data: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let Some(count) =
        data.get(8..12).filter(|_| data.starts_with(b"PACK")).map(|b| u32::from_be_bytes(b.try_into().unwrap()))
    else {
        return out;
    };
    let mut i = 12usize;
    for _ in 0..count {
        let start = i;
        let Some(&first) = data.get(i) else { break };
        i += 1;
        let kind = (first >> 4) & 7;
        let mut size = u64::from(first & 15);
        let (mut byte, mut shift) = (first, 4u32);
        while byte & 0x80 != 0 {
            let Some(&next) = data.get(i) else { return out };
            i += 1;
            let Some(part) = u64::from(next & 0x7f).checked_shl(shift) else { return out };
            size |= part;
            shift += 7;
            byte = next;
        }
        match kind {
            1..=4 => {}
            6 => {
                while data.get(i).is_some_and(|b| b & 0x80 != 0) {
                    i += 1;
                }
                i += 1;
            }
            7 => i += 20,
            _ => return out,
        }
        let Some(rest) = data.get(i..) else { return out };
        let mut zlib = flate2::bufread::ZlibDecoder::new(rest);
        // One byte past the size makes the decoder reach the end of the stream, so it counts it all.
        if std::io::copy(&mut (&mut zlib).take(size.saturating_add(1)), &mut std::io::sink()).is_err() {
            return out;
        }
        i += zlib.total_in() as usize;
        out.push(start as u64);
    }
    out
}

pub(super) fn inflate(data: &[u8], size: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    ZlibDecoder::new(data).take(size.saturating_add(1)).read_to_end(&mut out).ok()?;
    Some(out)
}

/// A tree's entries: (mode, name, id).
pub(super) fn parse_tree(data: &[u8]) -> Vec<(u32, Vec<u8>, Oid)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let Some(space) = data[i..].iter().position(|&b| b == b' ') else { break };
        let Some(nul) = data[i + space..].iter().position(|&b| b == 0) else { break };
        let mode = std::str::from_utf8(&data[i..i + space]).ok().and_then(|m| u32::from_str_radix(m, 8).ok());
        let name = data[i + space + 1..i + space + nul].to_vec();
        let start = i + space + nul + 1;
        let Some(oid) = data.get(start..start + 20).and_then(|o| <Oid>::try_from(o).ok()) else { break };
        if let Some(mode) = mode {
            out.push((mode, name, oid));
        }
        i = start + 20;
    }
    out
}

/// A version 2 pack index: every object id in the pack and its offset.
pub(super) fn parse_idx(idx: &[u8]) -> Option<Vec<(Oid, u64)>> {
    let u32_at = |at: usize| idx.get(at..at + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap()));
    if idx.get(..4)? != b"\xfftOc" || u32_at(4)? != 2 {
        return None; // version 1 indexes predate 2008
    }
    let count = u32_at(8 + 255 * 4)? as usize;
    let ids = 8 + 256 * 4;
    let offsets = ids + count.checked_mul(24)?; // ids (20 bytes each), then CRCs (4)
    let large = offsets + count * 4;
    let mut out = Vec::with_capacity(count.min(1 << 24));
    for k in 0..count {
        let oid: Oid = idx.get(ids + k * 20..ids + k * 20 + 20)?.try_into().ok()?;
        let small = u32_at(offsets + k * 4)?;
        let offset = if small & 0x8000_0000 != 0 {
            let at = large + (small & 0x7fff_ffff) as usize * 8;
            u64::from_be_bytes(idx.get(at..at + 8)?.try_into().ok()?)
        } else {
            u64::from(small)
        };
        out.push((oid, offset));
    }
    Some(out)
}

pub(super) fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    let mut varint = || -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *delta.get(i)?;
            i += 1;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
    };
    let base_size = varint()?;
    let result_size = varint()?;
    if base_size != base.len() as u64 || result_size > MAX_OBJECT {
        return None;
    }
    let mut out = Vec::with_capacity(result_size as usize);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            // Copy a run from the base: which bytes follow depends on the bits set in `op`.
            let mut offset = 0usize;
            let mut len = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    offset |= usize::from(*delta.get(i)?) << (bit * 8);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    len |= usize::from(*delta.get(i)?) << (bit * 8);
                    i += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            out.extend_from_slice(base.get(offset..offset.checked_add(len)?)?);
        } else if op != 0 {
            // Insert the next `op` bytes as they are.
            out.extend_from_slice(delta.get(i..i + usize::from(op))?);
            i += usize::from(op);
        } else {
            return None;
        }
    }
    (out.len() as u64 == result_size).then_some(out)
}
