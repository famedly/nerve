use anyhow::bail;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use rand::random;
use std::io::{Read, Write};

pub const IMAGE_WIDTH: u32 = 128;
pub const IMAGE_HEIGHT: u32 = 128;

const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

fn write_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

pub fn generate_png() -> Vec<u8> {
    let mut out = Vec::new();

    // PNG signature
    out.extend_from_slice(&PNG_SIGNATURE);

    // IHDR chunk: 13 bytes of data
    let mut ihdr_data = Vec::with_capacity(13);
    ihdr_data.extend_from_slice(&IMAGE_WIDTH.to_be_bytes());
    ihdr_data.extend_from_slice(&IMAGE_HEIGHT.to_be_bytes());
    ihdr_data.push(8); // bit depth
    ihdr_data.push(6); // color type: RGBA
    ihdr_data.push(0); // compression method
    ihdr_data.push(0); // filter method
    ihdr_data.push(0); // interlace method
    write_chunk(&mut out, b"IHDR", &ihdr_data);

    // Build raw image data: each row has filter byte 0 + WIDTH*4 random RGBA bytes
    let mut raw_data = Vec::with_capacity((IMAGE_HEIGHT as usize) * (1 + IMAGE_WIDTH as usize * 4));
    #[allow(clippy::same_item_push)]
    for _ in 0..IMAGE_HEIGHT {
        raw_data.push(0); // filter byte: None
        for _ in 0..IMAGE_WIDTH * 4 {
            raw_data.push(random::<u8>());
        }
    }

    // Compress with zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&raw_data)
        .expect("zlib compression write failed");
    let compressed = encoder.finish().expect("zlib compression finish failed");

    // IDAT chunk
    write_chunk(&mut out, b"IDAT", &compressed);

    // IEND chunk (empty)
    write_chunk(&mut out, b"IEND", &[]);

    out
}

pub fn validate_png(data: &[u8]) -> anyhow::Result<()> {
    if data.len() < 8 {
        bail!("data too short to contain PNG signature");
    }

    if data[..8] != PNG_SIGNATURE {
        bail!("invalid PNG signature");
    }

    let mut pos = 8;
    let mut chunk_index = 0;
    let mut found_ihdr = false;
    let mut found_iend = false;
    let mut idat_compressed = Vec::new();
    let mut ihdr_width: u32 = 0;
    let mut ihdr_height: u32 = 0;

    loop {
        if found_iend {
            // No more data should follow IEND (or we just stop parsing)
            break;
        }

        if pos + 8 > data.len() {
            bail!("unexpected end of data while reading chunk header at offset {pos}");
        }

        let length =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let chunk_type: [u8; 4] = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
        pos += 4;

        if pos + length + 4 > data.len() {
            bail!(
                "unexpected end of data while reading chunk body/CRC for chunk {:?} at offset {pos}",
                String::from_utf8_lossy(&chunk_type)
            );
        }

        let chunk_data = &data[pos..pos + length];
        pos += length;

        let stored_crc =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Verify CRC over type + data
        let mut crc_input = Vec::with_capacity(4 + length);
        crc_input.extend_from_slice(&chunk_type);
        crc_input.extend_from_slice(chunk_data);
        let computed_crc = crc32(&crc_input);
        if stored_crc != computed_crc {
            bail!(
                "CRC mismatch for chunk {:?}: stored={stored_crc:#010X}, computed={computed_crc:#010X}",
                String::from_utf8_lossy(&chunk_type)
            );
        }

        match &chunk_type {
            b"IHDR" => {
                if chunk_index != 0 {
                    bail!("IHDR chunk is not the first chunk");
                }
                if length < 13 {
                    bail!("IHDR chunk data too short (expected 13 bytes, got {length})");
                }
                found_ihdr = true;
                ihdr_width = u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]);
                ihdr_height = u32::from_be_bytes([
                    chunk_data[4],
                    chunk_data[5],
                    chunk_data[6],
                    chunk_data[7],
                ]);
            }
            b"IDAT" => {
                if !found_ihdr {
                    bail!("IDAT chunk found before IHDR");
                }
                idat_compressed.extend_from_slice(chunk_data);
            }
            b"IEND" => {
                found_iend = true;
            }
            _ => {
                // Unknown or ancillary chunk, skip
            }
        }

        chunk_index += 1;
    }

    if !found_ihdr {
        bail!("no IHDR chunk found");
    }
    if !found_iend {
        bail!("no IEND chunk found");
    }

    // Decompress IDAT data
    if idat_compressed.is_empty() {
        bail!("no IDAT data found");
    }

    let mut decoder = ZlibDecoder::new(&idat_compressed[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| anyhow::anyhow!("failed to decompress IDAT data: {e}"))?;

    // Verify decompressed size: each row = 1 filter byte + width * 4 bytes (RGBA)
    let expected_size = (ihdr_height as usize) * (1 + ihdr_width as usize * 4);
    if decompressed.len() != expected_size {
        bail!(
            "decompressed IDAT size mismatch: expected {expected_size}, got {}",
            decompressed.len()
        );
    }

    Ok(())
}
