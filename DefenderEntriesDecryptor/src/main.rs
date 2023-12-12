use std::env;
use std::str;
use std::fs::File;
use std::str::Utf8Error;
use chrono::{DateTime, Utc};
use std::io::{self, Read, Write, Cursor};
use std::time::{UNIX_EPOCH, Duration};
use byteorder::{LittleEndian, ReadBytesExt};

// RC4 decrypt function
fn rc4_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<usize> = (0..256).collect();
    let mut j: usize = 0;
    let mut out = Vec::new();

    // KSA Phase
    for i in 0..256 {
        j = (j + s[i] + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    // PRGA Phase
    let (mut i, mut j) = (0, 0);
    for &char in data {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        s.swap(i, j);
        out.push(char ^ s[(s[i] + s[j]) % 256] as u8);
    }

    out
}

// Function to extract entry from the decrypted data
fn get_entry(data: &[u8]) -> Result<(String, String, String), Utf8Error> {
    let pos = data.windows(3).position(|x| x == [0, 0, 0]).unwrap() + 1;

    // Decode UTF-16LE string
    let path_u16 = (0..pos).step_by(2)
        .map(|i| u16::from_le_bytes([data[i], data[i + 1]]))
        .take_while(|&u| u != 0) // Stop at null terminator
        .collect::<Vec<u16>>();
    let path_str = String::from_utf16_lossy(&path_u16);

    // Rest of the function...
    let mut path = path_str.clone();
    if path_str.starts_with("?\\") {
        path = path_str[2..].to_string();
    }

    let pos = pos + 4;
    let type_len = data[pos..].iter().position(|&x| x == 0).unwrap();
    let type_str = str::from_utf8(&data[pos..pos + type_len])?;

    let pos = pos + type_len + 1;
    let pos = (pos + 3) & !3; // align to 4 bytes
    let pos = pos + 4;
    let hash = &data[pos..pos + 20];

    Ok((path, hex::encode(hash).to_uppercase(), type_str.to_string()))
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: defender_entries_decryptor.exe <input_file> <output_file>");
        return Ok(());
    }

    let input_file = &args[1];
    let output_file = &args[2];

    let key: Vec<u8> = vec![
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
        0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
        0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
        0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
        0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
        0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
        0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
        0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
        0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
        0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
        0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
        0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
        0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
        0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
        0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
        0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
        0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
        0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
    ];

    let mut f = File::open(input_file)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    // Decrypt the header
    let header = rc4_decrypt(&key, &buffer[..0x3c]);
    let mut header_cursor = Cursor::new(header);
    header_cursor.set_position(0x28);
    let data1_len = header_cursor.read_u32::<LittleEndian>()?;

    // Decrypt and process data segments
    let data1 = rc4_decrypt(&key, &buffer[0x3c..0x3c + data1_len as usize]);
    let filetime = &data1[0x20..0x28];
    let filetime = u64::from_le_bytes(filetime.try_into().unwrap());
    let detection = str::from_utf8(&data1[0x34..]).unwrap();

    let data2 = rc4_decrypt(&key, &buffer[0x3c + data1_len as usize..]);
    let mut data2_cursor = Cursor::new(data2);
    let cnt = data2_cursor.read_u32::<LittleEndian>()?;
    let mut offsets = Vec::new();
    for _ in 0..cnt {
        offsets.push(data2_cursor.read_u32::<LittleEndian>()?);
    }

    let mut results = Vec::new();
    for o in offsets {
        let entry_data = &data2_cursor.get_ref()[o as usize..];

        // Handle the result from get_entry
        match get_entry(entry_data) {
            Ok((path, hash, entry_type)) => {
                if entry_type == "file" {
                    let filetime = UNIX_EPOCH + Duration::from_micros(filetime / 10 - 11644473600000000);
                    results.push((path, hash, detection.to_string(), filetime));
                }
            },
            Err(e) => {
                eprintln!("Error parsing entry: {}", e);
                continue;
            }
        }
    }

    // Write results to the output file
    let mut output = File::create(output_file)?;
    for result in &results {
        let (ref path, ref hash, ref detection, ref filetime) = *result;

        // Remove the '\\?\' prefix if it exists
        let formatted_path = if path.starts_with("\\\\?\\") {
            &path[4..]
        } else {
            path.as_str()
        };

        // Convert SystemTime to DateTime<Utc>
        let datetime: DateTime<Utc> = (*filetime).into();
        let formatted_filetime = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();

        // Adjust the string formatting
        writeln!(output, "file_record(path='{}', hash='{}', detection='{}', filetime={})", formatted_path, hash, detection.trim_end_matches('\0'), formatted_filetime)?;
    }

    println!("Defender Entries Decryption complete. Results saved to {}", output_file);
    Ok(())
}
