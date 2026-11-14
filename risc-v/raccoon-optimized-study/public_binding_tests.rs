//! Public-statement correctness checks only. No guest execution or proving.
use super::{expected, hex};
use serde_json::{Value, json};

fn claims(key_bytes: usize) -> Vec<Value> {
    (0..2)
        .map(|i| {
            let mut key = vec![0u8; key_bytes];
            key[key_bytes - 1] = i + 1;
            json!({"public_key":hex(&key),"message":hex(&[i+3;32])})
        })
        .collect()
}

#[test]
fn every_public_record_contributes_its_key_message_position_and_count() {
    for (scheme, key_bytes) in [("raccoon", 2256), ("raccoon-g", 16144)] {
        let records = claims(key_bytes);
        let baseline = expected(scheme, &records).unwrap();
        assert_ne!(baseline, expected(scheme, &records[..1]).unwrap());
        let mut reordered = records.clone();
        reordered.swap(0, 1);
        assert_ne!(baseline, expected(scheme, &reordered).unwrap());
        for record in 0..records.len() {
            for (field, bytes) in [("public_key", key_bytes), ("message", 32)] {
                for position in [0, bytes / 2, bytes - 1] {
                    let mut changed = records.clone();
                    let mut data = vec![0u8; bytes];
                    if field == "public_key" {
                        data[bytes - 1] = record as u8 + 1;
                    } else {
                        data.fill(record as u8 + 3);
                    }
                    data[position] ^= 1;
                    changed[record][field] = json!(hex(&data));
                    assert_ne!(
                        baseline,
                        expected(scheme, &changed).unwrap(),
                        "{scheme} record {record} field {field} byte {position}"
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_public_records_and_variant_substitution_are_rejected() {
    for (scheme, key_bytes) in [("raccoon", 2256), ("raccoon-g", 16144)] {
        assert!(expected(scheme, &[]).is_err());
        assert!(expected(scheme, &vec![claims(key_bytes)[0].clone(); 65]).is_err());
        for (field, bytes) in [("public_key", key_bytes), ("message", 32)] {
            let mut changed = claims(key_bytes);
            changed[0][field] = json!(hex(&vec![0; bytes - 1]));
            assert!(expected(scheme, &changed).is_err());
            changed[0][field] = json!("not hex");
            assert!(expected(scheme, &changed).is_err());
        }
    }
    assert!(expected("raccoon", &claims(16144)).is_err());
    assert!(expected("raccoon-g", &claims(2256)).is_err());
    assert!(expected("unknown", &claims(2256)).is_err());
}
