//! SHAKE with the official SDK's software Keccak-f[1600] permutation.
use leanvm_guest::keccak::f1600;

pub struct Xof {
    state: [u64; 25],
    position: usize,
    rate: usize,
    squeezing: bool,
}

impl Xof {
    pub fn new(rate: usize) -> Self {
        assert!(rate == 136 || rate == 168);
        Self {
            state: [0; 25],
            position: 0,
            rate,
            squeezing: false,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        assert!(!self.squeezing);
        while !bytes.is_empty() {
            if self.position.is_multiple_of(8) && bytes.len() >= 8 {
                self.state[self.position / 8] ^= u64::from_le_bytes(bytes[..8].try_into().unwrap());
                self.position += 8;
                bytes = &bytes[8..];
            } else {
                self.state[self.position / 8] ^= (bytes[0] as u64) << (8 * (self.position % 8));
                self.position += 1;
                bytes = &bytes[1..];
            }
            if self.position == self.rate {
                f1600(&mut self.state);
                self.position = 0;
            }
        }
    }

    pub fn read(&mut self, output: &mut [u8]) {
        if !self.squeezing {
            self.state[self.position / 8] ^= 0x1f << (8 * (self.position % 8));
            self.state[self.rate / 8 - 1] ^= 1 << 63;
            f1600(&mut self.state);
            self.position = 0;
            self.squeezing = true;
        }
        for byte in output {
            if self.position == self.rate {
                f1600(&mut self.state);
                self.position = 0;
            }
            *byte = (self.state[self.position / 8] >> (8 * (self.position % 8))) as u8;
            self.position += 1;
        }
    }
}

pub fn shake256(parts: &[&[u8]]) -> [u8; 32] {
    let mut xof = Xof::new(136);
    for part in parts {
        xof.update(part);
    }
    let mut result = [0; 32];
    xof.read(&mut result);
    result
}
