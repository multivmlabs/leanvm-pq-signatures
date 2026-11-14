//! Canonical Montgomery64 ring arithmetic. All internal coefficients are < q.
use crate::constants::{NI, ONE, Q, QINV, R2, W};
pub const N: usize = 256;
pub type Poly = [u64; N];

#[inline(always)]
pub fn add(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= Q { sum - Q } else { sum }
}

#[inline(always)]
pub fn sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { a + Q - b }
}

#[inline(always)]
pub fn multiply(a: u64, b: u64) -> u64 {
    // a*b < q^2 < 2^100; m*q < 2^114. Their sum cannot overflow u128.
    let product = (a as u128) * (b as u128);
    let m = (product as u64).wrapping_mul(QINV);
    let reduced = ((product + (m as u128) * (Q as u128)) >> 64) as u64;
    if reduced >= Q { reduced - Q } else { reduced }
}

#[inline(always)]
pub fn to_montgomery(a: u64) -> u64 {
    multiply(a, R2)
}
#[inline(always)]
pub fn from_montgomery(a: u64) -> u64 {
    multiply(a, 1)
}

pub fn forward(poly: &mut Poly) {
    let mut length = N / 2;
    let mut wi = 0;
    while length > 0 {
        for start in (0..N).step_by(2 * length) {
            wi += 1;
            let zeta = W[wi];
            for index in start..start + length {
                let x = poly[index];
                let y = multiply(poly[index + length], zeta);
                poly[index] = add(x, y);
                poly[index + length] = sub(x, y);
            }
        }
        length /= 2;
    }
}

pub fn inverse(poly: &mut Poly) {
    let mut length = 1;
    let mut wi = N;
    while length < N {
        for start in (0..N).step_by(2 * length) {
            wi -= 1;
            let zeta = W[wi];
            for index in start..start + length {
                let x = poly[index];
                let y = poly[index + length];
                poly[index] = add(x, y);
                poly[index + length] = multiply(sub(y, x), zeta);
            }
        }
        length *= 2;
    }
    for coefficient in poly {
        *coefficient = multiply(*coefficient, NI);
    }
}

pub fn challenge(hash: &[u8; 32]) -> Poly {
    let mut xof = crate::xof::Xof::new(136);
    xof.update(&[b'c', 23, 0, 0, 0, 0, 0, 0]);
    xof.update(hash);
    let mut poly = [0; N];
    let mut weight = 0;
    while weight < 23 {
        let mut sample = [0; 2];
        xof.read(&mut sample);
        let x = u16::from_le_bytes(sample);
        let index = ((x >> 1) & 255) as usize;
        if poly[index] == 0 {
            poly[index] = if x & 1 == 1 { ONE } else { Q - ONE };
            weight += 1;
        }
    }
    poly
}

pub fn matrix_poly(seed: &[u8], row: usize, column: usize, output: &mut Poly) {
    let mut xof = crate::xof::Xof::new(168);
    xof.update(&[b'A', row as u8, column as u8, 0, 0, 0, 0, 0]);
    xof.update(seed);
    for coefficient in output {
        loop {
            let mut bytes = [0; 8];
            xof.read(&mut bytes[..7]);
            let value = u64::from_le_bytes(bytes) & ((1 << 50) - 1);
            if value < Q {
                *coefficient = to_montgomery(value);
                break;
            }
        }
    }
}
