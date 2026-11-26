//! `LP(x) = u32be(len(x)) ‖ x` (spec §1).

pub(crate) fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    // Inputs are labels, origins and operation names; none approach 4 GiB.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    #[test]
    fn length_prefix_is_u32_big_endian() {
        let mut out = Vec::new();
        super::push_lp(&mut out, b"abc");
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }
}
