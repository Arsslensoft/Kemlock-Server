//! Punycode (RFC 3492) encoding of one label, which is all the site rule needs: hosts are made
//! lower case and NFC first, so no IDNA mapping table is involved.

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (((BASE - T_MIN + 1) * delta) / (delta + SKEW))
}

fn digit(d: u32) -> char {
    // `d` is below 36 by construction.
    let byte = if d < 26 {
        b'a' + u8::try_from(d).unwrap_or(0)
    } else {
        b'0' + u8::try_from(d - 26).unwrap_or(0)
    };
    char::from(byte)
}

/// The Punycode of `input` without the `xn--` prefix; `None` on arithmetic overflow, which only a
/// label far beyond DNS's 63 octets could cause.
fn encode(input: &str) -> Option<String> {
    let chars: Vec<u32> = input.chars().map(u32::from).collect();
    let mut out: String = input.chars().filter(char::is_ascii).collect();
    let basic = u32::try_from(out.len()).ok()?;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }
    let total = u32::try_from(chars.len()).ok()?;
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    while handled < total {
        let m = chars.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &chars {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n += 1;
    }
    Some(out)
}

/// A host label as it is written in DNS: ASCII stays as it is, anything else becomes `xn--` and
/// its Punycode. The label must already be lower case and NFC.
pub(crate) fn label_to_ascii(label: &str) -> Option<String> {
    if label.is_ascii() {
        return Some(label.to_owned());
    }
    encode(label).map(|p| format!("xn--{p}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_labels_stay() {
        assert_eq!(label_to_ascii("example").as_deref(), Some("example"));
        assert_eq!(
            label_to_ascii("xn--bcher-kva").as_deref(),
            Some("xn--bcher-kva")
        );
    }

    #[test]
    fn known_labels() {
        for (unicode, ascii) in [
            ("b\u{fc}cher", "xn--bcher-kva"),
            ("m\u{fc}nchen", "xn--mnchen-3ya"),
            ("ma\u{f1}ana", "xn--maana-pta"),
            ("\u{4f8b}\u{3048}", "xn--r8jz45g"),
            ("\u{65e5}\u{672c}\u{8a9e}", "xn--wgv71a119e"),
            ("\u{516c}\u{53f8}", "xn--55qx5d"),
        ] {
            assert_eq!(label_to_ascii(unicode).as_deref(), Some(ascii), "{unicode}");
        }
    }

    #[test]
    fn the_rfc_3492_sample_for_a_single_non_basic_label() {
        // RFC 3492 section 7.1 (A) Arabic (Egyptian), without the prefix.
        let arabic = "\u{644}\u{64a}\u{647}\u{645}\u{627}\u{628}\u{62a}\u{643}\u{644}\u{645}\u{648}\u{634}\u{639}\u{631}\u{628}\u{64a}\u{61f}";
        assert_eq!(encode(arabic).as_deref(), Some("egbpdaj6bu4bxfgehfvwxn"));
    }
}
