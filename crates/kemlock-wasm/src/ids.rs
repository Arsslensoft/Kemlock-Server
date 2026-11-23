//! Account ids, item ids and owners as they travel in JSON: hyphenated lower-case UUIDs and
//! `user:<uuid>` or `space:<uuid>`.

use kemlock_crypto::owner::Owner;

use crate::error::Error;

/// Parses a hyphenated lower-case UUID into its 16 raw bytes; anything else is refused.
pub(crate) fn parse_uuid(text: &str) -> Result<[u8; 16], Error> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return Err(Error::Invalid);
    }
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high = true;
    for (position, &c) in bytes.iter().enumerate() {
        if matches!(position, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return Err(Error::Invalid);
            }
            continue;
        }
        let nibble = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return Err(Error::Invalid),
        };
        if high {
            out[index] = nibble << 4;
        } else {
            out[index] |= nibble;
            index += 1;
        }
        high = !high;
    }
    Ok(out)
}

/// Parses `user:<uuid>` or `space:<uuid>`.
pub(crate) fn parse_owner(text: &str) -> Result<Owner, Error> {
    if let Some(id) = text.strip_prefix("user:") {
        Ok(Owner::user(parse_uuid(id)?))
    } else if let Some(id) = text.strip_prefix("space:") {
        Ok(Owner::space(parse_uuid(id)?))
    } else {
        Err(Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
    const BYTES: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn parses_a_canonical_uuid() {
        assert_eq!(parse_uuid(ID), Ok(BYTES));
    }

    #[test]
    fn refuses_every_other_form() {
        for bad in [
            "",
            "00010203-0405-0607-0809-0A0B0C0D0E0F",
            "000102030405060708090a0b0c0d0e0f",
            "{00010203-0405-0607-0809-0a0b0c0d0e0f}",
            "00010203-0405-0607-0809-0a0b0c0d0e0g",
            "00010203_0405-0607-0809-0a0b0c0d0e0f",
            "00010203-0405-0607-0809-0a0b0c0d0e0f0",
        ] {
            assert_eq!(parse_uuid(bad), Err(Error::Invalid), "{bad:?}");
        }
    }

    #[test]
    fn owners_carry_their_kind() {
        let user = parse_owner(&format!("user:{ID}")).expect("user owner");
        let space = parse_owner(&format!("space:{ID}")).expect("space owner");
        assert_eq!(user.to_bytes()[0], 1);
        assert_eq!(space.to_bytes()[0], 2);
        assert_eq!(&user.to_bytes()[1..], &BYTES);
        for bad in [
            "",
            ID,
            "team:00010203-0405-0607-0809-0a0b0c0d0e0f",
            "user:x",
        ] {
            assert_eq!(parse_owner(bad), Err(Error::Invalid), "{bad:?}");
        }
    }
}
