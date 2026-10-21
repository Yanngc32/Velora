//! Maps characters to key presses on the host's current X keyboard layout, so text typed on
//! a phone's soft keyboard comes out right whatever layout the host uses (ABNT2, US, ...).
//! Characters the layout only produces through a dead key (`á` on ABNT2 is `´` then `a`) are
//! typed that way.

use std::collections::HashMap;

use anyhow::{Context, Result};
use x11rb::{connection::Connection, protocol::xproto::ConnectionExt as _};

/// X keycodes are evdev codes + 8.
const EVDEV_OFFSET: u32 = 8;
const KEY_LEFTSHIFT: u16 = 42;
const KEY_ENTER: u16 = 28;
const KEY_TAB: u16 = 15;
const XK_ISO_LEVEL3_SHIFT: u32 = 0xfe03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stroke {
    pub code: u16,
    pub shift: bool,
    pub altgr: bool,
}

pub struct Keymap {
    keys: HashMap<u32, Stroke>,
    /// evdev code of the AltGr (ISO_Level3_Shift) key, if the layout has one.
    pub altgr: Option<u16>,
}

impl Keymap {
    pub fn load() -> Result<Self> {
        let (conn, _) = x11rb::connect(None).context("text input needs an X11 session")?;
        let setup = conn.setup();
        let (min, max) = (setup.min_keycode, setup.max_keycode);
        let reply = conn.get_keyboard_mapping(min, max - min + 1)?.reply()?;
        Ok(Self::from_mapping(min, reply.keysyms_per_keycode as usize, &reply.keysyms))
    }

    /// Builds the lookup from a core keyboard mapping. In the core view of an XKB layout,
    /// indices 0/1 are levels 1/2 (plain, Shift) and 4/5 are levels 3/4 (AltGr, AltGr+Shift).
    pub fn from_mapping(min_keycode: u8, per_keycode: usize, keysyms: &[u32]) -> Self {
        let mut keys = HashMap::new();
        for (i, syms) in keysyms.chunks(per_keycode.max(1)).enumerate() {
            let keycode = min_keycode as u32 + i as u32;
            let Some(code) = keycode.checked_sub(EVDEV_OFFSET).filter(|c| (1..=248).contains(c)) else { continue };
            for (index, shift, altgr) in [(0, false, false), (1, true, false), (4, false, true), (5, true, true)] {
                match syms.get(index) {
                    Some(&sym) if sym != 0 => {
                        // Prefer the simplest way to type a symbol.
                        keys.entry(sym).or_insert(Stroke { code: code as u16, shift, altgr });
                    }
                    _ => {}
                }
            }
        }
        let altgr = keys.get(&XK_ISO_LEVEL3_SHIFT).map(|s| s.code);
        Self { keys, altgr }
    }

    /// Key strokes producing `c`, or `None` if the layout cannot type it.
    pub fn strokes(&self, c: char) -> Option<Vec<Stroke>> {
        let plain = |code| Stroke { code, shift: false, altgr: false };
        match c {
            '\n' | '\r' => return Some(vec![plain(KEY_ENTER)]),
            '\t' => return Some(vec![plain(KEY_TAB)]),
            _ => {}
        }
        let usable = |s: &Stroke| !s.altgr || self.altgr.is_some();
        if let Some(s) = self.keys.get(&keysym(c)).filter(|s| usable(s)) {
            return Some(vec![*s]);
        }
        let (dead, base) = decompose(c)?;
        let dead = self.keys.get(&dead).filter(|s| usable(s))?;
        let base = self.keys.get(&keysym(base)).filter(|s| usable(s))?;
        Some(vec![*dead, *base])
    }
}

pub const SHIFT: u16 = KEY_LEFTSHIFT;

/// X keysym for a character: Latin-1 maps directly, everything else to the Unicode range.
fn keysym(c: char) -> u32 {
    let cp = c as u32;
    if (0x20..=0x7e).contains(&cp) || (0xa0..=0xff).contains(&cp) {
        cp
    } else {
        0x0100_0000 | cp
    }
}

const DEAD_GRAVE: u32 = 0xfe50;
const DEAD_ACUTE: u32 = 0xfe51;
const DEAD_CIRCUMFLEX: u32 = 0xfe52;
const DEAD_TILDE: u32 = 0xfe53;
const DEAD_DIAERESIS: u32 = 0xfe57;

/// Dead key + base letter for accented Latin letters.
fn decompose(c: char) -> Option<(u32, char)> {
    const TABLE: &[(u32, &str, &str)] = &[
        (DEAD_GRAVE, "àèìòùÀÈÌÒÙ", "aeiouAEIOU"),
        (DEAD_ACUTE, "áéíóúýÁÉÍÓÚÝ", "aeiouyAEIOUY"),
        (DEAD_CIRCUMFLEX, "âêîôûÂÊÎÔÛ", "aeiouAEIOU"),
        (DEAD_TILDE, "ãõñÃÕÑ", "aonAON"),
        (DEAD_DIAERESIS, "äëïöüÿÄËÏÖÜ", "aeiouyAEIOU"),
    ];
    TABLE.iter().find_map(|(dead, accented, base)| {
        let i = accented.chars().position(|a| a == c)?;
        Some((*dead, base.chars().nth(i)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few keys of a Brazilian ABNT2 layout, as the X server reports them.
    fn abnt2() -> Keymap {
        let per = 6;
        let mut syms = vec![0u32; 256 * per];
        let mut set = |keycode: usize, levels: [u32; 6]| syms[(keycode - 8) * per..][..per].copy_from_slice(&levels);
        set(38, [b'a' as u32, b'A' as u32, 0, 0, 0xe6, 0xc6]); // KEY_A
        set(26, [b'e' as u32, b'E' as u32, 0, 0, 0, 0]); // KEY_E
        set(10, [b'1' as u32, b'!' as u32, 0, 0, 0xb9, 0]); // KEY_1
        set(47, [0xe7, 0xc7, 0, 0, 0, 0]); // KEY_SEMICOLON: ç
        set(34, [DEAD_ACUTE, 0xfe50, 0, 0, 0, 0]); // ´ / `
        set(48, [DEAD_TILDE, DEAD_CIRCUMFLEX, 0, 0, 0, 0]); // ~ / ^
        set(108, [XK_ISO_LEVEL3_SHIFT, 0, 0, 0, 0, 0]); // right Alt
        Keymap::from_mapping(8, per, &syms)
    }

    fn s(code: u16, shift: bool, altgr: bool) -> Stroke {
        Stroke { code, shift, altgr }
    }

    #[test]
    fn types_direct_and_shifted_characters() {
        let km = abnt2();
        assert_eq!(km.altgr, Some(100));
        assert_eq!(km.strokes('a'), Some(vec![s(30, false, false)]));
        assert_eq!(km.strokes('A'), Some(vec![s(30, true, false)]));
        assert_eq!(km.strokes('!'), Some(vec![s(2, true, false)]));
        assert_eq!(km.strokes('ç'), Some(vec![s(39, false, false)]));
        assert_eq!(km.strokes('¹'), Some(vec![s(2, false, true)]));
        assert_eq!(km.strokes('\n'), Some(vec![s(KEY_ENTER, false, false)]));
    }

    #[test]
    fn composes_accents_with_dead_keys() {
        let km = abnt2();
        assert_eq!(km.strokes('é'), Some(vec![s(26, false, false), s(18, false, false)]));
        assert_eq!(km.strokes('ã'), Some(vec![s(40, false, false), s(30, false, false)]));
        assert_eq!(km.strokes('Ê'), Some(vec![s(40, true, false), s(18, true, false)]));
    }

    #[test]
    fn reports_untypable_characters() {
        assert_eq!(abnt2().strokes('✓'), None);
        assert_eq!(abnt2().strokes('õ'), None, "base letter o is not in this test layout");
    }

    #[test]
    fn keysyms() {
        assert_eq!(keysym('a'), 0x61);
        assert_eq!(keysym('ç'), 0xe7);
        assert_eq!(keysym('€'), 0x0100_20ac);
    }
}
