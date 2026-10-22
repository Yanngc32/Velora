//! Starting with the user's session. One login entry runs `velora --autostart`, which turns
//! sharing on and/or opens the launcher minimized, as the settings say (see `main`).

use std::path::Path;

use anyhow::Result;

/// The command a login entry runs. Paths are made absolute: sign-in runs it from another
/// working directory.
fn command_line(config_dir: Option<&Path>) -> Result<String> {
    let exe = std::env::current_exe()?;
    let mut line = quote(&exe.display().to_string());
    if let Some(dir) = config_dir {
        line.push_str(" --config-dir ");
        line.push_str(&quote(&std::path::absolute(dir)?.display().to_string()));
    }
    line.push_str(" --autostart");
    Ok(line)
}

/// Windows command-line quoting: backslashes before the closing quote are doubled, or
/// `"D:\"` would end with an escaped quote.
#[cfg(windows)]
fn quote(arg: &str) -> String {
    let trailing = arg.len() - arg.trim_end_matches('\\').len();
    format!("\"{arg}{}\"", "\\".repeat(trailing))
}

/// Desktop entry `Exec` quoting: `"`, `` ` ``, `$` and `\` are escaped inside quotes, and `%`
/// (field codes) is doubled.
#[cfg(unix)]
fn quote(arg: &str) -> String {
    let mut out = String::from("\"");
    for c in arg.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Adds or removes the login entry.
#[cfg(windows)]
pub fn apply(enabled: bool, config_dir: Option<&Path>) -> Result<()> {
    use anyhow::Context;
    use windows::{
        core::HSTRING,
        Win32::System::Registry::{RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ},
    };

    let key = HSTRING::from(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let name = HSTRING::from("Velora");
    if !enabled {
        // SAFETY: valid strings; a missing value is not an error worth reporting.
        let _ = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, &key, &name) };
        return Ok(());
    }
    let value: Vec<u16> = command_line(config_dir)?.encode_utf16().chain([0]).collect();
    // SAFETY: `value` is a NUL-terminated UTF-16 string of the given size in bytes.
    unsafe {
        RegSetKeyValueW(HKEY_CURRENT_USER, &key, &name, REG_SZ.0, Some(value.as_ptr().cast()), (value.len() * 2) as u32)
    }
    .ok()
    .context("writing the login entry")
}

/// Adds or removes `~/.config/autostart/velora.desktop` (XDG autostart).
#[cfg(unix)]
pub fn apply(enabled: bool, config_dir: Option<&Path>) -> Result<()> {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .ok_or_else(|| anyhow::anyhow!("no home directory"))?
        .join("autostart");
    let file = dir.join("velora.desktop");
    if !enabled {
        let _ = std::fs::remove_file(file);
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Velora\nExec={}\nX-GNOME-Autostart-enabled=true\n",
        command_line(config_dir)?
    );
    std::fs::write(file, entry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn quotes_windows_arguments() {
        assert_eq!(super::quote(r"C:\Program Files\velora.exe"), r#""C:\Program Files\velora.exe""#);
        assert_eq!(super::quote(r"D:\"), r#""D:\\""#);
    }

    #[cfg(unix)]
    #[test]
    fn quotes_desktop_entry_arguments() {
        assert_eq!(super::quote("/home/a b/velora"), r#""/home/a b/velora""#);
        assert_eq!(super::quote("/x/$HOME/50%"), r#""/x/\$HOME/50%%""#);
    }
}
