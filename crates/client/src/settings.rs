//! Preferences of this client device, shared by the GUI and the command line.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use velora_protocol::identity::StateDir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Name hosts list this device under.
    pub device_name: String,
    /// Install updates in the background (release builds only).
    pub auto_update: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { device_name: default_device_name(), auto_update: true }
    }
}

impl Settings {
    const FILE: &'static str = "settings.json";

    pub fn load(state: &StateDir) -> Self {
        state.load(Self::FILE).unwrap_or_default()
    }

    pub fn save(&self, state: &StateDir) -> Result<()> {
        state.save(Self::FILE, self)
    }
}

pub fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "client".into())
}
