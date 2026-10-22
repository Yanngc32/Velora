//! Which process holds a UDP port, so a host that cannot bind can say why, and a leftover
//! copy of the host can be stopped from the launcher.

/// A process bound to the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortOwner {
    pub pid: u32,
    /// Executable name, such as `velora-host.exe`.
    pub name: String,
}

impl PortOwner {
    /// Another copy of the host: a stray `velora-host` or a build from before the rename
    /// (`sm-host`). Safe to stop, since it serves the same purpose as the one being started.
    pub fn is_host(&self) -> bool {
        let name = self.name.to_ascii_lowercase();
        let stem = name.strip_suffix(".exe").unwrap_or(&name);
        matches!(stem, "velora-host" | "sm-host")
    }
}

/// The process bound to `port` on UDP (IPv4 or IPv6), if any.
#[cfg(windows)]
pub fn udp_owner(port: u16) -> Option<PortOwner> {
    let pid = udp_pids(port).into_iter().next()?;
    Some(PortOwner { pid, name: process_name(pid).unwrap_or_else(|| "?".into()) })
}

#[cfg(not(windows))]
pub fn udp_owner(_port: u16) -> Option<PortOwner> {
    None
}

/// Stops the process and waits (briefly) for it to release its sockets.
#[cfg(windows)]
pub fn stop(pid: u32) -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        },
    };
    // SAFETY: the handle is closed before returning.
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid)
            .with_context(|| format!("opening process {pid}"))?;
        let result = TerminateProcess(process, 1).with_context(|| format!("stopping process {pid}"));
        if result.is_ok() {
            WaitForSingleObject(process, 5000);
        }
        let _ = CloseHandle(process);
        result
    }
}

#[cfg(not(windows))]
pub fn stop(_pid: u32) -> anyhow::Result<()> {
    anyhow::bail!("not supported on this platform")
}

/// Owners of `port` in the IPv4 and IPv6 UDP tables.
#[cfg(windows)]
fn udp_pids(port: u16) -> Vec<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;

    /// The table for one family: a row count followed by the rows.
    fn table(family: u32) -> Option<Vec<u64>> {
        let mut size = 0u32;
        // SAFETY: the first call only reports the size; the second fills a buffer that large,
        // 8-byte aligned for the rows.
        unsafe {
            GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0);
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let ok =
                GetExtendedUdpTable(Some(buf.as_mut_ptr().cast()), &mut size, false, family, UDP_TABLE_OWNER_PID, 0);
            (ok == 0).then_some(buf)
        }
    }
    /// Rows of type `T` after the `u32` count (padded to `T`'s alignment).
    fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
        let base = buf.as_ptr().cast::<u8>();
        // SAFETY: the API wrote `count` rows after the count; reads stay within `buf`.
        unsafe {
            let count = *base.cast::<u32>() as usize;
            let start = base.add(std::mem::align_of::<T>().max(4)).cast::<T>();
            let fit = (buf.len() * 8).saturating_sub(std::mem::align_of::<T>().max(4)) / std::mem::size_of::<T>();
            (0..count.min(fit)).map(|i| *start.add(i)).collect()
        }
    }

    let mut pids = Vec::new();
    if let Some(buf) = table(AF_INET) {
        let found = rows::<MIB_UDPROW_OWNER_PID>(&buf);
        pids.extend(found.iter().filter(|r| u16::from_be(r.dwLocalPort as u16) == port).map(|r| r.dwOwningPid));
    }
    if let Some(buf) = table(AF_INET6) {
        let found = rows::<MIB_UDP6ROW_OWNER_PID>(&buf);
        pids.extend(found.iter().filter(|r| u16::from_be(r.dwLocalPort as u16) == port).map(|r| r.dwOwningPid));
    }
    pids.dedup();
    pids
}

/// Executable name of a running process. Works for processes of other users too.
#[cfg(windows)]
fn process_name(pid: u32) -> Option<String> {
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        },
    };
    // SAFETY: the snapshot handle is closed before returning; `entry.dwSize` is set as required.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut name = None;
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            if entry.th32ProcessID == pid {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                name = Some(String::from_utf16_lossy(&entry.szExeFile[..len]));
                break;
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
        name
    }
}

#[cfg(test)]
mod tests {
    use super::PortOwner;

    #[test]
    fn recognizes_host_copies() {
        let owner = |name: &str| PortOwner { pid: 1, name: name.into() };
        assert!(owner("velora-host.exe").is_host());
        assert!(owner("SM-HOST.EXE").is_host());
        assert!(owner("velora-host").is_host());
        assert!(!owner("velora.exe").is_host());
        assert!(!owner("svchost.exe").is_host());
    }

    #[cfg(windows)]
    #[test]
    fn finds_own_socket() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let owner = super::udp_owner(port).expect("owner of a bound port");
        assert_eq!(owner.pid, std::process::id());
    }
}
