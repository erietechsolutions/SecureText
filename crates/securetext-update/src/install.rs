//! How this copy of SecureText was installed, and how to apply an update
//! to it.
//!
//! | Installed as | Update asset | Applied by |
//! |---|---|---|
//! | AppImage | the new `.AppImage` | replacing the file in place, then restarting |
//! | NSIS `.exe` (Windows) | the new NSIS installer | running it passively (`/P /R /UPDATE`): it closes the app, installs, relaunches |
//! | `.msi` (Windows) | the new `.msi` | `msiexec /passive` |
//! | `.deb` / `.rpm` | the new package | the system's software installer (root is needed; the app never asks for it itself) |
//!
//! A development build (`cargo run`) isn't an install: it can still be
//! told a release exists, but never updates itself.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallKind {
    AppImage { path: PathBuf },
    WindowsNsis,
    WindowsMsi,
    Deb,
    Rpm,
    /// Not installed from a release (a source build).
    Development,
}

impl InstallKind {
    /// The key for this install's asset in the manifest.
    pub fn platform_key(&self) -> Option<&'static str> {
        Some(match self {
            Self::AppImage { .. } => "linux-x86_64-appimage",
            Self::WindowsNsis => "windows-x86_64-nsis",
            Self::WindowsMsi => "windows-x86_64-msi",
            Self::Deb => "linux-x86_64-deb",
            Self::Rpm => "linux-x86_64-rpm",
            Self::Development => return None,
        })
    }

    /// File extension for a downloaded asset of this kind.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::AppImage { .. } => "AppImage",
            Self::WindowsNsis => "exe",
            Self::WindowsMsi => "msi",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Development => "bin",
        }
    }

    /// Whether the app can apply an update without the user doing
    /// anything beyond agreeing to restart.
    pub fn applies_itself(&self) -> bool {
        matches!(self, Self::AppImage { .. } | Self::WindowsNsis | Self::WindowsMsi)
    }

    /// Work out how the running executable was installed. Only the
    /// current platform's checks are compiled in: a Windows build never
    /// looks for AppImages or Linux packages, and vice versa.
    pub fn detect() -> Self {
        if !cfg!(target_arch = "x86_64") {
            return Self::Development;
        }
        let Ok(exe) = std::env::current_exe() else { return Self::Development };
        detect_for(&exe)
    }
}

#[cfg(target_os = "linux")]
fn detect_for(exe: &Path) -> InstallKind {
    // The AppImage runtime sets APPIMAGE to the image's own path; only
    // trust it if we really are running from inside its mount.
    if let Some(image) = std::env::var_os("APPIMAGE").map(PathBuf::from) {
        if image.is_file() && std::env::var_os("APPDIR").is_some_and(|d| exe.starts_with(d)) {
            return InstallKind::AppImage { path: image };
        }
    }
    if exe.starts_with("/usr/bin") || exe.starts_with("/usr/lib") {
        return linux_package_kind(&std::fs::read_to_string("/etc/os-release").unwrap_or_default());
    }
    InstallKind::Development
}

#[cfg(windows)]
fn detect_for(exe: &Path) -> InstallKind {
    // NSIS installs put an uninstaller next to the executable.
    let dir = exe.parent().unwrap_or(Path::new("."));
    if dir.join("uninstall.exe").is_file() {
        return InstallKind::WindowsNsis;
    }
    if exe.to_string_lossy().to_ascii_lowercase().contains("\\program files") {
        return InstallKind::WindowsMsi;
    }
    InstallKind::Development
}

#[cfg(not(any(target_os = "linux", windows)))]
fn detect_for(_exe: &Path) -> InstallKind {
    InstallKind::Development
}

/// deb or rpm, from `/etc/os-release`'s `ID` / `ID_LIKE`.
#[cfg(target_os = "linux")]
pub fn linux_package_kind(os_release: &str) -> InstallKind {
    let ids: Vec<String> = os_release
        .lines()
        .filter_map(|l| l.strip_prefix("ID=").or_else(|| l.strip_prefix("ID_LIKE=")))
        .flat_map(|v| v.trim_matches('"').split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .collect();
    let has = |names: &[&str]| ids.iter().any(|id| names.contains(&id.as_str()));
    if has(&["debian", "ubuntu"]) {
        InstallKind::Deb
    } else if has(&["fedora", "rhel", "centos", "suse", "opensuse"]) {
        InstallKind::Rpm
    } else {
        InstallKind::Development
    }
}

/// What happened when an update was applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The new version is in place; restart into it (the path to launch).
    Restart(PathBuf),
    /// An installer is running and will close and relaunch the app itself;
    /// the app should exit now.
    InstallerLaunched,
    /// The package was handed to the system's software installer, which
    /// asks the user for permission; nothing more for the app to do.
    HandedToSystem(PathBuf),
}

/// Re-check a staged download against the hash the signed manifest gave,
/// right before using it.
pub fn verify_file(path: &Path, sha256_hex: &str, size: u64) -> anyhow::Result<()> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    anyhow::ensure!(file.metadata()?.len() == size, "downloaded update has the wrong size");
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    anyhow::ensure!(actual.eq_ignore_ascii_case(sha256_hex), "downloaded update does not match the signed hash");
    Ok(())
}

/// Apply a staged, already-verified update. Each platform only compiles
/// the installers it can actually run; any other kind is refused.
pub fn apply(kind: &InstallKind, staged: &Path) -> anyhow::Result<Applied> {
    match kind {
        #[cfg(target_os = "linux")]
        InstallKind::AppImage { path } => {
            replace_file(staged, path)?;
            Ok(Applied::Restart(path.clone()))
        }
        #[cfg(target_os = "linux")]
        InstallKind::Deb | InstallKind::Rpm => {
            // Opens GNOME Software / KDE Discover / App Center, which shows
            // the package and asks for the admin password itself.
            std::process::Command::new("xdg-open").arg(staged).spawn()?;
            Ok(Applied::HandedToSystem(staged.to_path_buf()))
        }
        #[cfg(windows)]
        InstallKind::WindowsNsis => {
            std::process::Command::new(staged).args(["/P", "/R", "/UPDATE"]).spawn()?;
            Ok(Applied::InstallerLaunched)
        }
        #[cfg(windows)]
        InstallKind::WindowsMsi => {
            std::process::Command::new("msiexec")
                .arg("/i")
                .arg(staged)
                .args(["/passive", "/norestart"])
                .spawn()?;
            Ok(Applied::InstallerLaunched)
        }
        InstallKind::Development => anyhow::bail!("this is a development build; install a release to get updates"),
        #[allow(unreachable_patterns)]
        other => anyhow::bail!("a {} update can't be installed on this platform", other.extension()),
    }
}

/// Swap `new` in for `target` atomically (AppImages, so Linux only): copy
/// next to the target (same filesystem), make it executable, flush it to
/// disk, then rename over the old one. A crash at any point leaves either
/// the old or the new file, never half of one.
#[cfg(target_os = "linux")]
pub fn replace_file(new: &Path, target: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = target.parent().ok_or_else(|| anyhow::anyhow!("update target has no directory"))?;
    let tmp = dir.join(format!(
        ".{}.update-tmp",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("securetext")
    ));
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(new, &tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::File::open(&tmp)?.sync_all()?;
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn package_kind_follows_os_release() {
        assert_eq!(linux_package_kind("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"), InstallKind::Deb);
        assert_eq!(linux_package_kind("ID=fedora\nVERSION_ID=44\n"), InstallKind::Rpm);
        assert_eq!(linux_package_kind("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"), InstallKind::Rpm);
        assert_eq!(linux_package_kind("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"), InstallKind::Deb);
        assert_eq!(linux_package_kind("ID=arch\n"), InstallKind::Development);
    }

    #[test]
    fn a_staged_file_must_match_the_signed_hash_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update.AppImage");
        std::fs::write(&path, b"new version").unwrap();
        let good = crate::manifest::sha256_hex(b"new version");
        verify_file(&path, &good, 11).unwrap();
        assert!(verify_file(&path, &good, 12).is_err(), "size");
        assert!(verify_file(&path, &crate::manifest::sha256_hex(b"other"), 11).is_err(), "hash");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacing_an_appimage_is_complete_and_executable() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("SecureText.AppImage");
        let staged = dir.path().join("staged");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        assert_eq!(apply(&InstallKind::AppImage { path: target.clone() }, &staged).unwrap(), Applied::Restart(target.clone()));
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o755);
        }
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(leftovers.len(), 2, "no temp file left behind: {leftovers:?}");
    }

    #[test]
    fn installers_for_other_platforms_are_refused() {
        #[cfg(target_os = "linux")]
        let foreign = [InstallKind::WindowsNsis, InstallKind::WindowsMsi];
        #[cfg(windows)]
        let foreign = [InstallKind::AppImage { path: "x".into() }, InstallKind::Deb, InstallKind::Rpm];
        #[cfg(not(any(target_os = "linux", windows)))]
        let foreign: [InstallKind; 0] = [];
        for kind in foreign {
            let err = apply(&kind, Path::new("/nonexistent")).unwrap_err().to_string();
            assert!(err.contains("can't be installed on this platform"), "{err}");
        }
    }

    #[test]
    fn development_builds_never_update_themselves() {
        assert_eq!(InstallKind::Development.platform_key(), None);
        assert!(apply(&InstallKind::Development, Path::new("/nonexistent")).is_err());
    }
}
