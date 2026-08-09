# ClamGuard — Modern ClamAV Security Suite for Linux

ClamGuard is a GTK4/libadwaita desktop security application integrating ClamAV,
VirusTotal API v3, third-party signature databases, quarantine management,
and system tray monitoring.

## Features
- **Bitdefender-style Dashboard** with prominent protection status
- **Async ClamAV Scanning** via clamd UNIX socket or clamscan fallback
- **Secure Quarantine** with SHA-256 integrity and optional AES-256-GCM encryption
- **VirusTotal API v3** with local SQLite cache and rate-limit handling
- **Third-Party Signatures** (Sanesecurity, URLhaus, Twinclams, ditekshen) with atomic updates
- **System Tray** integration (StatusNotifierItem / XApp fallback)
- **Zero-Privilege UI** — elevated operations via Polkit pkexec
- **SecretService** storage for API keys

## Building

### Meson (native)
```bash
meson setup build
meson compile -C build
sudo meson install -C build
```

### Flatpak
```bash
flatpak-builder --repo=repo build io.github.d3msudo.clamguard.json
```

### Debian
```bash
dpkg-buildpackage -us -uc -b
```

## License
GPL-3.0+
