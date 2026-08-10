# Security Policy

## Reporting a Vulnerability

We take the security of ClamGuard seriously. If you believe you have found a security
vulnerability, please report it to us as described below.

### Primary Method: GitHub Security Advisories (Preferred)

**Please report security vulnerabilities using [GitHub Security Advisories](https://github.com/D3M-Sudo/ClamGuard/security/advisories/new).**

This is the preferred method as it allows for:

- Private disclosure and discussion
- Coordinated vulnerability disclosure
- CVE assignment through GitHub
- Draft security advisories before public disclosure

### Secondary Method: Email

If you prefer not to use GitHub Security Advisories, you can email security reports to:

**d3m-sudo@users.noreply.github.com**

Please include:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (if available)

## Supported Versions

ClamGuard is currently in early development. Security updates are provided for:

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅         |

As the project matures, this policy will be updated to reflect long-term support commitments.

## What to Report

Please report any security vulnerabilities including but not limited to:

### High Priority

- **Command Injection**: Improper sanitization of paths or user input passed to shell commands
  (`clamscan`/`clamdscan`, `pkexec`, `flatpak-spawn`)
- **Path Traversal**: Ability to access or write files outside intended directories
- **Privilege Escalation**: Unauthorized elevation of permissions via the Polkit-elevated helper
- **Information Disclosure**: Exposure of sensitive data (VirusTotal API keys, scan results,
  quarantined file contents, system information)
- **Arbitrary Code Execution**: Ability to execute unauthorized code, including via crafted
  third-party signature databases

### Medium Priority

- **Denial of Service**: Crashes or resource exhaustion
- **Log Injection**: Ability to inject malicious content into logs
- **Symlink Attacks**: Improper handling of symbolic links during scanning or quarantine
- **Race Conditions**: Time-of-check to time-of-use (TOCTOU) vulnerabilities, e.g. between
  scan-result reporting and quarantine placement
- **Insecure Cryptography**: Weaknesses in the optional quarantine encryption (key derivation,
  key storage, ciphertext handling)

### Areas of Concern

- ClamAV invocation and result parsing (`src/core/clamav.py`)
- Privileged signature-install helper and its path allow-list
  (`src/core/privileged_paths.py`, `src/cli/install_helper.py`)
- Polkit elevation (`src/services/polkit.py`)
- Third-party signature download, hash verification, and staging
  (`src/core/third_party_db.py`)
- Quarantine file handling and encryption (`src/core/quarantine.py`)
- API key storage via SecretService/libsecret (`src/services/credentials.py`)
- Background daemon entry points invoked by systemd units
  (`src/daemon/updater_daemon.py`, `src/daemon/scheduler_daemon.py`, `src/daemon/cli.py`)
- Flatpak sandbox permissions and host command spawning
  (`io.github.d3msudo.clamguard.json`)

## What NOT to Report

The following are **not** considered security vulnerabilities:

- ClamAV detection capabilities (report to the [ClamAV project](https://www.clamav.net/documents/security))
- False positives/negatives from virus scans
- UI/UX issues without security impact
- Performance issues without DoS potential
- Issues requiring physical access to an unlocked system

## Disclosure Process

1. **Report Received**: We aim to acknowledge receipt within 48 hours
2. **Initial Assessment**: We will assess the severity and impact within 7 days
3. **Coordinated Disclosure**: We will work with you to understand and fix the issue
4. **Fix Development**: We will develop and test a fix
5. **Release**: We will release a patched version
6. **Public Disclosure**: After users have had time to update (typically 7-14 days), we will
   publicly disclose the vulnerability

## Security Best Practices

When using ClamGuard:

- **Keep Updated**: Always use the latest version of ClamGuard and ClamAV
- **Limit Permissions**: Run ClamGuard with minimal necessary permissions; only the third-party
  signature installer requires elevation, via Polkit
- **Validate Sources**: Only scan files from trusted sources when possible
- **Secure API Keys**: Rely on the built-in SecretService keyring storage for the VirusTotal API
  key rather than any plaintext alternative
- **Enable Quarantine Encryption**: Turn on the optional AES-256-GCM quarantine encryption for
  an extra layer of isolation on shared or multi-user systems
- **Review Third-Party Providers**: Only enable signature providers you trust; each is fetched
  and hash-verified independently before being staged for installation
- **Monitor Logs**: Check scan and daemon logs (`journalctl -u clamguard-updater.service`,
  `-u clamguard-scheduled-scan.service`) for suspicious activity

## Security Features

ClamGuard implements several security measures:

- **Zero-Privilege UI**: The main application never runs as root; elevated operations are
  delegated to a dedicated helper via Polkit `pkexec`
- **Destination Allow-Listing**: The privileged helper writes only inside `/var/lib/clamav`,
  validated against a fixed allow-list (`src/core/privileged_paths.py`) — no nested subdirectories,
  no arbitrary destinations
- **Signature Verification**: Third-party signature databases are hash-verified and
  test-loaded with `clamscan` before being staged for privileged installation, with atomic
  rollback on failure
- **Quarantine Integrity**: SHA-256 verification for all quarantined files, with optional
  AES-256-GCM encryption
- **Secure Storage**: VirusTotal API keys are stored in the system keyring
  (GNOME Keyring, KWallet) via SecretService — never in plaintext configuration
- **Flatpak Sandboxing**: Minimal `finish-args`, read-only filesystem access to ClamAV data
  directories, and `flatpak-spawn --host` (rather than `filesystem=host`) for the operations
  that must reach the host

## Contact

- **Security Issues**: [GitHub Security Advisories](https://github.com/D3M-Sudo/ClamGuard/security/advisories)
  or d3m-sudo@users.noreply.github.com
- **General Issues**: [GitHub Issues](https://github.com/D3M-Sudo/ClamGuard/issues)
- **Project**: <https://github.com/D3M-Sudo/ClamGuard>

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [ClamAV Security](https://www.clamav.net/documents/security)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
