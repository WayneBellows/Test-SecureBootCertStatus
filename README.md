# Test-SecureBootCertStatus

A free, read-only PowerShell checker that tells you which of your Windows hosts — AVD session hosts, Windows 365 Cloud PCs, or servers — still need the **2023 Secure Boot certificates** before the **2011 certificates expire in 2026**.

## Why this exists

Microsoft's 2011 Secure Boot certificate authorities start expiring in **June 2026** (KEK CA 2011, UEFI CA 2011), with the Windows Production PCA 2011 following in **October 2026**. A host that hasn't received the 2023 CAs keeps booting — but stops getting boot-level security updates (Boot Manager, Secure Boot DB/DBX, revocations). When it eventually bites, it looks like a different problem: failed boots, BitLocker recovery loops, or updates that quietly stop applying.

The hard part isn't fixing it. It's finding the stragglers across a host pool before they fail. This does that.

## What it checks

For each host it reads the **actual UEFI Secure Boot variables** (the ground truth), then cross-checks two corroborating signals:

- **DB / KEK firmware variables (the verdict driver)** — are the `Microsoft Corporation KEK 2K CA 2023` and `Windows UEFI CA 2023` (the two load-bearing CAs for a Windows host) present yet? The `Microsoft UEFI CA 2023` and `Option ROM UEFI CA 2023` are also reported, but they only matter for hosts that boot third-party / non-Windows loaders — a Cloud PC or locked-down session host usually doesn't.
- **Registry** — `UEFICA2023Status` is reported for context but does **not** gate the verdict. On managed Windows 365 Cloud PCs this value is often empty even when the 2023 CAs are genuinely present in firmware, so trusting it would flag compliant hosts as failing.
- **System event log** — Event IDs `1795` / `1801` are surfaced as corroborating signals only. They relate to Secure Boot certificate servicing and can appear on healthy, fully-updated hosts, so they don't determine the result on their own.

It returns a per-host verdict: **Compliant**, **InProgress**, **ActionRequired**, plus **Inconclusive** (run elevated) / **NotApplicable** (legacy BIOS) / **Unreachable**.

Verdict logic is grounded in real firmware: validated against a managed Windows 365 Cloud PC (Secure Boot on, KEK 2023 + Windows UEFI CA 2023 present, registry value empty, 1795/1801 events present on a healthy host).

It is **read-only**. It does not modify firmware, certificates, or the registry, and it does not deploy the 2023 certificates. For remediation, follow Microsoft's Secure Boot playbook (linked below) via Intune, Group Policy, or OEM firmware.

## Usage

Run elevated (reading UEFI variables requires Administrator):

```powershell
# Local host
.\Test-SecureBootCertStatus.ps1

# Whole AVD host pool, with an HTML report
$hosts = (Get-AzWvdSessionHost -ResourceGroupName rg-avd -HostPoolName hp-prod).Name |
         ForEach-Object { ($_ -split '/')[-1] }
.\Test-SecureBootCertStatus.ps1 -ComputerName $hosts -OutputHtml .\secureboot-report.html
```

Or deploy the host-check logic as an **Intune remediation** (runs as SYSTEM, so it's elevated and inventories your whole fleet).

## Requirements

- PowerShell 5.1+
- Administrator (local) or WinRM + credentials (remote fan-out)
- `Az.DesktopVirtualization` only if you use the host-pool enumeration example

## Sources

- [Update Secure Boot Certificates for Windows Devices](https://learn.microsoft.com/troubleshoot/windows-client/windows-security/update-secure-boot-certificates)
- [Troubleshooting Windows Server Secure Boot certificate update issues](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/troubleshoot-windows-server-secure-boot-certificate-update-issues)
- [Secure Boot playbook for certificates expiring in 2026](https://techcommunity.microsoft.com/blog/windows-itpro-blog/secure-boot-playbook-for-certificates-expiring-in-2026/4469235)

## License

MIT. No warranty — validate on a pilot ring before acting on results in production.
