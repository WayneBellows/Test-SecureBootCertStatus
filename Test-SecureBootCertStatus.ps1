#Requires -Version 5.1
<#
.SYNOPSIS
    Checks whether a Windows host (AVD session host, Windows 365 Cloud PC, or
    physical/virtual server) has transitioned from the 2011 Secure Boot
    certificate authorities to the 2023 CAs before the 2011 certificates expire.

.DESCRIPTION
    Microsoft's 2011 Secure Boot certificates begin expiring in June 2026
    (KEK CA 2011 and UEFI CA 2011) with the Windows Production PCA 2011
    following in October 2026. A host that hasn't received the 2023 CAs keeps
    booting, but stops receiving boot-level security updates (Boot Manager,
    Secure Boot DB/DBX, revocations). The symptom, when it bites, looks like a
    different problem: failed boots, BitLocker recovery loops, or updates that
    silently stop applying.

    This script reads the actual UEFI Secure Boot variables (the ground truth),
    cross-checks the UEFICA2023Status registry signal and the System event log,
    and reports a per-host verdict so you can find the stragglers in a host pool
    before they fail.

    It is READ-ONLY. It does not modify firmware, certificates, or registry.
    It does not deploy the 2023 certificates -for that, follow Microsoft's
    Secure Boot playbook (link in the .LINK section) via Intune, Group Policy,
    or OEM firmware updates.

.PARAMETER ComputerName
    One or more remote hosts to check via PowerShell remoting (WinRM). Reading
    UEFI variables happens locally on each host, so remote checks run the same
    logic inside an Invoke-Command session. Omit to check the local machine.
    For an AVD host pool, pass the session host names (see .EXAMPLE).

.PARAMETER Credential
    Optional credential for the remote sessions.

.PARAMETER OutputHtml
    Optional path to write a self-contained HTML report with a traffic-light
    status per host. Mirrors the style of AVD-Assess.

.EXAMPLE
    .\Test-SecureBootCertStatus.ps1
    Checks the local machine and prints the result object.

.EXAMPLE
    $hosts = (Get-AzWvdSessionHost -ResourceGroupName rg-avd -HostPoolName hp-prod).Name |
             ForEach-Object { ($_ -split '/')[-1] }
    .\Test-SecureBootCertStatus.ps1 -ComputerName $hosts -OutputHtml .\secureboot-report.html
    Fans out across every session host in an AVD host pool and writes an HTML report.

.NOTES
    Author : (your name)
    License : MIT
    Verified against Microsoft Learn guidance (June 2026):
      - Update Secure Boot Certificates for Windows Devices
      - Troubleshooting Windows Server Secure Boot certificate update issues
    The certificate detection works by scanning the raw DB/KEK UEFI variables for
    the certificate common names. This is a pragmatic check, not a full ASN.1
    parse -it answers "is the 2023 CA present in the firmware database yet?".

.LINK
    https://learn.microsoft.com/troubleshoot/windows-client/windows-security/update-secure-boot-certificates
.LINK
    https://techcommunity.microsoft.com/blog/windows-itpro-blog/secure-boot-playbook-for-certificates-expiring-in-2026/4469235
#>
[CmdletBinding()]
param(
    [string[]] $ComputerName,
    [System.Management.Automation.PSCredential] $Credential,
    [string] $OutputHtml
)

# This scriptblock runs on each target host (local or remote). It must be
# self-contained because it is shipped into an Invoke-Command session.
$checker = {

    # Certificate common names. 2011 = expiring, 2023 = the replacements.
    $certs2011 = @(
        'Microsoft Corporation KEK CA 2011',      # KEK,  expires June 2026
        'Microsoft Corporation UEFI CA 2011',     # DB,   expires June 2026
        'Microsoft Windows Production PCA 2011'    # DB,   expires Oct  2026
    )
    $kek2023   = 'Microsoft Corporation KEK 2K CA 2023'
    $db2023    = @(
        'Windows UEFI CA 2023',                   # signs the Windows boot loader
        'Microsoft UEFI CA 2023',                 # signs third-party boot loaders
        'Microsoft Option ROM UEFI CA 2023'       # signs third-party option ROMs
    )

    $result = [ordered]@{
        ComputerName       = $env:COMPUTERNAME
        Verdict            = 'Unknown'
        IsUefi             = $false
        SecureBootEnabled  = $null
        Kek2023Present     = $false
        Db2023Present      = @()
        Db2023Missing      = @()
        Legacy2011Present  = @()
        UefiCa2023Status   = $null
        EventSignals       = @()
        Detail             = $null
    }

    # Reading firmware variables needs an elevated, UEFI-booted session.
    function Get-UefiVarString {
        param([string] $Name)
        try {
            $var = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
            if (-not $var -or -not $var.Bytes) { return $null }
            # Strip null bytes so wide-char CNs become searchable, then decode
            # the remaining bytes as Latin1 so every byte maps to a character.
            $bytes = $var.Bytes | Where-Object { $_ -ne 0 }
            return [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($bytes)
        }
        catch {
            return $null
        }
    }

    # 1. Is Secure Boot even available / on?
    #    Confirm-SecureBootUEFI throws in two distinct cases we must not conflate:
    #    a privilege error when the session isn't elevated, versus a genuine
    #    "not a UEFI system" on legacy BIOS. Treat the former as inconclusive.
    try {
        $result.SecureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
        $result.IsUefi = $true
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'privilege|elevat|denied|administrat') {
            $result.Verdict = 'Inconclusive'
            $result.Detail  = 'Secure Boot state needs an elevated session to read. Re-run as Administrator (or deploy as an Intune remediation, which runs as SYSTEM).'
            return [pscustomobject]$result
        }
        # Otherwise this is a legacy BIOS / non-UEFI host.
        $result.IsUefi = $false
        $result.Verdict = 'NotApplicable'
        $result.Detail  = 'Not a UEFI system. Secure Boot certificate updates do not apply.'
        return [pscustomobject]$result
    }

    # 2. Read the DB and KEK firmware variables (ground truth).
    $dbString  = Get-UefiVarString -Name 'db'
    $kekString = Get-UefiVarString -Name 'KEK'
    $haystack  = "$kekString`n$dbString"

    if (-not $dbString -and -not $kekString) {
        $result.Verdict = 'Inconclusive'
        $result.Detail  = 'Could not read DB/KEK UEFI variables. Run elevated (Administrator) on a UEFI host.'
        return [pscustomobject]$result
    }

    # 3. Match certificate CNs present in the firmware databases.
    $result.Kek2023Present    = $haystack -match [regex]::Escape($kek2023)
    $result.Db2023Present     = @($db2023 | Where-Object { $haystack -match [regex]::Escape($_) })
    $result.Db2023Missing     = @($db2023 | Where-Object { $haystack -notmatch [regex]::Escape($_) })
    $result.Legacy2011Present = @($certs2011 | Where-Object { $haystack -match [regex]::Escape($_) })

    # 4. Registry signal Microsoft surfaces: UEFICA2023Status should be 'Updated'.
    foreach ($path in @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
    )) {
        try {
            $val = Get-ItemProperty -Path $path -Name 'UEFICA2023Status' -ErrorAction Stop
            if ($null -ne $val.UEFICA2023Status) {
                $result.UefiCa2023Status = [string]$val.UEFICA2023Status
                break
            }
        }
        catch { }
    }

    # 5. Secure Boot servicing events (1795 / 1801). Informational only -these
    #    relate to certificate servicing and can appear on healthy, fully-updated
    #    hosts too (confirmed on a managed Windows 365 Cloud PC), so they
    #    corroborate rather than determine the verdict. The DB is the ground truth.
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1795, 1801 } -MaxEvents 5 -ErrorAction Stop
        $result.EventSignals = @($events | ForEach-Object { "Event $($_.Id) @ $($_.TimeCreated.ToString('s'))" })
    }
    catch { }

    # 6. Verdict, driven purely by the firmware DB/KEK (ground truth). The two
    #    load-bearing CAs for a Windows host are the KEK 2K CA 2023 (so firmware
    #    keeps receiving DB/DBX updates) and the Windows UEFI CA 2023 (signs
    #    future Windows boot managers). The Microsoft UEFI CA 2023 and Option ROM
    #    UEFI CA 2023 only matter if the host boots third-party / non-Windows
    #    loaders or option ROMs, which a Cloud PC or locked-down session host
    #    typically does not. The UEFICA2023Status registry value is NOT used to
    #    gate the verdict: it is absent on managed Cloud PCs whose firmware
    #    already holds the 2023 CAs, so trusting it would produce false negatives.
    $hasBootLoaderCa   = $haystack -match [regex]::Escape('Windows UEFI CA 2023')
    $thirdPartyMissing = @('Microsoft UEFI CA 2023', 'Microsoft Option ROM UEFI CA 2023') |
                         Where-Object { $haystack -notmatch [regex]::Escape($_) }

    if ($hasBootLoaderCa -and $result.Kek2023Present) {
        $result.Verdict = 'Compliant'
        $result.Detail  = 'KEK 2K CA 2023 and Windows UEFI CA 2023 present. The Windows boot path is covered for the 2026 expiry.'
        if ($thirdPartyMissing) {
            $result.Detail += " Third-party CA(s) not in DB ($($thirdPartyMissing -join ', ')) -only relevant if this host boots non-Windows loaders or option ROMs."
        }
    }
    elseif ($result.Kek2023Present -or $result.Db2023Present.Count -gt 0) {
        $result.Verdict = 'InProgress'
        $result.Detail  = "Partial 2023 rollout. Present: $($result.Db2023Present -join ', '). Still missing the Windows UEFI CA 2023 and/or KEK 2023 -re-check after the next servicing reboot, or deploy via Intune/GPO/firmware."
    }
    else {
        $result.Verdict = 'ActionRequired'
        $result.Detail  = 'No 2023 Secure Boot CAs detected. This host is still on the 2011 certificates and will stop receiving boot-level security updates once they expire. Deploy the 2023 CAs.'
    }

    return [pscustomobject]$result
}

# --- Execution: local or fan-out across hosts -------------------------------

$results = @()
if ($ComputerName) {
    $icmParams = @{
        ComputerName = $ComputerName
        ScriptBlock  = $checker
        ErrorAction  = 'SilentlyContinue'
    }
    if ($Credential) { $icmParams.Credential = $Credential }

    $results = Invoke-Command @icmParams |
               Select-Object * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName

    # Surface hosts that failed to respond so they aren't silently missed.
    $responded = $results.ComputerName
    foreach ($name in $ComputerName) {
        if ($name -notin $responded -and $name.Split('.')[0] -notin $responded) {
            $results += [pscustomobject]@{
                ComputerName = $name; Verdict = 'Unreachable'
                Detail = 'No WinRM response. Check the host is running and remoting is enabled.'
            }
        }
    }
}
else {
    $results = & $checker
}

# --- Console output ---------------------------------------------------------

$colorMap = @{
    Compliant = 'Green'; InProgress = 'Yellow'; ActionRequired = 'Red'
    Unreachable = 'DarkGray'; NotApplicable = 'DarkGray'; Inconclusive = 'Yellow'; Unknown = 'DarkGray'
}
foreach ($r in $results) {
    $c = if ($colorMap.ContainsKey([string]$r.Verdict)) { $colorMap[[string]$r.Verdict] } else { 'Gray' }
    Write-Host ("[{0,-14}] {1}" -f $r.Verdict, $r.ComputerName) -ForegroundColor $c
    if ($r.Detail) { Write-Host ("                 {0}" -f $r.Detail) -ForegroundColor DarkGray }
}

$summary = $results | Group-Object Verdict | ForEach-Object { "$($_.Name): $($_.Count)" }
Write-Host "`nSummary: $($summary -join '  |  ')" -ForegroundColor Cyan

# --- Optional HTML report ---------------------------------------------------

if ($OutputHtml) {
    $badge = {
        param($v)
        $bg = switch ($v) {
            'Compliant'      { '#2e7d32' }
            'InProgress'     { '#f9a825' }
            'ActionRequired' { '#c62828' }
            default          { '#616161' }
        }
        "<span style='background:$bg;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>$v</span>"
    }
    $rows = foreach ($r in $results) {
        $db = if ($r.Db2023Present) { ($r.Db2023Present -join '<br>') } else { '-' }
        @"
<tr>
  <td>$($r.ComputerName)</td>
  <td>$(& $badge $r.Verdict)</td>
  <td>$($r.SecureBootEnabled)</td>
  <td>$($r.Kek2023Present)</td>
  <td>$db</td>
  <td>$($r.UefiCa2023Status)</td>
  <td style='color:#555'>$($r.Detail)</td>
</tr>
"@
    }
    $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>Secure Boot 2023 CA Readiness</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}
h1{font-size:20px} .meta{color:#666;font-size:13px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
th{background:#f4f4f4}
</style></head><body>
<h1>Secure Boot 2023 CA Readiness</h1>
<div class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; 2011 certificates expire June&ndash;October 2026 &middot; read-only check</div>
<table>
<tr><th>Host</th><th>Verdict</th><th>Secure Boot</th><th>KEK 2023</th><th>DB 2023 CAs present</th><th>UEFICA2023Status</th><th>Detail</th></tr>
$($rows -join "`n")
</table>
<p class='meta'>Remediation guidance: Microsoft Secure Boot playbook for certificates expiring in 2026.</p>
</body></html>
"@
    $html | Out-File -FilePath $OutputHtml -Encoding utf8
    Write-Host "HTML report written to $OutputHtml" -ForegroundColor Cyan
}

# Emit objects so the script composes with the pipeline / further filtering.
$results
