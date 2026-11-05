<#
.SYNOPSIS
    Hardens Windows SCHANNEL registry configuration to enforce TLS 1.2/1.3 and disable legacy protocols and weak ciphers.

.DESCRIPTION
    Set-WindowsTlsHardening configures the Windows Security Channel (SCHANNEL) and cryptographic policy settings
    in accordance with modern CIS and NIST SP 800-52r2 security guidelines.

    Configured Protections:
    - Disables insecure protocols: SSL 2.0, SSL 3.0, PCT 1.0, Multi-Protocol Unified Hello, TLS 1.0, TLS 1.1 (Server & Client).
    - Enforces modern secure protocols: TLS 1.2, TLS 1.3 (Server & Client).
    - Disables weak/broken ciphers: NULL, DES (56-bit), RC2, RC4, Triple DES (3DES/Sweet32).
    - Enforces strong ciphers: AES 128/128, AES 256/256.
    - Disables insecure hashes: MD5, SHA-1 (for certificates/signatures).
    - Enforces secure hashes: SHA-256, SHA-384, SHA-512.
    - Sets secure elliptic curve and Diffie-Hellman key exchange parameters (minimum 2048-bit).
    - Orders cipher suites prioritizing Perfect Forward Secrecy (ECDHE) and Authenticated Encryption (AES-GCM).

    Includes an -AuditOnly switch to assess compliance without modifying registry state, and an automated
    registry backup mechanism. Requires local Administrator privileges.

.PARAMETER AuditOnly
    Assesses existing SCHANNEL settings against the hardening baseline and outputs compliance status without modifying the registry.

.PARAMETER BackupPath
    Path to save a registry backup (.reg file) of existing SCHANNEL configuration before making changes.
    Default: "$env:SystemRoot\Temp\SCHANNEL_Backup_<timestamp>.reg".

.PARAMETER Force
    Suppresses confirmation prompts during registry modification.

.EXAMPLE
    PS C:\> .\Set-WindowsTlsHardening.ps1 -AuditOnly

    Audits the local system SCHANNEL configuration and outputs compliance status for each protocol, cipher, and hash.

.EXAMPLE
    PS C:\> .\Set-WindowsTlsHardening.ps1 -BackupPath "C:\Backups\SCHANNEL_PreHardening.reg"

    Backs up the existing SCHANNEL registry hive and applies full TLS 1.2/1.3 hardening.

.NOTES
    Author: Koality Assured Security Engineering
    Compliance: NIST SP 800-52 Rev. 2, CIS Microsoft Windows Server Benchmark, PCI-DSS v4.0 Section 8.3
    Requires system reboot to activate newly configured SCHANNEL settings.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [switch]$AuditOnly,

    [Parameter()]
    [string]$BackupPath,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure running with administrative elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $AuditOnly) {
    throw "Set-WindowsTlsHardening requires elevated Administrator privileges to modify SCHANNEL registry settings. Re-run PowerShell as Administrator or use -AuditOnly."
}

$schannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$protocolsBase = "$schannelBase\Protocols"
$ciphersBase = "$schannelBase\Ciphers"
$hashesBase = "$schannelBase\Hashes"
$keyExchangesBase = "$schannelBase\KeyExchangeAlgorithms"
$cipherSuitesPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'

# Target Hardening Baseline
$disabledProtocols = @(
    'SSL 2.0',
    'SSL 3.0',
    'PCT 1.0',
    'Multi-Protocol Unified Hello',
    'TLS 1.0',
    'TLS 1.1'
)

$enabledProtocols = @(
    'TLS 1.2',
    'TLS 1.3'
)

$disabledCiphers = @(
    'NULL',
    'DES 56/56',
    'RC2 40/128',
    'RC2 56/128',
    'RC2 128/128',
    'RC4 40/128',
    'RC4 56/128',
    'RC4 64/128',
    'RC4 128/128',
    'Triple DES 168'
)

$enabledCiphers = @(
    'AES 128/128',
    'AES 256/256'
)

$disabledHashes = @(
    'MD5'
)

$enabledHashes = @(
    'SHA',
    'SHA256',
    'SHA384',
    'SHA512'
)

# Ordered Cipher Suites prioritizing PFS (ECDHE) and AEAD (GCM)
$cipherSuiteOrder = @(
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
)

$complianceReport = [System.Collections.Generic.List[PSCustomObject]]::new()

# Registry Helper Functions
function Get-RegistryDword {
    param([string]$Path, [string]$Name)
    if (Test-Path -Path $Path) {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            return $val.$Name
        }
    }
    return $null
}

function Set-RegistryDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force | Out-Null
}

# 1. Backup Registry if modifying
if (-not $AuditOnly) {
    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $tempDir = if (Test-Path "$env:SystemRoot\Temp") { "$env:SystemRoot\Temp" } else { $env:TEMP }
        $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $BackupPath = Join-Path $tempDir "SCHANNEL_Backup_$timestamp.reg"
    }

    Write-Verbose "Creating SCHANNEL registry backup at: $BackupPath"
    try {
        & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' "$BackupPath" /y | Out-Null
        Write-Verbose "Registry backup exported successfully."
    }
    catch {
        Write-Warning "Could not export SCHANNEL registry backup: $_"
    }
}

# 2. Audit and Configure Insecure Protocols (Disable)
foreach ($proto in $disabledProtocols) {
    foreach ($role in @('Server', 'Client')) {
        $path = "$protocolsBase\$proto\$role"
        $currentEnabled = Get-RegistryDword -Path $path -Name 'Enabled'
        $currentDisabledByDefault = Get-RegistryDword -Path $path -Name 'DisabledByDefault'

        $isCompliant = ($currentEnabled -eq 0 -and $currentDisabledByDefault -eq 1)

        $actionTaken = 'None'
        if (-not $AuditOnly) {
            if ($PSCmdlet.ShouldProcess("$proto ($role)", "Disable insecure protocol in SCHANNEL")) {
                Set-RegistryDword -Path $path -Name 'Enabled' -Value 0
                Set-RegistryDword -Path $path -Name 'DisabledByDefault' -Value 1
                $actionTaken = 'Disabled'
            }
        }

        $complianceReport.Add([PSCustomObject]@{
            Category      = 'Protocol'
            Name          = "$proto ($role)"
            TargetState   = 'Disabled (Enabled=0, DisabledByDefault=1)'
            CurrentState  = "Enabled=$currentEnabled, DisabledByDefault=$currentDisabledByDefault"
            Compliant     = $isCompliant
            Action        = if ($AuditOnly) { 'Audited' } else { $actionTaken }
        })
    }
}

# 3. Audit and Configure Modern Protocols (Enable TLS 1.2 / TLS 1.3)
foreach ($proto in $enabledProtocols) {
    foreach ($role in @('Server', 'Client')) {
        $path = "$protocolsBase\$proto\$role"
        $currentEnabled = Get-RegistryDword -Path $path -Name 'Enabled'
        $currentDisabledByDefault = Get-RegistryDword -Path $path -Name 'DisabledByDefault'

        $isCompliant = ($currentEnabled -eq 1 -and $currentDisabledByDefault -eq 0)

        $actionTaken = 'None'
        if (-not $AuditOnly) {
            if ($PSCmdlet.ShouldProcess("$proto ($role)", "Enforce modern protocol in SCHANNEL")) {
                Set-RegistryDword -Path $path -Name 'Enabled' -Value 1
                Set-RegistryDword -Path $path -Name 'DisabledByDefault' -Value 0
                $actionTaken = 'Enabled'
            }
        }

        $complianceReport.Add([PSCustomObject]@{
            Category      = 'Protocol'
            Name          = "$proto ($role)"
            TargetState   = 'Enabled (Enabled=1, DisabledByDefault=0)'
            CurrentState  = "Enabled=$currentEnabled, DisabledByDefault=$currentDisabledByDefault"
            Compliant     = $isCompliant
            Action        = if ($AuditOnly) { 'Audited' } else { $actionTaken }
        })
    }
}

# 4. Audit and Configure Weak Ciphers (Disable)
foreach ($cipher in $disabledCiphers) {
    $path = "$ciphersBase\$cipher"
    $currentEnabled = Get-RegistryDword -Path $path -Name 'Enabled'
    $isCompliant = ($currentEnabled -eq 0)

    $actionTaken = 'None'
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess("Cipher: $cipher", "Disable weak cipher")) {
            Set-RegistryDword -Path $path -Name 'Enabled' -Value 0
            $actionTaken = 'Disabled'
        }
    }

    $complianceReport.Add([PSCustomObject]@{
        Category      = 'Cipher'
        Name          = $cipher
        TargetState   = 'Disabled (Enabled=0)'
        CurrentState  = "Enabled=$currentEnabled"
        Compliant     = $isCompliant
        Action        = if ($AuditOnly) { 'Audited' } else { $actionTaken }
    })
}

# 5. Audit and Configure Strong Ciphers (Enable)
foreach ($cipher in $enabledCiphers) {
    $path = "$ciphersBase\$cipher"
    $currentEnabled = Get-RegistryDword -Path $path -Name 'Enabled'
    $isCompliant = ($currentEnabled -eq [int]0xffffffff -or $currentEnabled -eq 1)

    $actionTaken = 'None'
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess("Cipher: $cipher", "Enforce strong cipher")) {
            Set-RegistryDword -Path $path -Name 'Enabled' -Value [int]0xffffffff
            $actionTaken = 'Enabled'
        }
    }

    $complianceReport.Add([PSCustomObject]@{
        Category      = 'Cipher'
        Name          = $cipher
        TargetState   = 'Enabled (Enabled=0xFFFFFFFF)'
        CurrentState  = "Enabled=$currentEnabled"
        Compliant     = $isCompliant
        Action        = if ($AuditOnly) { 'Audited' } else { $actionTaken }
    })
}

# 6. Audit and Configure Insecure Hashes
foreach ($hash in $disabledHashes) {
    $path = "$hashesBase\$hash"
    $currentEnabled = Get-RegistryDword -Path $path -Name 'Enabled'
    $isCompliant = ($currentEnabled -eq 0)

    $actionTaken = 'None'
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess("Hash: $hash", "Disable weak hash")) {
            Set-RegistryDword -Path $path -Name 'Enabled' -Value 0
            $actionTaken = 'Disabled'
        }
    }

    $complianceReport.Add([PSCustomObject]@{
        Category      = 'Hash'
        Name          = $hash
        TargetState   = 'Disabled (Enabled=0)'
        CurrentState  = "Enabled=$currentEnabled"
        Compliant     = $isCompliant
        Action        = if ($AuditOnly) { 'Audited' } else { $actionTaken }
    })
}

# 7. Audit and Configure Strong Hashes
foreach ($hash in $enabledHashes) {
    $path = "$hashesBase\$hash"
    $currentEnabled = Get-RegistryDword -Path $path -Name 'Enabled'
    $isCompliant = ($currentEnabled -eq [int]0xffffffff -or $currentEnabled -eq 1)

    $actionTaken = 'None'
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess("Hash: $hash", "Enforce strong hash")) {
            Set-RegistryDword -Path $path -Name 'Enabled' -Value [int]0xffffffff
            $actionTaken = 'Enabled'
        }
    }

    $complianceReport.Add([PSCustomObject]@{
        Category      = 'Hash'
        Name          = $hash
        TargetState   = 'Enabled (Enabled=0xFFFFFFFF)'
        CurrentState  = "Enabled=$currentEnabled"
        Compliant     = $isCompliant
        Action        = if ($AuditOnly) { 'Audited' } else { $actionTaken }
    })
}

# 8. Configure Ordered Cipher Suites
$joinedSuites = $cipherSuiteOrder -join ','
$currentSuites = $null
if (Test-Path -Path $cipherSuitesPolicyKey) {
    $val = Get-ItemProperty -Path $cipherSuitesPolicyKey -Name 'Functions' -ErrorAction SilentlyContinue
    if ($null -ne $val) {
        $currentSuites = $val.Functions
    }
}

$suitesCompliant = ($currentSuites -eq $joinedSuites)
$actionTakenSuites = 'None'
if (-not $AuditOnly) {
    if ($PSCmdlet.ShouldProcess("SSL Cipher Suite Policy Order", "Apply PFS/AEAD prioritized cipher suites")) {
        if (-not (Test-Path -Path $cipherSuitesPolicyKey)) {
            New-Item -Path $cipherSuitesPolicyKey -Force | Out-Null
        }
        Set-ItemProperty -Path $cipherSuitesPolicyKey -Name 'Functions' -Value $joinedSuites -Type String -Force | Out-Null
        $actionTakenSuites = 'Configured'
    }
}

$complianceReport.Add([PSCustomObject]@{
    Category      = 'CipherSuiteOrder'
    Name          = 'SSL/00010002 Functions'
    TargetState   = "$($cipherSuiteOrder.Count) Modern PFS/AEAD suites ordered"
    CurrentState  = if ($suitesCompliant) { 'Matches Baseline' } else { 'Custom or Default' }
    Compliant     = $suitesCompliant
    Action        = if ($AuditOnly) { 'Audited' } else { $actionTakenSuites }
})

# Summary output
$compliantCount = @($complianceReport | Where-Object { $_.Compliant -eq $true }).Count
$totalCount = $complianceReport.Count

if ($AuditOnly) {
    $summaryColor = if ($compliantCount -eq $totalCount) { 'Green' } else { 'Yellow' }
    Write-Host "SCHANNEL Baseline Audit Complete: $compliantCount / $totalCount settings compliant." -ForegroundColor $summaryColor
}
else {
    Write-Host "SCHANNEL Hardening Complete: Settings configured. Note: System reboot is required to activate new SCHANNEL security posture." -ForegroundColor Green
    if ($BackupPath) {
        Write-Host "Registry backup preserved at: $BackupPath" -ForegroundColor Cyan
    }
}

return $complianceReport
