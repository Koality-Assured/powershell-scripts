<#
.SYNOPSIS
    Compares installed Windows updates and hotfixes across a server fleet to identify missing patches and compliance drift.

.DESCRIPTION
    Compare-WindowsHotfixes audits QuickFixEngineering (QFE) updates across local and remote Windows systems
    using high-performance CIM sessions. It establishes a multi-system hotfix matrix, identifying patches installed
    across the fleet, highlighting systems missing critical security updates, and evaluating drift against an optional
    reference baseline host.

    Features:
    - Pure headless execution with pipeline support (no interactive GUI dialogs).
    - Modern CIM implementation (Win32_QuickFixEngineering) compatible with PowerShell 7+ and 5.1.
    - Multiple reporting formats: 'PatchSummary', 'Matrix', and 'HostDiscrepancy'.
    - Baseline delta analysis when a -ReferenceComputer is specified.
    - Automated structured exporting to CSV and JSON.

.PARAMETER ComputerName
    One or more hostnames or IP addresses to audit. Accepts pipeline input. Defaults to $env:COMPUTERNAME.

.PARAMETER ReferenceComputer
    Optional baseline computer name. When specified, discrepancies are evaluated relative to updates present on this host.

.PARAMETER MissingOnly
    When specified, filters output to only include hotfixes that are missing on at least one audited system.

.PARAMETER Format
    The presentation schema for output objects:
    - 'PatchSummary' (Default): Aggregates each HotFixID with installed/missing host lists and compliance percentage.
    - 'Matrix': Pivot table format with one row per hotfix and dynamic columns for each audited server.
    - 'HostDiscrepancy': System-centric view listing each host and all patches it lacks relative to the fleet or baseline.

.PARAMETER Credential
    PSCredential object containing administrative credentials for remote system querying.

.PARAMETER ExportCsv
    Optional file path to export hotfix analysis results to CSV.

.PARAMETER ExportJson
    Optional file path to export hotfix analysis results to JSON.

.EXAMPLE
    PS C:\> "SRV-WEB-01", "SRV-WEB-02", "SRV-WEB-03" | .\Compare-WindowsHotfixes.ps1 -MissingOnly

    Compares installed patches across three web servers and displays only hotfixes missing on one or more hosts.

.EXAMPLE
    PS C:\> .\Compare-WindowsHotfixes.ps1 -ComputerName "SRV-APP-01", "SRV-APP-02" -ReferenceComputer "SRV-GOLD-01" -Format HostDiscrepancy

    Identifies updates present on SRV-GOLD-01 that have not yet been installed on SRV-APP-01 or SRV-APP-02.

.NOTES
    Author: Koality Assured Systems Engineering
    Compliance: CIS Critical Security Control 7 (Continuous Vulnerability Management)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReferenceComputer,

    [Parameter()]
    [switch]$MissingOnly,

    [Parameter()]
    [ValidateSet('PatchSummary', 'Matrix', 'HostDiscrepancy')]
    [string]$Format = 'PatchSummary',

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

begin {
    Set-StrictMode -Version Latest
    $allTargetComputers = [System.Collections.Generic.List[string]]::new()
    $installedHotfixMap = @{} # Key: ComputerName, Value: HashSet of HotFixIDs
    $hotfixMetadataMap = @{}  # Key: HotFixID, Value: Description / InstalledOn
}

process {
    foreach ($comp in $ComputerName) {
        if (-not $allTargetComputers.Contains($comp)) {
            $allTargetComputers.Add($comp)
        }
    }
}

end {
    if (-not [string]::IsNullOrWhiteSpace($ReferenceComputer) -and -not $allTargetComputers.Contains($ReferenceComputer)) {
        $allTargetComputers.Insert(0, $ReferenceComputer)
    }

    Write-Verbose "Beginning hotfix collection across $($allTargetComputers.Count) target host(s)..."

    $reachableHosts = [System.Collections.Generic.List[string]]::new()
    $unreachableHosts = [System.Collections.Generic.List[string]]::new()
    $allDiscoveredHotfixIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($target in $allTargetComputers) {
        Write-Verbose "Querying Win32_QuickFixEngineering on [$target]..."
        $isLocal = ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost' -or $target -eq '127.0.0.1')

        try {
            $cimParams = @{
                ClassName   = 'Win32_QuickFixEngineering'
                ErrorAction = 'Stop'
            }

            if (-not $isLocal) {
                $cimParams['ComputerName'] = $target
                if ($null -ne $Credential) {
                    $cimParams['Credential'] = $Credential
                }
            }

            $hotfixRecords = Get-CimInstance @cimParams
            $hostHotfixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($hf in $hotfixRecords) {
                $rawId = $hf.HotFixID
                if ([string]::IsNullOrWhiteSpace($rawId)) {
                    continue
                }

                $cleanId = $rawId.Trim().ToUpper()
                [void]$hostHotfixSet.Add($cleanId)
                [void]$allDiscoveredHotfixIds.Add($cleanId)

                if (-not $hotfixMetadataMap.ContainsKey($cleanId)) {
                    $hotfixMetadataMap[$cleanId] = @{
                        Description = $hf.Description
                        InstalledOn = if ($hf.InstalledOn) { $hf.InstalledOn.ToString() } else { $null }
                    }
                }
            }

            $installedHotfixMap[$target] = $hostHotfixSet
            $reachableHosts.Add($target)
            Write-Verbose "Host [$target]: successfully collected $($hostHotfixSet.Count) hotfixes."
        }
        catch {
            Write-Warning "Failed to query hotfixes on host [$target]: $_"
            $unreachableHosts.Add($target)
        }
    }

    if ($reachableHosts.Count -eq 0) {
        Write-Error "No target systems were reachable to collect hotfix information."
        return
    }

    $sortedHotfixList = @($allDiscoveredHotfixIds) | Sort-Object
    $outputResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Mode 1: PatchSummary (Default)
    if ($Format -eq 'PatchSummary') {
        foreach ($hId in $sortedHotfixList) {
            $installedOn = [System.Collections.Generic.List[string]]::new()
            $missingFrom = [System.Collections.Generic.List[string]]::new()

            foreach ($h in $reachableHosts) {
                if ($installedHotfixMap[$h].Contains($hId)) {
                    $installedOn.Add($h)
                }
                else {
                    $missingFrom.Add($h)
                }
            }

            $installedCount = $installedOn.Count
            $totalReachable = $reachableHosts.Count
            $pctCompliant = [Math]::Round(($installedCount / $totalReachable) * 100, 1)

            if ($MissingOnly.IsPresent -and $missingFrom.Count -eq 0) {
                continue
            }

            $meta = $hotfixMetadataMap[$hId]

            $outputResults.Add([PSCustomObject]@{
                HotFixID            = $hId
                Description         = $meta.Description
                InstalledCount      = $installedCount
                MissingCount        = $missingFrom.Count
                FleetCoveragePct    = $pctCompliant
                InstalledHosts      = ($installedOn -join ', ')
                MissingHosts        = ($missingFrom -join ', ')
            })
        }
    }
    # Mode 2: Matrix (Pivot Grid)
    elseif ($Format -eq 'Matrix') {
        foreach ($hId in $sortedHotfixList) {
            $missingOnAny = $false
            $rowObj = [PSCustomObject]::new()
            $rowObj | Add-Member -MemberType NoteProperty -Name 'HotFixID' -Value $hId
            $rowObj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $hotfixMetadataMap[$hId].Description

            foreach ($h in $reachableHosts) {
                $status = if ($installedHotfixMap[$h].Contains($hId)) { 'Installed' } else { 'Missing' }
                if ($status -eq 'Missing') { $missingOnAny = $true }
                $rowObj | Add-Member -MemberType NoteProperty -Name $h -Value $status
            }

            if ($MissingOnly.IsPresent -and -not $missingOnAny) {
                continue
            }

            $outputResults.Add($rowObj)
        }
    }
    # Mode 3: HostDiscrepancy (Host-Centric Drift)
    elseif ($Format -eq 'HostDiscrepancy') {
        $referenceSet = $null
        if (-not [string]::IsNullOrWhiteSpace($ReferenceComputer) -and $installedHotfixMap.ContainsKey($ReferenceComputer)) {
            $referenceSet = $installedHotfixMap[$ReferenceComputer]
            Write-Verbose "Using [$ReferenceComputer] as authoritative baseline ($($referenceSet.Count) patches)."
        }

        foreach ($h in $reachableHosts) {
            if ($h -eq $ReferenceComputer) {
                continue
            }

            $currentHostSet = $installedHotfixMap[$h]
            $missingPatches = [System.Collections.Generic.List[string]]::new()

            if ($null -ne $referenceSet) {
                # Compare strictly against baseline
                foreach ($refPatch in $referenceSet) {
                    if (-not $currentHostSet.Contains($refPatch)) {
                        $missingPatches.Add($refPatch)
                    }
                }
            }
            else {
                # Compare against all hotfixes seen anywhere in fleet
                foreach ($fPatch in $sortedHotfixList) {
                    if (-not $currentHostSet.Contains($fPatch)) {
                        $missingPatches.Add($fPatch)
                    }
                }
            }

            if ($MissingOnly.IsPresent -and $missingPatches.Count -eq 0) {
                continue
            }

            $outputResults.Add([PSCustomObject]@{
                ComputerName     = $h
                InstalledCount   = $currentHostSet.Count
                MissingCount     = $missingPatches.Count
                MissingHotFixIDs = ($missingPatches -join ', ')
                BaselineHost     = if ($referenceSet) { $ReferenceComputer } else { 'FleetUnion' }
            })
        }
    }

    Write-Verbose "Completed hotfix analysis. Generated $($outputResults.Count) result records."

    if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
        Write-Verbose "Writing hotfix analysis to CSV: $ExportCsv"
        $outputResults | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
        Write-Verbose "Writing hotfix analysis to JSON: $ExportJson"
        $outputResults | ConvertTo-Json -Depth 4 | Set-Content -Path $ExportJson -Encoding utf8
    }

    return $outputResults
}
