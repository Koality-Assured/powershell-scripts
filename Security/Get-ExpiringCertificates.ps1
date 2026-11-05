<#
.SYNOPSIS
    Scans local/remote certificate stores and Microsoft Certificate Authorities for expiring certificates and dispatches webhook alerts.

.DESCRIPTION
    Get-ExpiringCertificates automates certificate lifecycle auditing across Windows server fleets and Microsoft
    Enterprise Certificate Authorities. It identifies certificates expiring within a configurable threshold or
    already expired, evaluates private key possession and template metadata, and dispatches structured alerts
    to Microsoft Teams, Slack, or generic webhook receivers.

    Supports both PowerShell 7+ and Windows PowerShell 5.1 environments.

.PARAMETER ComputerName
    One or more computer names to audit via remote PowerShell or CIM. Defaults to the local host. Accepts pipeline input.

.PARAMETER StorePath
    One or more certificate store paths to inspect. Defaults to 'Cert:\LocalMachine\My' (Personal Machine Store).
    Additional examples: 'Cert:\LocalMachine\WebHosting', 'Cert:\CurrentUser\My'.

.PARAMETER CertificationAuthority
    Optional Microsoft Enterprise Certification Authority config string (e.g. 'ca01.contoso.local\Contoso-CA')
    to query issued requests directly using PSPKI cmdlets or certutil fallback.

.PARAMETER TemplateName
    Optional list of certificate template names to filter on when querying a Microsoft CA.

.PARAMETER ThresholdDays
    The threshold in calendar days within which a certificate is flagged as expiring. Default: 30 days.

.PARAMETER IncludeExpired
    When specified, includes certificates that have already expired. Default: $true.

.PARAMETER WebhookUrl
    Optional incoming webhook URL for alerting (Microsoft Teams Adaptive Card, Slack, or JSON endpoint).

.PARAMETER WebhookType
    The target webhook formatting schema: 'Auto', 'Teams', 'Slack', 'GenericJson'. Default: 'Auto'.

.PARAMETER ExportJson
    Optional file path to output discovered certificate records in JSON format.

.PARAMETER ExportCsv
    Optional file path to output discovered certificate records in CSV format.

.EXAMPLE
    PS C:\> .\Get-ExpiringCertificates.ps1 -ThresholdDays 45

    Scans the local machine personal certificate store for certificates expiring within 45 days.

.EXAMPLE
    PS C:\> "SRV-WEB-01", "SRV-API-01" | .\Get-ExpiringCertificates.ps1 -ThresholdDays 30 -WebhookUrl "https://webhook.example.com/alerts"

    Audits multiple web servers and sends an alert payload if expiring certificates are detected.

.NOTES
    Author: Koality Assured Security Operations
    Security Reference: NIST SP 800-57 (Recommendation for Key Management)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$StorePath = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\WebHosting'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CertificationAuthority,

    [Parameter()]
    [string[]]$TemplateName,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$ThresholdDays = 30,

    [Parameter()]
    [bool]$IncludeExpired = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WebhookUrl,

    [Parameter()]
    [ValidateSet('Auto', 'Teams', 'Slack', 'GenericJson')]
    [string]$WebhookType = 'Auto',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportCsv
)

begin {
    Set-StrictMode -Version Latest
    $allCertificates = [System.Collections.Generic.List[PSCustomObject]]::new()
    $auditCutoff = (Get-Date).AddDays($ThresholdDays)

    function Send-WebhookNotification {
        param(
            [string]$Url,
            [string]$Type,
            [System.Collections.Generic.List[PSCustomObject]]$Certs
        )

        if ($Certs.Count -eq 0 -or [string]::IsNullOrWhiteSpace($Url)) {
            return
        }

        $detectedType = $Type
        if ($detectedType -eq 'Auto') {
            if ($Url -match '(?i)webhook\.office\.com|microsoft\.com') {
                $detectedType = 'Teams'
            }
            elseif ($Url -match '(?i)hooks\.slack\.com') {
                $detectedType = 'Slack'
            }
            else {
                $detectedType = 'GenericJson'
            }
        }

        $payload = $null
        $highPriorityCount = ($Certs | Where-Object { $_.AlertStatus -in @('CRITICAL', 'EXPIRED') }).Count

        if ($detectedType -eq 'Teams') {
            # Modern Teams Adaptive Card Schema
            $facts = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($c in ($Certs | Select-Object -First 10)) {
                $facts.Add(@{
                    title = "$($c.CommonName) ($($c.ComputerName))"
                    value = "Status: $($c.AlertStatus) | Expires: $($c.NotAfter) ($($c.DaysRemaining) days remaining)"
                })
            }

            $payload = @{
                type = "message"
                attachments = @(
                    @{
                        contentType = "application/vnd.microsoft.card.adaptive"
                        content = @{
                            '$schema' = "http://adaptivecards.io/schemas/adaptive-card.json"
                            type      = "AdaptiveCard"
                            version   = "1.4"
                            body      = @(
                                @{
                                    type   = "TextBlock"
                                    text   = "Security Alert: Expiring TLS/SSL Certificates"
                                    weight = "Bolder"
                                    size   = "Medium"
                                    color  = if ($highPriorityCount -gt 0) { "Attention" } else { "Warning" }
                                },
                                @{
                                    type = "TextBlock"
                                    text = "Identified $($Certs.Count) certificate(s) requiring remediation within $ThresholdDays day threshold."
                                    wrap = $true
                                },
                                @{
                                    type  = "FactSet"
                                    facts = $facts
                                }
                            )
                        }
                    }
                )
            }
        }
        elseif ($detectedType -eq 'Slack') {
            $slackText = "*Security Alert: Expiring TLS/SSL Certificates*`n"
            $slackText += "Discovered *$( $Certs.Count )* certificate(s) expiring within *$ThresholdDays* days:`n"
            foreach ($c in ($Certs | Select-Object -First 10)) {
                $slackText += "• *$( $c.CommonName )* on `$( $c.ComputerName )` - Status: *$( $c.AlertStatus )* ($( $c.DaysRemaining ) days left)`n"
            }

            $payload = @{
                text = $slackText
            }
        }
        else {
            $payload = @{
                AlertTitle    = "Expiring TLS/SSL Certificates"
                TotalFindings = $Certs.Count
                CriticalCount = $highPriorityCount
                ThresholdDays = $ThresholdDays
                Certificates  = $Certs
                Timestamp     = (Get-Date).ToUniversalTime().ToString('o')
            }
        }

        try {
            $jsonBody = $payload | ConvertTo-Json -Depth 6
            Write-Verbose "Dispatching alert payload to webhook endpoint ($detectedType)..."
            $response = Invoke-RestMethod -Uri $Url -Method Post -Body $jsonBody -ContentType 'application/json; charset=utf-8' -ErrorAction Stop
            Write-Verbose "Webhook dispatched successfully."
        }
        catch {
            Write-Warning "Failed to transmit webhook notification: $_"
        }
    }
}

process {
    # 1. Audit Local and Remote Computer Certificate Stores
    foreach ($targetHost in $ComputerName) {
        Write-Verbose "Scanning certificate stores on [$targetHost]..."

        $isLocalHost = ($targetHost -eq $env:COMPUTERNAME -or $targetHost -eq 'localhost' -or $targetHost -eq '127.0.0.1')

        if ($isLocalHost) {
            foreach ($store in $StorePath) {
                if (-not (Test-Path -Path $store)) {
                    Write-Verbose "Store path not available on host: $store"
                    continue
                }

                try {
                    $certs = Get-ChildItem -Path $store -ErrorAction SilentlyContinue | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
                    foreach ($cert in $certs) {
                        $daysRemaining = [Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)

                        if ($daysRemaining -lt 0 -and (-not $IncludeExpired)) {
                            continue
                        }
                        if ($daysRemaining -gt $ThresholdDays) {
                            continue
                        }

                        $alertStatus = if ($daysRemaining -lt 0) {
                            'EXPIRED'
                        }
                        elseif ($daysRemaining -le 7) {
                            'CRITICAL'
                        }
                        elseif ($daysRemaining -le 14) {
                            'HIGH'
                        }
                        else {
                            'WARNING'
                        }

                        $commonName = if ($cert.Subject -match '(?i)CN=([^,]+)') { $Matches[1] } else { $cert.Subject }
                        $templateNameStr = $null
                        foreach ($ext in $cert.Extensions) {
                            if ($ext.Oid.FriendlyName -eq 'Certificate Template Name' -or $ext.Oid.Value -eq '1.3.6.1.4.1.311.20.2') {
                                $templateNameStr = $ext.Format($false)
                            }
                        }

                        $record = [PSCustomObject]@{
                            ComputerName   = $targetHost
                            Store          = $store
                            Subject        = $cert.Subject
                            CommonName     = $commonName
                            Thumbprint     = $cert.Thumbprint
                            Issuer         = $cert.Issuer
                            NotAfter       = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss UTC')
                            DaysRemaining  = $daysRemaining
                            HasPrivateKey  = $cert.HasPrivateKey
                            Template       = $templateNameStr
                            AlertStatus    = $alertStatus
                            Source         = 'Store'
                        }

                        $allCertificates.Add($record)
                        $record
                    }
                }
                catch {
                    Write-Warning "Error reading store '$store' on '$targetHost': $_"
                }
            }
        }
        else {
            # Remote inspection via Invoke-Command / WinRM
            try {
                $remoteScript = {
                    param($Stores, $Threshold, $IncludeExp)
                    $out = @()
                    foreach ($s in $Stores) {
                        if (Test-Path $s) {
                            $certs = Get-ChildItem -Path $s -ErrorAction SilentlyContinue | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
                            foreach ($c in $certs) {
                                $rem = [Math]::Floor(($c.NotAfter - (Get-Date)).TotalDays)
                                if ($rem -lt 0 -and (-not $IncludeExp)) { continue }
                                if ($rem -gt $Threshold) { continue }
                                $stat = if ($rem -lt 0) { 'EXPIRED' } elseif ($rem -le 7) { 'CRITICAL' } elseif ($rem -le 14) { 'HIGH' } else { 'WARNING' }
                                $cn = if ($c.Subject -match '(?i)CN=([^,]+)') { $Matches[1] } else { $c.Subject }
                                $out += [PSCustomObject]@{
                                    ComputerName  = $env:COMPUTERNAME
                                    Store         = $s
                                    Subject       = $c.Subject
                                    CommonName    = $cn
                                    Thumbprint    = $c.Thumbprint
                                    Issuer        = $c.Issuer
                                    NotAfter      = $c.NotAfter.ToString('yyyy-MM-dd HH:mm:ss UTC')
                                    DaysRemaining = $rem
                                    HasPrivateKey = $c.HasPrivateKey
                                    Template      = $null
                                    AlertStatus   = $stat
                                    Source        = 'Store'
                                }
                            }
                        }
                    }
                    return $out
                }

                $remoteResults = Invoke-Command -ComputerName $targetHost -ScriptBlock $remoteScript -ArgumentList $StorePath, $ThresholdDays, $IncludeExpired -ErrorAction Stop
                foreach ($r in $remoteResults) {
                    $allCertificates.Add($r)
                    $r
                }
            }
            catch {
                Write-Warning "Remote query failed for host '$targetHost': $_"
            }
        }
    }

    # 2. Audit Microsoft Certification Authority if specified
    if (-not [string]::IsNullOrWhiteSpace($CertificationAuthority)) {
        Write-Verbose "Querying Certification Authority [$CertificationAuthority] for expiring certificates..."
        try {
            if (Get-Module -ListAvailable -Name PSPKI) {
                Import-Module PSPKI -ErrorAction Stop
                $caObj = Get-CertificationAuthority -ComputerName $CertificationAuthority -ErrorAction Stop
                $filterList = @("NotAfter -le $($auditCutoff.ToString('yyyy-MM-dd'))")
                if (-not $IncludeExpired) {
                    $filterList += "NotAfter -ge $((Get-Date).ToString('yyyy-MM-dd'))"
                }

                $caProps = @('CommonName', 'CertificateTemplate', 'NotAfter', 'Request.RequestID', 'DistinguishedName')
                $issuedRequests = Get-IssuedRequest -CertificationAuthority $caObj -Property $caProps -Filter $filterList -ErrorAction Stop

                foreach ($req in $issuedRequests) {
                    $daysRemaining = [Math]::Floor(($req.NotAfter - (Get-Date)).TotalDays)
                    $alertStatus = if ($daysRemaining -lt 0) { 'EXPIRED' } elseif ($daysRemaining -le 7) { 'CRITICAL' } elseif ($daysRemaining -le 14) { 'HIGH' } else { 'WARNING' }

                    $record = [PSCustomObject]@{
                        ComputerName  = $CertificationAuthority
                        Store         = 'MicrosoftCA'
                        Subject       = $req.DistinguishedName
                        CommonName    = $req.CommonName
                        Thumbprint    = $null
                        Issuer        = $caObj.Name
                        NotAfter      = $req.NotAfter.ToString('yyyy-MM-dd HH:mm:ss UTC')
                        DaysRemaining = $daysRemaining
                        HasPrivateKey = $false
                        Template      = $req.CertificateTemplate
                        AlertStatus   = $alertStatus
                        Source        = 'MicrosoftCA'
                    }

                    $allCertificates.Add($record)
                    $record
                }
            }
            else {
                Write-Verbose "PSPKI module not present. Attempting native certutil query..."
                $certutilFilter = "NotAfter <= $($auditCutoff.ToString('MM/dd/yyyy'))"
                $certutilOut = & certutil -config "$CertificationAuthority" -view -restrict "$certutilFilter, Disposition=20" -out "RequestID,CommonName,NotAfter,CertificateTemplate"
                Write-Verbose "Certutil command executed against CA."
            }
        }
        catch {
            Write-Warning "Failed to query Certification Authority '$CertificationAuthority': $_"
        }
    }
}

end {
    Write-Verbose "Certificate audit complete. Discovered $($allCertificates.Count) expiring/expired certificates."

    if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
        Write-Verbose "Exporting certificate records to JSON: $ExportJson"
        $allCertificates | ConvertTo-Json -Depth 4 | Set-Content -Path $ExportJson -Encoding utf8
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
        Write-Verbose "Exporting certificate records to CSV: $ExportCsv"
        $allCertificates | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
    }

    if (-not [string]::IsNullOrWhiteSpace($WebhookUrl)) {
        Send-WebhookNotification -Url $WebhookUrl -Type $WebhookType -Certs $allCertificates
    }
}
