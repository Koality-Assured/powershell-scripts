<#
.SYNOPSIS
    Evaluates GraphQL API endpoint security by sending schema introspection queries to detect exposure.

.DESCRIPTION
    Test-GraphQLIntrospection tests target GraphQL endpoints to assess whether schema introspection
    (__schema query) is accessible. Introspection enabled on production APIs exposes internal types,
    queries, mutations, arguments, and sensitive field definitions to unauthorized observers (OWASP API8:2023).

    The script sends standard GraphQL introspection queries, evaluates HTTP status codes and response bodies,
    identifies sensitive keywords across discovered fields (e.g. 'token', 'password', 'secret', 'admin'),
    and outputs a structured risk assessment report with remediation guidance.

.PARAMETER Uri
    The target GraphQL endpoint URL (e.g. 'https://api.example.com/graphql').

.PARAMETER Method
    HTTP method for transmitting the GraphQL payload ('POST' or 'GET'). Default: 'POST'.

.PARAMETER Headers
    Optional hashtable of HTTP request headers (e.g. @{ 'Authorization' = 'Bearer <token>'; 'X-API-Key' = '...' }).

.PARAMETER TimeoutSeconds
    HTTP request timeout in seconds. Default: 15.

.PARAMETER SkipCertificateCheck
    Bypasses SSL/TLS certificate validation for internal lab testing.

.PARAMETER ExportSchemaPath
    Optional file path to save the complete introspected schema JSON when introspection is active.

.PARAMETER ExportJson
    Optional file path to output the audit result object to JSON.

.EXAMPLE
    PS C:\> .\Test-GraphQLIntrospection.ps1 -Uri "https://api.example.com/graphql"

    Tests if introspection is open on the specified endpoint.

.EXAMPLE
    PS C:\> $headers = @{ "Authorization" = "Bearer eyJhbGciOi..." }
    PS C:\> .\Test-GraphQLIntrospection.ps1 -Uri "https://internal.contoso.local/graphql" -Headers $headers -ExportSchemaPath ".\schema.json"

    Tests authenticated GraphQL endpoint and exports schema if introspection is permitted.

.NOTES
    Author: Koality Assured Security Operations
    Security Reference: OWASP API Security Top 10 (API8: Security Misconfiguration)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [Alias('Url', 'Endpoint')]
    [string]$Uri,

    [Parameter()]
    [ValidateSet('POST', 'GET')]
    [string]$Method = 'POST',

    [Parameter()]
    [hashtable]$Headers = @{},

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$TimeoutSeconds = 15,

    [Parameter()]
    [switch]$SkipCertificateCheck,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportSchemaPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Sensitive schema keyword indicators
$SENSITIVE_FIELD_PATTERNS = @(
    'password',
    'passwd',
    'token',
    'secret',
    'apiKey',
    'api_key',
    'credential',
    'ssn',
    'creditcard',
    'credit_card',
    'privateKey',
    'auth_token',
    'session_id',
    'admin'
)

# Standard full introspection query
$introspectionQuery = @'
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
      }
    }
  }
}
'@

Write-Verbose "Preparing introspection probe against: $Uri via $Method"

# Configure SSL bypass if requested
if ($SkipCertificateCheck.IsPresent) {
    Write-Verbose "Bypassing TLS certificate validation callback..."
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

$requestPayload = @{
    query = $introspectionQuery
} | ConvertTo-Json -Compress

$requestHeaders = @{
    'Content-Type' = 'application/json'
    'Accept'       = 'application/json'
    'User-Agent'   = 'KoalityAssured-SecurityAudit-GraphQLProbe/1.0'
}

foreach ($key in $Headers.Keys) {
    $requestHeaders[$key] = $Headers[$key]
}

$httpStatus = 0
$introspectionEnabled = $false
$schemaData = $null
$errorMessage = $null
$rawResponse = $null

try {
    $restParams = @{
        Uri            = $Uri
        Method         = $Method
        Headers        = $requestHeaders
        TimeoutSec     = $TimeoutSeconds
        ErrorAction    = 'Stop'
    }

    if ($Method -eq 'POST') {
        $restParams['Body'] = $requestPayload
    }
    else {
        # GET query encoding
        $encodedQuery = [System.Uri]::EscapeDataString($introspectionQuery)
        $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
        $restParams['Uri'] = "$Uri${separator}query=$encodedQuery"
    }

    $rawResponse = Invoke-RestMethod @restParams
    $httpStatus = 200

    if ($rawResponse.data -and $rawResponse.data.__schema) {
        $introspectionEnabled = $true
        $schemaData = $rawResponse.data.__schema
    }
    elseif ($rawResponse.__schema) {
        $introspectionEnabled = $true
        $schemaData = $rawResponse.__schema
    }
    elseif ($rawResponse.errors) {
        $introspectionEnabled = $false
        $errorMsgs = ($rawResponse.errors | ForEach-Object { $_.message }) -join '; '
        $errorMessage = "GraphQL Error: $errorMsgs"
    }
}
catch {
    $exception = $_.Exception
    if ($exception.Response) {
        try {
            $httpStatus = [int]$exception.Response.StatusCode
        }
        catch {
            $httpStatus = 0
        }
    }

    $errorMessage = $exception.Message

    # Check if response body indicates explicit introspection block
    try {
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $respBody = $_.ErrorDetails.Message
            if ($respBody -match '(?i)introspection|__schema|disabled|not allowed|forbidden') {
                $errorMessage = "Introspection explicitly rejected by GraphQL engine ($httpStatus): $respBody"
            }
        }
    }
    catch {
        # Silently retain primary error message
    }
}

# Analyze discovered schema
$typesCount = 0
$queriesCount = 0
$mutationsCount = 0
$subscriptionsCount = 0
$sensitiveFieldsFound = [System.Collections.Generic.List[string]]::new()

if ($introspectionEnabled -and $null -ne $schemaData) {
    $types = @($schemaData.types)
    $typesCount = $types.Count

    $queryTypeName = if ($schemaData.queryType) { $schemaData.queryType.name } else { 'Query' }
    $mutationTypeName = if ($schemaData.mutationType) { $schemaData.mutationType.name } else { 'Mutation' }
    $subscriptionTypeName = if ($schemaData.subscriptionType) { $schemaData.subscriptionType.name } else { 'Subscription' }

    foreach ($type in $types) {
        if ($type.name -eq $queryTypeName -and $type.fields) {
            $queriesCount = @($type.fields).Count
        }
        if ($type.name -eq $mutationTypeName -and $type.fields) {
            $mutationsCount = @($type.fields).Count
        }
        if ($type.name -eq $subscriptionTypeName -and $type.fields) {
            $subscriptionsCount = @($type.fields).Count
        }

        # Inspect field names for sensitive keywords
        if ($type.fields) {
            foreach ($field in $type.fields) {
                $fieldName = $field.name
                foreach ($pattern in $SENSITIVE_FIELD_PATTERNS) {
                    if ($fieldName -match "(?i)\b$pattern\b|_$pattern|$pattern") {
                        $matchId = "$($type.name).$fieldName"
                        if (-not $sensitiveFieldsFound.Contains($matchId)) {
                            $sensitiveFieldsFound.Add($matchId)
                        }
                    }
                }
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportSchemaPath)) {
        Write-Verbose "Exporting introspected schema to: $ExportSchemaPath"
        $rawResponse | ConvertTo-Json -Depth 20 | Set-Content -Path $ExportSchemaPath -Encoding utf8
    }
}

# Risk rating determination
$riskLevel = 'Low'
$remediation = 'GraphQL introspection is disabled or inaccessible. Secure configuration verified.'

if ($introspectionEnabled) {
    $riskLevel = 'High'
    $remediation = "IMMEDIATE HARDENING: Disable GraphQL introspection in production environments. Configure server options (e.g. Apollo Server `introspection: false`, GraphQL-Yoga `plugins: [useDisableIntrospection()]`) to prevent schema enumeration."
}
elseif ($httpStatus -in @(401, 403)) {
    $remediation = "Endpoint returned HTTP $httpStatus. Verify whether introspection is protected behind authentication or globally disabled."
}

$auditResult = [PSCustomObject]@{
    Endpoint                 = $Uri
    Method                   = $Method
    HttpStatus               = $httpStatus
    IntrospectionEnabled     = $introspectionEnabled
    RiskLevel                = $riskLevel
    TotalTypesCount          = $typesCount
    QueriesCount             = $queriesCount
    MutationsCount           = $mutationsCount
    SubscriptionsCount       = $subscriptionsCount
    SensitiveFieldsDetected  = @($sensitiveFieldsFound)
    ErrorMessage             = $errorMessage
    Remediation              = $remediation
    Timestamp                = (Get-Date).ToUniversalTime().ToString('o')
}

if ($introspectionEnabled) {
    Write-Host "[!] VULNERABILITY DETECTED: GraphQL Introspection is ENABLED on $Uri" -ForegroundColor Red
    Write-Host "    Discovered: $typesCount types, $queriesCount queries, $mutationsCount mutations." -ForegroundColor Yellow
    if ($sensitiveFieldsFound.Count -gt 0) {
        Write-Host "    Potentially Sensitive Fields: $($sensitiveFieldsFound.Count) matches (e.g. $($sensitiveFieldsFound | Select-Object -First 5 -Join ', '))" -ForegroundColor Yellow
    }
}
else {
    Write-Host "[+] PASS: GraphQL Introspection is DISABLED or blocked on $Uri" -ForegroundColor Green
}

if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
    Write-Verbose "Exporting audit report to JSON: $ExportJson"
    $auditResult | ConvertTo-Json -Depth 5 | Set-Content -Path $ExportJson -Encoding utf8
}

return $auditResult
