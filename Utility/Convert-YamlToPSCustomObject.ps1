<#
.SYNOPSIS
    Recursively converts YAML strings, files, or hashtable hierarchies into native PowerShell [PSCustomObject] structures.

.DESCRIPTION
    Convert-YamlToPSCustomObject provides deep recursive deserialization of YAML data into native PowerShell
    [PSCustomObject] hierarchies. While standard YAML converters often leave nested structures as raw Hashtables
    or OrderedDictionaries, this utility traverses all nested mappings and collection items, converting every
    key-value dictionary into a strongly typed PSCustomObject that supports fluent dot-notation property navigation.

    Supports:
    - Reading YAML directly from a file path (-Path)
    - Parsing YAML from raw string input (-YamlContent)
    - Converting pre-parsed Hashtable/Dictionary graphs (-InputObject)
    - Full pipeline input from Get-Content or upstream commands
    - Cross-platform PowerShell 7+ and Windows PowerShell 5.1 compatibility

.PARAMETER Path
    Path to a YAML file (.yaml or .yml) to read and deserialize.

.PARAMETER YamlContent
    Raw YAML formatted string to deserialize. Accepts pipeline input.

.PARAMETER InputObject
    An existing Hashtable, OrderedDictionary, or collection graph to recursively transform into [PSCustomObject].

.PARAMETER MaxDepth
    Maximum recursive traversal depth to prevent infinite circular reference loops. Default: 64.

.EXAMPLE
    PS C:\> .\Convert-YamlToPSCustomObject.ps1 -Path ".\config.yaml"

    Deserializes the configuration YAML file into a nested PSCustomObject graph.

.EXAMPLE
    PS C:\> Get-Content ".\manifest.yml" -Raw | .\Convert-YamlToPSCustomObject.ps1

    Pipes raw YAML text into the converter.

.EXAMPLE
    PS C:\> $hash = @{ server = @{ host = "db01.contoso.local"; port = 5432; auth = @{ user = "svc_app" } } }
    PS C:\> $psObj = .\Convert-YamlToPSCustomObject.ps1 -InputObject $hash
    PS C:\> $psObj.server.auth.user
    svc_app

.NOTES
    Author: Koality Assured Systems Engineering
    Standard: Standard YAML 1.2 parsing and deep object transformation
#>

[CmdletBinding(DefaultParameterSetName = 'FromContent')]
param(
    [Parameter(ParameterSetName = 'FromPath', Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter(ParameterSetName = 'FromContent', Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [AllowEmptyString()]
    [string]$YamlContent,

    [Parameter(ParameterSetName = 'FromObject', Mandatory = $true, Position = 0)]
    [AllowNull()]
    [psobject]$InputObject,

    [Parameter()]
    [ValidateRange(1, 256)]
    [int]$MaxDepth = 64
)

begin {
    Set-StrictMode -Version Latest

    function ConvertTo-RecursivePSCustomObject {
        param(
            [Parameter(Mandatory = $false)]
            $Source,
            [int]$CurrentDepth = 0
        )

        if ($null -eq $Source) {
            return $null
        }

        if ($CurrentDepth -gt $MaxDepth) {
            Write-Warning "Maximum recursion depth ($MaxDepth) exceeded while converting object graph."
            return $Source
        }

        # Handle dictionaries (Hashtables, OrderedDictionaries, IDictionary)
        if ($Source -is [System.Collections.IDictionary]) {
            $outputObj = [PSCustomObject]::new()
            foreach ($key in $Source.Keys) {
                $propName = [string]$key
                $propVal = ConvertTo-RecursivePSCustomObject -Source $Source[$key] -CurrentDepth ($CurrentDepth + 1)
                $outputObj | Add-Member -MemberType NoteProperty -Name $propName -Value $propVal -Force
            }
            return $outputObj
        }

        # Handle collections / arrays
        if ($Source -is [System.Collections.IEnumerable] -and -not ($Source -is [string])) {
            $outputList = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Source) {
                $convertedItem = ConvertTo-RecursivePSCustomObject -Source $item -CurrentDepth ($CurrentDepth + 1)
                $outputList.Add($convertedItem)
            }
            return $outputList.ToArray()
        }

        # Scalars / Primitives
        return $Source
    }

    function Convert-YamlScalarValue {
        param([string]$Raw)
        if ($null -eq $Raw) { return $null }
        $s = $Raw.Trim()
        if ($s.Length -eq 0 -or $s -in @('~', 'null', 'Null', 'NULL')) { return $null }
        if ($s -in @('true', 'True', 'TRUE')) { return $true }
        if ($s -in @('false', 'False', 'FALSE')) { return $false }
        if (($s.StartsWith('"') -and $s.EndsWith('"')) -or ($s.StartsWith("'") -and $s.EndsWith("'"))) {
            if ($s.Length -ge 2) {
                return $s.Substring(1, $s.Length - 2)
            }
            return ''
        }
        if ($s -match '^-?\d+$') {
            try { return [int64]$s } catch { return $s }
        }
        if ($s -match '^-?\d+\.\d+$') {
            try { return [double]$s } catch { return $s }
        }
        return $s
    }

    function Parse-BasicYamlString {
        param([string]$Yaml)

        # 1. Attempt PowerShell native ConvertFrom-Yaml if available
        if (Get-Command -Name 'ConvertFrom-Yaml' -ErrorAction SilentlyContinue) {
            return ($Yaml | ConvertFrom-Yaml)
        }

        # 2. Attempt ConvertFrom-Json if content is JSON-compatible subset
        try {
            $trimmed = $Yaml.Trim()
            if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
                return ($trimmed | ConvertFrom-Json)
            }
        }
        catch {
            # Continue to line parser
        }

        # 3. Robust stack-based YAML parser supporting nested objects, arrays of primitives, arrays of objects, and nulls
        $lines = $Yaml -split "`r?`n"

        # Determine root container type based on first non-comment non-empty line
        $rootIsList = $false
        foreach ($l in $lines) {
            $tl = $l.Trim()
            if (-not [string]::IsNullOrWhiteSpace($tl) -and -not $tl.StartsWith('#')) {
                if ($tl.StartsWith('- ')) { $rootIsList = $true }
                break
            }
        }

        $rootContainer = $null
        $rootType = 'Dict'
        if ($rootIsList) {
            $rootContainer = [System.Collections.ArrayList]::new()
            $rootType = 'List'
        }
        else {
            $rootContainer = [ordered]@{}
            $rootType = 'Dict'
        }

        $stack = [System.Collections.Generic.List[hashtable]]::new()
        $stack.Add(@{
            Indent        = -1
            Type          = $rootType
            Container     = $rootContainer
            PendingKey    = $null
            PendingIndent = -1
        })

        foreach ($rawLine in $lines) {
            if ([string]::IsNullOrWhiteSpace($rawLine) -or $rawLine.TrimStart().StartsWith('#')) {
                continue
            }

            # Strip trailing comments not inside quotes
            $lineClean = $rawLine
            if ($lineClean -match '^(.*?)(\s+#.*)$') {
                $candidate = $Matches[1]
                $dQuotes = ($candidate.ToCharArray() | Where-Object { $_ -eq '"' }).Count
                $sQuotes = ($candidate.ToCharArray() | Where-Object { $_ -eq "'" }).Count
                if ($dQuotes % 2 -eq 0 -and $sQuotes % 2 -eq 0) {
                    $lineClean = $candidate
                }
            }

            $trimmed = $lineClean.TrimStart()
            $indent = $lineClean.Length - $trimmed.Length

            # Unwind stack if current indent is less than or equal to top's indent
            while ($stack.Count -gt 1) {
                $top = $stack[$stack.Count - 1]
                if ($indent -le $top.Indent) {
                    $stack.RemoveAt($stack.Count - 1)
                }
                else {
                    break
                }
            }

            $currentContext = $stack[$stack.Count - 1]

            # If current context has a PendingKey, instantiate container for that key
            if ($currentContext.PendingKey) {
                $pKey = $currentContext.PendingKey
                $pIndent = $currentContext.PendingIndent
                $currentContext.PendingKey = $null

                if ($trimmed.StartsWith('- ')) {
                    $newList = [System.Collections.ArrayList]::new()
                    $currentContext.Container[$pKey] = $newList
                    $newContext = @{
                        Indent        = $pIndent
                        Type          = 'List'
                        Container     = $newList
                        PendingKey    = $null
                        PendingIndent = -1
                    }
                    $stack.Add($newContext)
                    $currentContext = $newContext
                }
                else {
                    $newDict = [ordered]@{}
                    $currentContext.Container[$pKey] = $newDict
                    $newContext = @{
                        Indent        = $pIndent
                        Type          = 'Dict'
                        Container     = $newDict
                        PendingKey    = $null
                        PendingIndent = -1
                    }
                    $stack.Add($newContext)
                    $currentContext = $newContext
                }
            }

            # List element: - value OR - key: value
            if ($trimmed.StartsWith('- ')) {
                $listContent = $trimmed.Substring(2).Trim()

                # Ensure current container is a list; if not, wrap or pop
                $targetList = $null
                if ($currentContext.Type -eq 'List' -and $currentContext.Container -is [System.Collections.IList]) {
                    $targetList = $currentContext.Container
                }
                else {
                    # Fallback to nearest list in stack
                    for ($si = $stack.Count - 1; $si -ge 0; $si--) {
                        if ($stack[$si].Type -eq 'List' -and $stack[$si].Container -is [System.Collections.IList]) {
                            $targetList = $stack[$si].Container
                            break
                        }
                    }
                }

                if ($listContent -match '^([A-Za-z0-9_\-\.]+)\s*:\s*(.*)$') {
                    $itemDict = [ordered]@{}
                    $itemKey = $Matches[1].Trim()
                    $itemValRaw = $Matches[2].Trim()

                    $parsedVal = Convert-YamlScalarValue -Raw $itemValRaw
                    $itemDict[$itemKey] = $parsedVal

                    if ($null -ne $targetList) { [void]$targetList.Add($itemDict) }

                    # Push frame for this object item so indented properties belong to it
                    $stack.Add(@{
                        Indent        = $indent
                        Type          = 'Dict'
                        Container     = $itemDict
                        PendingKey    = if ($null -eq $parsedVal -and [string]::IsNullOrEmpty($itemValRaw)) { $itemKey } else { $null }
                        PendingIndent = if ($null -eq $parsedVal -and [string]::IsNullOrEmpty($itemValRaw)) { $indent } else { -1 }
                    })
                }
                else {
                    $scalarVal = Convert-YamlScalarValue -Raw $listContent
                    if ($null -ne $targetList) {
                        [void]$targetList.Add($scalarVal)
                    }
                }
            }
            # Key-Value or Key-Container mapping
            elseif ($trimmed -match '^([A-Za-z0-9_\-\.]+)\s*:\s*(.*)$') {
                $k = $Matches[1].Trim()
                $vRaw = $Matches[2].Trim()

                if ([string]::IsNullOrEmpty($vRaw)) {
                    # Empty scalar or container parent
                    if ($currentContext.Container -is [System.Collections.IDictionary]) {
                        $currentContext.Container[$k] = $null
                    }
                    $currentContext.PendingKey = $k
                    $currentContext.PendingIndent = $indent
                }
                else {
                    $parsedScalar = Convert-YamlScalarValue -Raw $vRaw
                    if ($currentContext.Container -is [System.Collections.IDictionary]) {
                        $currentContext.Container[$k] = $parsedScalar
                    }
                    $currentContext.PendingKey = $null
                }
            }
        }

        return $rootContainer
    }
}

process {
    $rawParsed = $null

    if ($PSCmdlet.ParameterSetName -eq 'FromPath') {
        if (-not (Test-Path -Path $Path)) {
            throw "YAML file not found at path: $Path"
        }
        $content = Get-Content -Path $Path -Raw -Encoding utf8
        $rawParsed = Parse-BasicYamlString -Yaml $content
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'FromContent') {
        $rawParsed = Parse-BasicYamlString -Yaml $YamlContent
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'FromObject') {
        $rawParsed = $InputObject
    }

    $finalCustomObject = ConvertTo-RecursivePSCustomObject -Source $rawParsed -CurrentDepth 0
    return $finalCustomObject
}
