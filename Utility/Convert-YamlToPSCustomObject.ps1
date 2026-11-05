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

    function Parse-BasicYamlString {
        param([string]$Yaml)

        # 1. Attempt PowerShell 7 native ConvertFrom-Yaml
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

        # 3. Indentation-stack YAML parser supporting nested dictionaries and arrays
        $rootDict = [ordered]@{}
        $stack = [System.Collections.Generic.List[hashtable]]::new()
        $stack.Add(@{ Indent = -1; Container = $rootDict; Key = $null; IsList = $false })

        $lines = $Yaml -split "`r?`n"

        foreach ($rawLine in $lines) {
            if ([string]::IsNullOrWhiteSpace($rawLine) -or $rawLine.TrimStart().StartsWith('#')) {
                continue
            }

            $trimmed = $rawLine.TrimStart()
            $indent = $rawLine.Length - $trimmed.Length

            # Unwind stack when indent drops
            while ($stack.Count -gt 1 -and $indent -le $stack[$stack.Count - 1].Indent) {
                $stack.RemoveAt($stack.Count - 1)
            }

            $currentContext = $stack[$stack.Count - 1]
            $currentContainer = $currentContext.Container

            # List element: - value or - key: value
            if ($trimmed.StartsWith('- ')) {
                $listContent = $trimmed.Substring(2).Trim()

                # If current container is not an ArrayList, convert or wrap
                $targetList = $null
                if ($currentContext.IsList) {
                    $targetList = $currentContainer
                }
                elseif ($currentContext.Key -and $currentContainer -is [System.Collections.IDictionary]) {
                    $targetList = [System.Collections.ArrayList]::new()
                    $currentContainer[$currentContext.Key] = $targetList
                    $stack.Add(@{ Indent = $indent; Container = $targetList; Key = $null; IsList = $true })
                }

                if ($listContent -match '^([A-Za-z0-9_\-]+)\s*:\s*(.*)$') {
                    $itemDict = [ordered]@{}
                    $itemKey = $Matches[1].Trim()
                    $itemVal = $Matches[2].Trim()
                    if ($itemVal.StartsWith('"') -and $itemVal.EndsWith('"')) { $itemVal = $itemVal.Substring(1, $itemVal.Length - 2) }
                    elseif ($itemVal.StartsWith("'") -and $itemVal.EndsWith("'")) { $itemVal = $itemVal.Substring(1, $itemVal.Length - 2) }
                    $itemDict[$itemKey] = $itemVal
                    if ($targetList) { [void]$targetList.Add($itemDict) }
                    $stack.Add(@{ Indent = $indent + 2; Container = $itemDict; Key = $itemKey; IsList = $false })
                }
                else {
                    $val = $listContent
                    if ($val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Substring(1, $val.Length - 2) }
                    elseif ($val.StartsWith("'") -and $val.EndsWith("'")) { $val = $val.Substring(1, $val.Length - 2) }
                    if ($targetList) { [void]$targetList.Add($val) }
                }
            }
            # Key-Value or Key-Object mapping
            elseif ($trimmed -match '^([A-Za-z0-9_\-]+)\s*:\s*(.*)$') {
                $k = $Matches[1].Trim()
                $v = $Matches[2].Trim()

                if ([string]::IsNullOrEmpty($v)) {
                    $newSubDict = [ordered]@{}
                    if ($currentContainer -is [System.Collections.IDictionary]) {
                        $currentContainer[$k] = $newSubDict
                    }
                    $stack.Add(@{ Indent = $indent; Container = $newSubDict; Key = $k; IsList = $false })
                }
                else {
                    if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
                        $v = $v.Substring(1, $v.Length - 2)
                    }

                    $parsedV = $v
                    if ($v -eq 'true') { $parsedV = $true }
                    elseif ($v -eq 'false') { $parsedV = $false }
                    elseif ($v -match '^-?\d+$') { $parsedV = [int]$v }
                    elseif ($v -match '^-?\d+\.\d+$') { $parsedV = [double]$v }

                    if ($currentContainer -is [System.Collections.IDictionary]) {
                        $currentContainer[$k] = $parsedV
                    }
                }
            }
        }

        return $rootDict
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
