Describe "Koality Assured PowerShell Scripts Validation Suite" {
    Context "PowerShell Abstract Syntax Tree Validation" {
        $scripts = Get-ChildItem -Path "$PSScriptRoot\.." -Recurse -Filter "*.ps1" |
            Where-Object { $_.FullName -notmatch 'Tests\.ps1$' }

        foreach ($script in $scripts) {
            It "Parses '$($script.Name)' cleanly without AST syntax errors" {
                $parseErrors = $null
                $null = [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$null, [ref]$parseErrors)
                @($parseErrors).Count | Should Be 0
            }
        }
    }

    Context "Script Architecture and Metadata Standards" {
        $expectedScripts = @(
            "ActiveDirectory\Manage-ADComputer.ps1",
            "ActiveDirectory\Test-DCSyncReplicationRights.ps1",
            "ActiveDirectory\Get-LocalAdminMembers.ps1",
            "ActiveDirectory\Get-StaleADAccounts.ps1",
            "Security\Get-ExpiringCertificates.ps1",
            "Security\Set-WindowsTlsHardening.ps1",
            "Security\Test-GraphQLIntrospection.ps1",
            "Utility\Convert-YamlToPSCustomObject.ps1",
            "Utility\Compare-WindowsHotfixes.ps1"
        )

        foreach ($relPath in $expectedScripts) {
            $fullPath = Join-Path "$PSScriptRoot\.." $relPath
            $leafName = Split-Path $relPath -Leaf

            It "Verifies '$leafName' exists and contains [CmdletBinding()]" {
                Test-Path $fullPath | Should Be $true
                $content = Get-Content $fullPath -Raw
                $content -match '\[CmdletBinding\(.*?\)\]' | Should Be $true
            }

            It "Verifies '$leafName' contains complete comment-based help tags" {
                $content = Get-Content $fullPath -Raw
                ($content -match '\.SYNOPSIS') | Should Be $true
                ($content -match '\.DESCRIPTION') | Should Be $true
                ($content -match '\.EXAMPLE') | Should Be $true
                ($content -match '\.NOTES') | Should Be $true
            }
        }
    }

    Context "Utility and Security Execution" {
        It "Converts structured YAML string to native PSCustomObject" {
            $convScript = Join-Path "$PSScriptRoot\.." "Utility\Convert-YamlToPSCustomObject.ps1"
            $yaml = @"
service:
  name: test-app
  port: 8080
  active: true
"@
            $res = & $convScript -YamlContent $yaml
            $null -ne $res | Should Be $true
            $res.service.name | Should Be "test-app"
            $res.service.port | Should Be 8080
            $res.service.active | Should Be $true
        }

        It "Runs Set-WindowsTlsHardening in -AuditOnly mode" {
            $tlsScript = Join-Path "$PSScriptRoot\.." "Security\Set-WindowsTlsHardening.ps1"
            $report = & $tlsScript -AuditOnly
            $null -ne $report | Should Be $true
            @($report).Count -ge 20 | Should Be $true
        }

        It "Queries local machine hotfixes via Compare-WindowsHotfixes" {
            $hfScript = Join-Path "$PSScriptRoot\.." "Utility\Compare-WindowsHotfixes.ps1"
            $summary = & $hfScript -ComputerName 'localhost'
            $null -ne $summary | Should Be $true
            @($summary).Count -ge 1 | Should Be $true
        }
    }
}
