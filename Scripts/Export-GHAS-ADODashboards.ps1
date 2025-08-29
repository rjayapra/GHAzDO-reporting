<#
.SYNOPSIS
  Export Azure DevOps Advanced Security (GHAzDO) data for two dashboards:
  1) Repositories with vulnerabilities found
  2) Repositories scanned but no vulnerabilities, with reasons:
     - UnsupportedLanguage (CodeQL not supported)
     - NoCode (repo contains no code files)
     - NoAlerts (scanned but alert count = 0)

.PARAMETERS
  -Organization  : Azure DevOps organization name (e.g., contoso)
  -Pat           : Azure DevOps Personal Access Token with vso.advsec + read scopes
  -OutputDir     : Folder to write CSVs
  -Projects      : Optional array of project names to limit the scan

.NOTES
  Uses Advanced Security REST APIs:
    Alerts List:   https://advsec.dev.azure.com/{org}/{proj}/_apis/alert/repositories/{repo}/alerts?api-version=7.2-preview.1
    Alerts Get:    same base (not used by default)
    Analysis List: https://advsec.dev.azure.com/{org}/{proj}/_apis/alert/repositories/{repo}/filters/branches?alertType=code&api-version=7.2-preview.1
  Doc refs: Alerts-List / Alerts-Get / Analysis-List (branches with analysis) 
#>

param(
  [Parameter(Mandatory=$true)] [string] $Organization,
  [Parameter(Mandatory=$true)] [string] $Pat,
  [Parameter(Mandatory=$true)] [string] $OutputDir,
  [string[]] $Projects
)

# ----- Helpers -----
$baseOrgUrl      = "https://dev.azure.com/$Organization"
$advSecBase      = "https://advsec.dev.azure.com/$Organization"
$apiVerCore      = "7.2-preview.1"
$apiVerAdvSec    = "7.2-preview.1"

# Auth header (PAT as Basic with empty username)
$pair = ":" + $Pat
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$basic = [Convert]::ToBase64String($bytes)
$headers = @{ Authorization = "Basic $basic" }

# Minimal language map for CodeQL support (extend as needed)
# Source: Microsoft Learn (CodeQL supported langs) 
$codeqlSupported = @{
  "cs"   = "csharp"
  "c"    = "cpp"; "h" = "cpp"; "hpp"="cpp"; "cpp"="cpp"; "cc"="cpp"; "cxx"="cpp"
  "go"   = "go"
  "java" = "java"; "kt"="java"; "kts"="java" # kotlin via java engine
  "js"   = "javascript"; "ts"="javascript"; "jsx"="javascript"; "tsx"="javascript"
  "py"   = "python"
  "rb"   = "ruby"
  "swift"= "swift"
}

# File extensions considered "code" even if not CodeQL-supported (helps detect NoCode)
$codeLikeExt = @("cs","c","h","hpp","cpp","cc","cxx","go","java","kt","kts","js","ts","jsx","tsx","py","rb","swift",
                 "php","scala","rs","dart","m","mm","vb","fs","fsx","ps1","sh","yml","yaml","json","xml","sql")

# Ensure output
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$alertsCsvPath         = Join-Path $OutputDir "alerts.csv"
$reposWithVulnsPath    = Join-Path $OutputDir "repos_with_vulnerabilities.csv"
$reposNoVulnsPath      = Join-Path $OutputDir "repos_without_vulnerabilities.csv"

$alertsRows = New-Object System.Collections.Generic.List[object]
$withRows   = New-Object System.Collections.Generic.List[object]
$noRows     = New-Object System.Collections.Generic.List[object]

function Invoke-Get($url) {
  $resp = Invoke-RestMethod -Method GET -Uri $url -Headers $headers -ErrorAction Stop
  return $resp
}

function Get-Projects() {
  if ($Projects -and $Projects.Count -gt 0) { return $Projects }
  $url = "$baseOrgUrl/_apis/projects?api-version=$apiVerCore"
  $p = Invoke-Get $url
  return $p.value.name
}

function Get-Repos($project) {
  $url = "$baseOrgUrl/$project/_apis/git/repositories?api-version=7.2"
  (Invoke-Get $url).value
}

function Get-DefaultBranchName([string]$fullRef) {
  if ([string]::IsNullOrEmpty($fullRef)) { return $null }
  # fullRef looks like 'refs/heads/main'
  return ($fullRef -split "/")[-1]
}

function Get-RepoItems($project, $repoId, $branchRef) {
  # Get top-level items recursively to detect code files (limit to 4000 items to be safe)
  $url = "$baseOrgUrl/$project/_apis/git/repositories/$repoId/items?recursionLevel=Full&includeContentMetadata=false&versionDescriptor.version=$branchRef&$"+"top=4000&api-version=7.2"
  try { (Invoke-Get $url).value } catch { @() }
}

function Detect-LanguageInfo($items) {
  $exts = $items | Where-Object { $_.gitObjectType -eq 'blob' -and $_.path } |
          ForEach-Object {
            $name = [System.IO.Path]::GetFileName($_.path)
            $ext  = ($name.Contains('.') ? ($name.Split('.')[-1].ToLowerInvariant()) : "")
            $ext
          } | Where-Object { $_ -ne "" }
  $hasAnyCode = $false
  $supportedHits = New-Object System.Collections.Generic.List[string]
  foreach ($e in $exts) {
    if ($codeLikeExt -contains $e) { $hasAnyCode = $true }
    if ($codeqlSupported.ContainsKey($e)) { $supportedHits.Add($codeqlSupported[$e]) }
  }
  $supportedLangs = ($supportedHits | Select-Object -Unique)
  [pscustomobject]@{
    HasAnyCode        = $hasAnyCode
    SupportedLangs    = ($supportedLangs -join ",")
    SupportedLangsArr = $supportedLangs
  }
}

function Get-AlertsAll($project, $repoId) {
  # Pull all alert types; page through continuation tokens if present
  $accum = @()
  $nextUrl = "$advSecBase/$project/_apis/alert/repositories/$repoId/alerts?api-version=$apiVerAdvSec"
  while ($nextUrl) {
    $resp = Invoke-WebRequest -Method GET -Uri $nextUrl -Headers $headers -ErrorAction Stop
    $json = ($resp.Content | ConvertFrom-Json)
    if ($json.value) { $accum += $json.value }
    # Continuation token header: x-ms-continuationtoken
    $ctok = $resp.Headers["x-ms-continuationtoken"]
    if ([string]::IsNullOrEmpty($ctok)) { $nextUrl = $null }
    else {
      $sep = ($nextUrl.Contains("?")) ? "&" : "?"
      $nextUrl = "$nextUrl$sep" + "continuationToken=$ctok"
    }
  }
  return $accum
}

function Get-CodeAnalysisBranches($project, $repoId) {
  $url = "$advSecBase/$project/_apis/alert/repositories/$repoId/filters/branches?alertType=code&api-version=$apiVerAdvSec"
  try { (Invoke-Get $url).value } catch { @() }
}

Write-Host "Enumerating projects/repos and collecting alerts..." -ForegroundColor Cyan

$projList = Get-Projects
foreach ($proj in $projList) {
  $repos = Get-Repos $proj
  foreach ($repo in $repos) {
    $repoId   = $repo.id
    $repoName = $repo.name
    $defaultRef = $repo.defaultBranch
    $defaultBranch = Get-DefaultBranchName $defaultRef

    # Repo items for language & code presence
    $items = @()
    if ($defaultBranch) {
      $items = Get-RepoItems -project $proj -repoId $repoId -branchRef $defaultBranch
    }
    $langInfo = Detect-LanguageInfo -items $items

    # Alerts across all types (code, dependency, secret). See Alerts-List doc. 
    $alerts = Get-AlertsAll -project $proj -repoId $repoId

    # Count by type/severity/state
    $totalAlerts = 0
    $byType = @{
      code = 0; dependency = 0; secret = 0
    }
    $bySeverity = @{
      critical=0; high=0; medium=0; low=0; none=0
    }

    foreach ($a in $alerts) {
      $totalAlerts++
      if ($byType.ContainsKey($a.alertType)) { $byType[$a.alertType]++ }
      if ($a.severity) {
        $sev = $a.severity.ToLowerInvariant()
        if ($bySeverity.ContainsKey($sev)) { $bySeverity[$sev]++ } else { $bySeverity["none"]++ }
      } else { $bySeverity["none"]++ }

      # Accumulate alert detail row for alerts.csv
      $alertsRows.Add([pscustomobject]@{
        Organization = $Organization
        Project      = $proj
        Repository   = $repoName
        RepositoryId = $repoId
        AlertId      = $a.alertId
        AlertType    = $a.alertType
        Severity     = $a.severity
        State        = $a.state
        Title        = $a.title
        RuleId       = $a.rule.ruleId
        RuleName     = $a.rule.ruleName
        RepoUrl      = $a.repositoryUrl
        FirstSeen    = $a.firstSeenDate
        LastSeen     = $a.lastSeenDate
      })
    }

    # Determine if any CodeQL analysis branches exist
    $codeBranches = Get-CodeAnalysisBranches -project $proj -repoId $repoId
    $codeAnalyzed = ($codeBranches -and $codeBranches.Count -gt 0)

    # Classification
    if ($totalAlerts -gt 0) {
      $withRows.Add([pscustomobject]@{
        Organization            = $Organization
        Project                 = $proj
        Repository              = $repoName
        RepositoryId            = $repoId
        DefaultBranch           = $defaultBranch
        SupportedLangs          = $langInfo.SupportedLangs
        HasAnyCode              = $langInfo.HasAnyCode
        CodeQLAnalyzedBranches  = ($codeBranches | ForEach-Object { $_.name }) -join ","
        Alerts_Total            = $totalAlerts
        Alerts_Code             = $byType["code"]
        Alerts_Dependency       = $byType["dependency"]
        Alerts_Secret           = $byType["secret"]
        Sev_Critical            = $bySeverity["critical"]
        Sev_High                = $bySeverity["high"]
        Sev_Medium              = $bySeverity["medium"]
        Sev_Low                 = $bySeverity["low"]
      })
    }
    else {
      # No alerts — find reason
      $reason = "NoAlerts"
      if (-not $langInfo.HasAnyCode) {
        $reason = "NoCode"
      }
      elseif (-not $codeAnalyzed -and ($langInfo.SupportedLangsArr.Count -eq 0)) {
        $reason = "UnsupportedLanguage"
      }
      $noRows.Add([pscustomobject]@{
        Organization            = $Organization
        Project                 = $proj
        Repository              = $repoName
        RepositoryId            = $repoId
        DefaultBranch           = $defaultBranch
        SupportedLangs          = $langInfo.SupportedLangs
        HasAnyCode              = $langInfo.HasAnyCode
        CodeQLAnalyzedBranches  = ($codeBranches | ForEach-Object { $_.name }) -join ","
        Reason                  = $reason
      })
    }
  }
}

# Export CSVs
$alertsRows | Export-Csv -Path $alertsCsvPath -NoTypeInformation -Encoding UTF8
$withRows   | Export-Csv -Path $reposWithVulnsPath -NoTypeInformation -Encoding UTF8
$noRows     | Export-Csv -Path $reposNoVulnsPath -NoTypeInformation -Encoding UTF8

Write-Host "Done. Files:" -ForegroundColor Green
Write-Host " - $alertsCsvPath"
Write-Host " - $reposWithVulnsPath"
Write-Host " - $reposNoVulnsPath"