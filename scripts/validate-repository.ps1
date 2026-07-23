[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$failures = [System.Collections.Generic.List[string]]::new()
$strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)

function Add-ValidationFailure {
  param([Parameter(Mandatory)][string] $Message)

  $script:failures.Add($Message)
}

function Get-RepositoryPath {
  param([Parameter(Mandatory)][string] $RelativePath)

  return [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $RelativePath))
}

$requiredFiles = @(
  '.editorconfig'
  '.gitattributes'
  '.gitignore'
  '.github/CODEOWNERS'
  '.github/PULL_REQUEST_TEMPLATE.md'
  '.github/ISSUE_TEMPLATE/bug.yml'
  '.github/ISSUE_TEMPLATE/config.yml'
  '.github/ISSUE_TEMPLATE/feature.yml'
  '.github/ISSUE_TEMPLATE/spike.yml'
  '.github/workflows/repository-ci.yml'
  'CHANGELOG.md'
  'CODE_OF_CONDUCT.md'
  'CONTRIBUTING.md'
  'GOVERNANCE.md'
  'LICENSE'
  'README.md'
  'ROADMAP.md'
  'SECURITY.md'
  'SUPPORT.md'
  'docs/adr/0000-template.md'
  'docs/adr/README.md'
  'docs/branching-and-releases.md'
  'scripts/validate-repository.ps1'
)

foreach ($relativePath in $requiredFiles) {
  if (-not (Test-Path -LiteralPath (Get-RepositoryPath $relativePath) -PathType Leaf)) {
    Add-ValidationFailure "Required file is missing: $relativePath"
  }
}

$binaryExtensions = @(
  '.gif', '.ico', '.jpeg', '.jpg', '.png', '.webp', '.woff', '.woff2'
)

$repositoryFiles = @(
  & git -c core.quotepath=false -C $repositoryRoot ls-files --cached --others --exclude-standard
)
if ($LASTEXITCODE -ne 0) {
  throw 'Unable to enumerate repository files with git.'
}

$textFiles = $repositoryFiles |
  Where-Object {
    $extension = [System.IO.Path]::GetExtension($_).ToLowerInvariant()
    $binaryExtensions -notcontains $extension
  } |
  Sort-Object -Unique

foreach ($relativePath in $textFiles) {
  $absolutePath = Get-RepositoryPath $relativePath
  if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
    continue
  }

  $bytes = [System.IO.File]::ReadAllBytes($absolutePath)
  if ($bytes.Length -ge 3 -and
      $bytes[0] -eq 0xEF -and
      $bytes[1] -eq 0xBB -and
      $bytes[2] -eq 0xBF) {
    Add-ValidationFailure "UTF-8 BOM is not allowed: $relativePath"
  }

  try {
    $content = $strictUtf8.GetString($bytes)
  }
  catch [System.Text.DecoderFallbackException] {
    Add-ValidationFailure "File is not valid UTF-8: $relativePath"
    continue
  }

  if ($bytes.Length -eq 0 -or $bytes[$bytes.Length - 1] -ne 0x0A) {
    Add-ValidationFailure "File must end with a newline: $relativePath"
  }

  $lineNumber = 0
  foreach ($line in ($content -split "`r`n|`n|`r")) {
    $lineNumber++
    if ($line -match '[\x20\t]+$') {
      Add-ValidationFailure "Trailing whitespace: ${relativePath}:$lineNumber"
    }
  }
}

$markdownFiles = $textFiles | Where-Object { $_.EndsWith('.md', [System.StringComparison]::OrdinalIgnoreCase) }
$rootPrefix = $repositoryRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
$markdownLinkPattern = '!?' + '\[[^\]]*\]\((?<target>[^)]+)\)'

foreach ($relativePath in $markdownFiles) {
  $absolutePath = Get-RepositoryPath $relativePath
  $content = [System.IO.File]::ReadAllText($absolutePath, $strictUtf8)

  $visibleLines = [System.Collections.Generic.List[string]]::new()
  $inCodeFence = $false
  $fenceCharacter = [char]0
  foreach ($line in ($content -split "`r`n|`n|`r")) {
    if ($line -match '^\s*(?<fence>`{3,}|~{3,})') {
      $currentFenceCharacter = $Matches['fence'][0]
      if (-not $inCodeFence) {
        $inCodeFence = $true
        $fenceCharacter = $currentFenceCharacter
      }
      elseif ($currentFenceCharacter -eq $fenceCharacter) {
        $inCodeFence = $false
        $fenceCharacter = [char]0
      }
      continue
    }

    if (-not $inCodeFence) {
      $visibleLines.Add($line)
    }
  }
  if ($inCodeFence) {
    Add-ValidationFailure "Unclosed Markdown code fence: $relativePath"
  }

  $visibleContent = $visibleLines -join "`n"
  $visibleContent = [System.Text.RegularExpressions.Regex]::Replace(
    $visibleContent,
    '`[^`\r\n]*`',
    ''
  )
  $rawTargets = [System.Collections.Generic.List[string]]::new()
  foreach ($match in [System.Text.RegularExpressions.Regex]::Matches($visibleContent, $markdownLinkPattern)) {
    $rawTargets.Add($match.Groups['target'].Value)
  }
  $referenceDefinitionPattern = '(?m)^[ \t]*\[(?!\^)[^\]]+\]:[ \t]*(?<target><[^>]+>|[^\s]+)'
  foreach ($match in [System.Text.RegularExpressions.Regex]::Matches($visibleContent, $referenceDefinitionPattern)) {
    $rawTargets.Add($match.Groups['target'].Value)
  }

  foreach ($rawTargetValue in $rawTargets) {
    $rawTarget = $rawTargetValue.Trim()
    if ($rawTarget.StartsWith('<')) {
      $closingBracket = $rawTarget.IndexOf('>')
      if ($closingBracket -lt 1) {
        Add-ValidationFailure "Malformed Markdown link in ${relativePath}: $rawTarget"
        continue
      }
      $target = $rawTarget.Substring(1, $closingBracket - 1)
    }
    else {
      $target = ($rawTarget -split '\s+', 2)[0]
    }

    if ([string]::IsNullOrWhiteSpace($target) -or
        $target.StartsWith('#') -or
        $target.StartsWith('//') -or
        $target -match '^[A-Za-z][A-Za-z0-9+.-]*:') {
      continue
    }

    $pathOnly = ($target -split '[?#]', 2)[0]
    if ([string]::IsNullOrWhiteSpace($pathOnly)) {
      continue
    }

    try {
      $decodedPath = [System.Uri]::UnescapeDataString($pathOnly).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
      $candidatePath = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetDirectoryName($absolutePath)) $decodedPath))
    }
    catch {
      Add-ValidationFailure "Invalid relative Markdown link in ${relativePath}: $target"
      continue
    }

    $isWithinRepository =
      $candidatePath.Equals($repositoryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
      $candidatePath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $isWithinRepository -or
        -not (Test-Path -LiteralPath $candidatePath)) {
      Add-ValidationFailure "Broken relative Markdown link in ${relativePath}: $target"
    }
  }
}

$expectedIssueFormIds = [ordered]@{
  '.github/ISSUE_TEMPLATE/bug.yml' = @(
    'description', 'reproduction', 'fixture', 'expected', 'actual', 'version',
    'environment', 'logs', 'additional', 'confirmations'
  )
  '.github/ISSUE_TEMPLATE/feature.yml' = @(
    'problem', 'users', 'outcome', 'criteria', 'proposal', 'alternatives',
    'impact', 'context', 'confirmations'
  )
  '.github/ISSUE_TEMPLATE/spike.yml' = @(
    'question', 'decision', 'scope', 'options', 'criteria', 'timebox',
    'deliverables', 'risks', 'references'
  )
}

foreach ($entry in $expectedIssueFormIds.GetEnumerator()) {
  $absolutePath = Get-RepositoryPath $entry.Key
  if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
    continue
  }

  $content = [System.IO.File]::ReadAllText($absolutePath, $strictUtf8)
  if ($content.Contains("`t")) {
    Add-ValidationFailure "Tabs are not allowed in issue forms: $($entry.Key)"
  }

  foreach ($requiredKey in @('name:', 'description:', 'body:')) {
    if ($content -notmatch "(?m)^$([System.Text.RegularExpressions.Regex]::Escape($requiredKey))") {
      Add-ValidationFailure "Issue form is missing top-level '$requiredKey': $($entry.Key)"
    }
  }

  $actualIds = @(
    [System.Text.RegularExpressions.Regex]::Matches($content, '(?m)^\s+id:\s*([A-Za-z][A-Za-z0-9_-]*)\s*$') |
      ForEach-Object { $_.Groups[1].Value }
  )
  $duplicateIds = $actualIds | Group-Object | Where-Object Count -gt 1 | Select-Object -ExpandProperty Name
  foreach ($duplicateId in $duplicateIds) {
    Add-ValidationFailure "Duplicate issue-form id '$duplicateId': $($entry.Key)"
  }

  if (($actualIds -join "`n") -ne ($entry.Value -join "`n")) {
    Add-ValidationFailure "Issue-form IDs changed unexpectedly: $($entry.Key)"
  }
}

$issueConfigPath = Get-RepositoryPath '.github/ISSUE_TEMPLATE/config.yml'
if (Test-Path -LiteralPath $issueConfigPath -PathType Leaf) {
  $issueConfig = [System.IO.File]::ReadAllText($issueConfigPath, $strictUtf8)
  if ($issueConfig.Contains("`t")) {
    Add-ValidationFailure 'Tabs are not allowed in issue forms: .github/ISSUE_TEMPLATE/config.yml'
  }
  if ($issueConfig -notmatch '(?m)^blank_issues_enabled:\s*false\s*$') {
    Add-ValidationFailure 'Blank issues must remain disabled.'
  }
}

$baseRef = if ($env:PROOF_BASE_REF) { $env:PROOF_BASE_REF } else { $env:GITHUB_BASE_REF }
$headRef = if ($env:PROOF_HEAD_REF) { $env:PROOF_HEAD_REF } else { $env:GITHUB_HEAD_REF }
$headRepository = $env:PROOF_HEAD_REPOSITORY
$pullRequestAuthor = $env:PROOF_PR_AUTHOR
$pullRequestTitle = $env:PROOF_PR_TITLE
$repository = if ($env:PROOF_REPOSITORY) { $env:PROOF_REPOSITORY } else { $env:GITHUB_REPOSITORY }
$sameRepository =
  $repository -and
  $headRepository -and
  $repository.Equals($headRepository, [System.StringComparison]::OrdinalIgnoreCase)

if ($baseRef -or $headRef) {
  if (-not $baseRef -or -not $headRef) {
    Add-ValidationFailure 'Both pull-request base and head refs must be provided.'
  }
  elseif ($baseRef -eq 'develop') {
    $validDevelopHead =
      ($headRef -eq 'main' -and $sameRepository) -or
      $headRef -match '^(feat|fix|spike|docs|chore)/[0-9]+-[a-z0-9][a-z0-9-]*$' -or
      ($headRef -match '^dependabot/.+$' -and $pullRequestAuthor -eq 'dependabot[bot]')
    if (-not $validDevelopHead) {
      Add-ValidationFailure "Branch '$headRef' is not allowed to target develop."
    }
  }
  elseif ($baseRef -eq 'main') {
    $validMainHead =
      ($headRef -eq 'develop' -and $sameRepository) -or
      $headRef -match '^hotfix/[0-9]+-[a-z0-9][a-z0-9-]*$'
    if (-not $validMainHead) {
      Add-ValidationFailure "Only develop or a hotfix branch may target main; received '$headRef'."
    }
  }
  else {
    Add-ValidationFailure "Pull requests must target develop or main; received '$baseRef'."
  }
}

if ($pullRequestTitle) {
  $conventionalTitlePattern = '^(feat|fix|docs|chore|refactor|test|ci|build|perf|revert|style)(\([a-z0-9][a-z0-9._/-]*\))?!?: .+'
  if ($pullRequestTitle -notmatch $conventionalTitlePattern) {
    Add-ValidationFailure "Pull-request title must follow Conventional Commits: $pullRequestTitle"
  }
}

if ($failures.Count -gt 0) {
  Write-Error ("Repository validation failed:`n- " + ($failures -join "`n- "))
  exit 1
}

Write-Host "Repository validation passed for $($textFiles.Count) text files."
