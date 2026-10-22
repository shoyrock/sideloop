# Save a user-provided token for other agents working in this checkout.
# The token is never echoed or included in command arguments.
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$credentialDirectory = Join-Path $taskRoot '.local'
$tokenFile = Join-Path $credentialDirectory 'github-token'

Push-Location $taskRoot
try {
    & git check-ignore --quiet -- .local/github-token
    if ($LASTEXITCODE -ne 0) { throw 'The credential path must be Git-ignored before saving.' }
    $dockerIgnore = Get-Content -LiteralPath (Join-Path $taskRoot '.dockerignore')
    if ($dockerIgnore -notcontains '.local/') { throw 'The credential directory must be excluded from Docker builds.' }

    Write-Host 'Paste the GitHub personal access token. Input is hidden.'
    $secureToken = Read-Host 'GitHub token' -AsSecureString
    $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try {
        $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer).Trim()
        if (-not $plainToken) { throw 'No token entered; nothing was saved.' }
        New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null
        [IO.File]::WriteAllText($tokenFile, $plainToken, [Text.UTF8Encoding]::new($false))
    } finally {
        $plainToken = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
        $secureToken.Dispose()
    }
    Write-Host "Saved locally to $tokenFile (excluded from Git and Docker builds)."
} finally {
    Pop-Location
}
