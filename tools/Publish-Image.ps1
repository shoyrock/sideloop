param(
    [string]$Archive = (Join-Path $PSScriptRoot '../artifacts/sideloop-all-in-one-amd64.tar.gz')
)

$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = Join-Path $taskRoot 'artifacts'
$statusFile = Join-Path $artifactRoot 'publish-status.json'
$imageRepository = 'ghcr.io/shoyrock/sideloop'
$authDirectory = Join-Path $artifactRoot ('.registry-auth-' + [guid]::NewGuid().ToString('N'))
$expectedHash = 'd73ab9290ae249a5ca802cb2fb2f773fa22b9e758ab2d89322e97a3951bcfc59'
$loginComplete = $false

function Set-PublishStatus([string]$State, [string]$Detail) {
    @{ state=$State; detail=$Detail; updated_at_utc=[DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $statusFile -Encoding utf8
}

function Invoke-CheckedDocker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw 'Docker command failed; see the publishing window.' }
}

try {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
    $actualHash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -ne $expectedHash) { throw 'Archive checksum does not match the tested image.' }
    $contextName = (& docker context show).Trim()
    $contextInfo = (& docker context inspect $contextName | ConvertFrom-Json)[0]
    $engineEndpoint = $contextInfo.Endpoints.docker.Host
    Invoke-CheckedDocker load -i $Archive
    $imagePlatform = (& docker image inspect sideloop:all-in-one --format '{{.Os}}/{{.Architecture}}').Trim()
    if ($imagePlatform -ne 'linux/amd64') { throw 'The loaded image is not linux/amd64.' }
    New-Item -ItemType Directory -Path $authDirectory | Out-Null
    Set-PublishStatus 'waiting_for_token' 'Enter a GitHub token for shoyrock with write:packages permission in the publishing window.'
    $Host.UI.RawUI.WindowTitle = 'Sideloop - publish image to GitHub Container Registry'
    Write-Host "Publishing the tested image to $imageRepository"
    Write-Host 'Enter a GitHub personal access token for shoyrock with write:packages permission.'
    Write-Host 'Use a token, not your GitHub account password. The token is hidden and is not saved in the project.'
    $secureToken = Read-Host 'GitHub package token' -AsSecureString
    $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try {
        $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
        $tokenAccount = Invoke-RestMethod -Uri 'https://api.github.com/user' -Headers @{Authorization="Bearer $plainToken"; Accept='application/vnd.github+json'}
        if ($tokenAccount.login -ne 'shoyrock') { throw 'The token must belong to shoyrock, the destination repository owner.' }
        $plainToken | & docker --config $authDirectory --host $engineEndpoint login ghcr.io --username shoyrock --password-stdin
        if ($LASTEXITCODE -ne 0) { throw 'GitHub Container Registry login failed.' }
        $loginComplete = $true
    } finally {
        $plainToken = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
        $secureToken.Dispose()
    }
    Set-PublishStatus 'publishing' 'Uploading the verified amd64 image from the local Docker engine.'
    foreach ($imageTag in @('all-in-one-amd64','all-in-one','latest','all-in-one-amd64-2026.10.08')) {
        Invoke-CheckedDocker tag sideloop:all-in-one "${imageRepository}:$imageTag"
        Invoke-CheckedDocker --config $authDirectory --host $engineEndpoint push "${imageRepository}:$imageTag"
    }
    Set-PublishStatus 'complete' "Published ${imageRepository}:all-in-one-amd64"
    Write-Host 'Image publication completed. The package must be public for anonymous Unraid pulls.'
} catch {
    Set-PublishStatus 'failed' $_.Exception.Message
    Write-Host $_.Exception.Message -ForegroundColor Red
} finally {
    if ($loginComplete) { & docker --config $authDirectory logout ghcr.io | Out-Null }
    $checkedAuthPath = [IO.Path]::GetFullPath($authDirectory)
    $checkedArtifactPath = [IO.Path]::GetFullPath($artifactRoot) + [IO.Path]::DirectorySeparatorChar
    if ($checkedAuthPath.StartsWith($checkedArtifactPath, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $checkedAuthPath)) {
        Remove-Item -LiteralPath $checkedAuthPath -Recurse -Force
    }
}
Read-Host 'Press Enter to close' | Out-Null
