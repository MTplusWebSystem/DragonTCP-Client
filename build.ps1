<#
.SYNOPSIS
    Script PowerShell para compilar o DragonTCP Client para Android utilizando o NDK 30.

.DESCRIPTION
    Compila o DragonTCP Client para Android via CGO utilizando as toolchains LLVM/Clang
    do Android NDK (API Level 30).
    
    Salva o arquivo compilado como:
      libdragontcp_client.so
    
    na pasta 'builds', organizado por arquitetura:
      builds/<ABI>/libdragontcp_client.so   (formato padrão jniLibs do Android)
      builds/libdragontcp_client-<ABI>.so  (formato plano)
      builds/libdragontcp_client.so        (cópia principal da última/única ABI)

.PARAMETER ApiLevel
    Nível da API do Android NDK (padrão: 30).

.PARAMETER Abi
    Arquiteturas a compilar: "all", "arm64-v8a", "armeabi-v7a", "x86_64", "x86" (padrão: "arm64-v8a").
    Use "all" para gerar binários para todas as 4 arquiteturas.

.PARAMETER NdkPath
    Caminho base do Android NDK. Se omitido, o script detecta automaticamente a instalação do NDK 30.

.PARAMETER OutputDir
    Pasta de saída dos binários compilados (padrão: "builds").

.EXAMPLE
    .\build.ps1
    Compila para arm64-v8a (padrão para dispositivos Android modernos) gerando builds/arm64-v8a/libdragontcp_client.so e builds/libdragontcp_client.so.

.EXAMPLE
    .\build.ps1 -Abi all
    Compila para todas as 4 arquiteturas Android (arm64-v8a, armeabi-v7a, x86_64, x86).
#>

[CmdletBinding()]
param (
    [int]$ApiLevel = 30,
    [ValidateSet("all", "arm64-v8a", "armeabi-v7a", "x86_64", "x86")]
    [string]$Abi = "arm64-v8a",
    [string]$NdkPath = "",
    [string]$OutputDir = "builds"
)

$ErrorActionPreference = "Stop"

$OutputFileName = "libdragontcp_client.so"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-ErrMsg {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

# 1. Localização automática do Android NDK
Write-Step "Localizando Android NDK (API $ApiLevel)..."

$candidatePaths = @(
    $NdkPath,
    $env:ANDROID_NDK_HOME,
    $env:ANDROID_NDK_ROOT,
    $env:NDK_HOME,
    "$env:LOCALAPPDATA\Android\Sdk\ndk\30.0.14904198",
    "$env:LOCALAPPDATA\Android\Sdk\ndk-bundle"
)

# Adiciona outros diretórios em %LOCALAPPDATA%\Android\Sdk\ndk se existirem
$ndkBase = "$env:LOCALAPPDATA\Android\Sdk\ndk"
if (Test-Path $ndkBase) {
    Get-ChildItem -Path $ndkBase -Directory | Sort-Object Name -Descending | ForEach-Object {
        $candidatePaths += $_.FullName
    }
}

$resolvedNdk = $null
foreach ($path in $candidatePaths) {
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path)) {
        $llvmCheck = Join-Path $path "toolchains\llvm\prebuilt\windows-x86_64\bin"
        if (Test-Path $llvmCheck) {
            $resolvedNdk = $path
            break
        }
    }
}

if (-not $resolvedNdk) {
    Write-ErrMsg "Android NDK não encontrado!"
    Write-Host "Instale o NDK via Android Studio ou informe o caminho via:" -ForegroundColor White
    Write-Host ".\build.ps1 -NdkPath 'C:\caminho\para\ndk\30.x'" -ForegroundColor Yellow
    exit 1
}

$llvmBin = Join-Path $resolvedNdk "toolchains\llvm\prebuilt\windows-x86_64\bin"
Write-Success "NDK localizado: $resolvedNdk"
Write-Host "Toolchain LLVM: $llvmBin" -ForegroundColor DarkGray

# 2. Matriz de arquiteturas suportadas
$allTargets = @(
    @{
        Abi      = "arm64-v8a"
        GoArch   = "arm64"
        GoArm    = ""
        ClangCmd = "aarch64-linux-android$ApiLevel-clang.cmd"
    },
    @{
        Abi      = "armeabi-v7a"
        GoArch   = "arm"
        GoArm    = "7"
        ClangCmd = "armv7a-linux-androideabi$ApiLevel-clang.cmd"
    },
    @{
        Abi      = "x86_64"
        GoArch   = "amd64"
        GoArm    = ""
        ClangCmd = "x86_64-linux-android$ApiLevel-clang.cmd"
    },
    @{
        Abi      = "x86"
        GoArch   = "386"
        GoArm    = ""
        ClangCmd = "i686-linux-android$ApiLevel-clang.cmd"
    }
)

if ($Abi -eq "all") {
    $targets = $allTargets
} else {
    $targets = @($allTargets | Where-Object { $_.Abi -eq $Abi })
}

# 3. Preparação do diretório de saída
$absOutputDir = Join-Path $PSScriptRoot $OutputDir
if (-not (Test-Path $absOutputDir)) {
    New-Item -ItemType Directory -Path $absOutputDir -Force | Out-Null
}

Write-Step "Iniciando compilação para $($targets.Count) arquitetura(s) -> $OutputFileName..."
$results = @()
$startTime = Get-Date

foreach ($target in $targets) {
    $targetAbi = $target.Abi
    $clangPath = Join-Path $llvmBin $target.ClangCmd

    if (-not (Test-Path $clangPath)) {
        Write-ErrMsg "Compilador não encontrado para $targetAbi em: $clangPath"
        continue
    }

    $abiDir = Join-Path $absOutputDir $targetAbi
    if (-not (Test-Path $abiDir)) {
        New-Item -ItemType Directory -Path $abiDir -Force | Out-Null
    }

    $outputSo = Join-Path $abiDir $OutputFileName
    $flatSo   = Join-Path $absOutputDir "libdragontcp_client-$targetAbi.so"
    $rootSo   = Join-Path $absOutputDir $OutputFileName

    Write-Host "`n>>> Compilando [$targetAbi] (GOARCH=$($target.GoArch), API=$ApiLevel)..." -ForegroundColor Magenta

    # Configura variáveis de ambiente para CGO Android cross-compile
    $env:CGO_ENABLED = "1"
    $env:GOOS        = "android"
    $env:GOARCH      = $target.GoArch
    if ($target.GoArm) {
        $env:GOARM = $target.GoArm
    } else {
        Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
    }
    $env:CC = $clangPath

    # Flags de otimização e strip de símbolos de debug
    $ldflags = "-s -w"

    Write-Host "Executando: go build -buildmode=pie -ldflags=`"$ldflags`" -o `"$outputSo`" ." -ForegroundColor DarkGray
    
    # Invoca diretamente o compilador Go com as flags adequadas (-buildmode=pie para binário executável Android)
    & go build -buildmode=pie "-ldflags=$ldflags" -o $outputSo .

    if ($LASTEXITCODE -ne 0) {
        Write-ErrMsg "Falha na compilação para $targetAbi (Código de saída: $LASTEXITCODE)"
        continue
    }

    # Copia para os caminhos convenientes em builds/
    Copy-Item -Path $outputSo -Destination $flatSo -Force
    Copy-Item -Path $outputSo -Destination $rootSo -Force

    # Sincroniza automaticamente para a pasta lib do app Android se existir
    $androidLib = Join-Path $PSScriptRoot "..\..\..\android\lib\$targetAbi"
    if (-not (Test-Path $androidLib)) {
        New-Item -ItemType Directory -Path $androidLib -Force | Out-Null
    }
    Copy-Item -Path $outputSo -Destination (Join-Path $androidLib $OutputFileName) -Force
    Write-Host "  -> Sincronizado para Android: android\lib\$targetAbi\$OutputFileName" -ForegroundColor DarkCyan

    # Limpa arquivos .h residuais se existirem
    $hHeader = [System.IO.Path]::ChangeExtension($outputSo, ".h")
    if (Test-Path $hHeader) {
        Remove-Item $hHeader -Force -ErrorAction SilentlyContinue
    }
    $hFlat = [System.IO.Path]::ChangeExtension($flatSo, ".h")
    if (Test-Path $hFlat) {
        Remove-Item $hFlat -Force -ErrorAction SilentlyContinue
    }
    $hRoot = [System.IO.Path]::ChangeExtension($rootSo, ".h")
    if (Test-Path $hRoot) {
        Remove-Item $hRoot -Force -ErrorAction SilentlyContinue
    }

    $soFile = Get-Item $outputSo
    $sizeMB = [math]::Round($soFile.Length / 1MB, 2)
    Write-Success "Gerado: $targetAbi/$OutputFileName ($sizeMB MB)"

    $results += [PSCustomObject]@{
        ABI       = $targetAbi
        Arquivo   = "$targetAbi/$OutputFileName"
        Tamanho   = "$sizeMB MB"
        Status    = "Sucesso"
    }
}

# 4. Resumo final
$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

Write-Step "Resumo da Compilação ($elapsed segundos)"
if ($results.Count -gt 0) {
    $results | Format-Table -AutoSize
    Write-Success "Arquivo principal gerado em: $absOutputDir\$OutputFileName"
    
    Write-Host "`nConteúdo da pasta '$OutputDir':" -ForegroundColor Cyan
    Get-ChildItem -Path $absOutputDir -Recurse -File | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
} else {
    Write-ErrMsg "Nenhum binário foi gerado com sucesso."
    exit 1
}
