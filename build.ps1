# Compila dnet-server y dnet-client para todas las combinaciones de
# GOOS/GOARCH soportadas, dejando los binarios en dist/<programa>/.
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

$Targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" }
    @{ GOOS = "linux";   GOARCH = "amd64"; Ext = ""     }
    @{ GOOS = "linux";   GOARCH = "arm64"; Ext = ""     }
    @{ GOOS = "darwin";  GOARCH = "amd64"; Ext = ""     }
    @{ GOOS = "darwin";  GOARCH = "arm64"; Ext = ""     }
)

function Build-Target($Prog, $Goos, $Goarch, $Ext) {
    $OutDir = "dist\$Prog"
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $Out = "..\$OutDir\dnet-$Prog-$Goos-$Goarch$Ext"

    Write-Host "==> $Prog $Goos/$Goarch"

    Push-Location $Prog
    try {
        $env:GOOS = $Goos
        $env:GOARCH = $Goarch
        $env:CGO_ENABLED = "0"
        go build -o $Out .
    } finally {
        Pop-Location
        Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
    }
}

foreach ($prog in @("server", "client")) {
    foreach ($t in $Targets) {
        Build-Target -Prog $prog -Goos $t.GOOS -Goarch $t.GOARCH -Ext $t.Ext
    }
}

Write-Host ""
Write-Host "Binarios generados en dist/"
