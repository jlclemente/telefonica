# Número de días
$dias = 45
$fechaLimite = (Get-Date).AddDays(-$dias)
$hoy = Get-Date
$logPath = "C:\Windows\Logs\deleteFiles.log"

# Crear/Clear log
"Log de eliminación de archivos - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $logPath -Encoding UTF8

# Función para registrar en log
function Escribir-Log {
    param (
        [string]$filePath,
        [int]$diasAntiguedad
    )
    $linea = "$filePath | $diasAntiguedad días | Eliminado el $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Content -Path $logPath -Value $linea
}

# 1. Eliminar archivos antiguos en la carpeta Logs
$logsPath = "E:\Scripts\CopiaFicherosEditranSFTP\Logs"
Get-ChildItem -Path $logsPath -File -Recurse | Where-Object { $_.LastWriteTime -lt $fechaLimite } | ForEach-Object {
    $diasAntiguedad = ($hoy - $_.LastWriteTime).Days
    Escribir-Log -filePath $_.FullName -diasAntiguedad $diasAntiguedad
    Remove-Item $_.FullName -Force
}

# 2. Función para limpiar subcarpetas N43\Procesados y N43\Erroneos
function Limpiar-SubcarpetasN43 {
    param (
        [string]$raiz
    )

    Get-ChildItem -Path $raiz -Directory | ForEach-Object {
        $n43Path = Join-Path $_.FullName "N43"
        if (Test-Path $n43Path) {
            @("Procesados", "Erroneos") | ForEach-Object {
                $subPath = Join-Path $n43Path $_
                if (Test-Path $subPath) {
                    Get-ChildItem -Path $subPath -File -Recurse | Where-Object { $_.LastWriteTime -lt $fechaLimite } | ForEach-Object {
                        $diasAntiguedad = ($hoy - $_.LastWriteTime).Days
                        Escribir-Log -filePath $_.FullName -diasAntiguedad $diasAntiguedad
                        Remove-Item $_.FullName -Force
                    }
                }
            }
        }
    }
}

# Aplicar la función a las dos rutas
Limpiar-SubcarpetasN43 -raiz "E:\DATOS_BANCOS"
Limpiar-SubcarpetasN43 -raiz "E:\SFTP"
