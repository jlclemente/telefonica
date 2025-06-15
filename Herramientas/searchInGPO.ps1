param (
    [string[]]$SearchPatterns
)

# Rutas de trabajo
$logPath = "C:\script\GPO_SearchLog.log"
$scriptDir = "C:\script"
$tempReportDir = "C:\Temp\GPOReports"

# Verificar y crear directorio de logs
if (-not (Test-Path -Path $scriptDir)) {
    try {
        New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    } catch {
        Write-Host "Error al crear el directorio C:\script: $_"
        exit
    }
}

# Iniciar log
"==== Inicio del análisis de GPOs: $(Get-Date) ====" | Out-File -FilePath $logPath

# Validar que se han ingresado patrones
if (-not $SearchPatterns -or $SearchPatterns.Count -eq 0) {
    "Error: Debe especificar al menos una cadena de búsqueda." | Out-File -FilePath $logPath -Append
    exit
}

# Crear carpeta temporal para informes si no existe
if (-not (Test-Path -Path $tempReportDir)) {
    try {
        New-Item -ItemType Directory -Path $tempReportDir -Force | Out-Null
    } catch {
        "Error al crear el directorio de informes: $_" | Out-File -FilePath $logPath -Append
        exit
    }
}

# Obtener todas las GPOs
$gpos = Get-GPO -All

$results = @()

foreach ($gpo in $gpos) {
    $foundPatterns = @()
    $reportFileName = "$($gpo.DisplayName.Replace(' ', '_').Substring(0, [Math]::Min($gpo.DisplayName.Length, 50)))_Report.xml"
    $reportPath = Join-Path -Path $tempReportDir -ChildPath $reportFileName

    if (Test-Path -Path $reportPath) {
        Remove-Item -Path $reportPath -Force
    }

    try {
        Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $reportPath

        if (-not (Test-Path -Path $reportPath)) {
            "No se pudo generar el informe para la GPO '$($gpo.DisplayName)'." | Out-File -FilePath $logPath -Append
            continue
        }

        foreach ($pattern in $SearchPatterns) {
            $matches = Select-String -Path $reportPath -Pattern $pattern
            if ($matches) {
                $foundPatterns += $pattern
                "Encontrado '$pattern' en la GPO '$($gpo.DisplayName)'" | Out-File -FilePath $logPath -Append
                foreach ($line in $matches) {
                    "    Línea: $($line.Line)" | Out-File -FilePath $logPath -Append
                }
            }
        }
    } catch {
        "Error al procesar la GPO '$($gpo.DisplayName)': $_" | Out-File -FilePath $logPath -Append
    }

    $result = [PSCustomObject]@{
        GPOName       = $gpo.DisplayName
        FoundPatterns = if ($foundPatterns.Count -gt 0) { $foundPatterns -join ', ' } else { "Ninguna" }
    }
    $results += $result
}

# Escribir resumen
"`nResumen de resultados:" | Out-File -FilePath $logPath -Append
foreach ($result in $results) {
    "GPO: $($result.GPOName) - Encontrado: $($result.FoundPatterns)" | Out-File -FilePath $logPath -Append
}

# Limpiar archivos temporales
Remove-Item -Path $tempReportDir -Recurse -Force

"==== Fin del análisis: $(Get-Date) ====" | Out-File -FilePath $logPath -Append
param (
    [string[]]$SearchPatterns
)

# Rutas de trabajo
$logPath = "C:\script\GPO_SearchLog.log"
$scriptDir = "C:\script"
$tempReportDir = "C:\Temp\GPOReports"

# Verificar y crear directorio de logs
if (-not (Test-Path -Path $scriptDir)) {
    try {
        New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    } catch {
        Write-Host "Error al crear el directorio C:\script: $_"
        exit
    }
}

# Iniciar log
"==== Inicio del análisis de GPOs: $(Get-Date) ====" | Out-File -FilePath $logPath

# Validar que se han ingresado patrones
if (-not $SearchPatterns -or $SearchPatterns.Count -eq 0) {
    "Error: Debe especificar al menos una cadena de búsqueda." | Out-File -FilePath $logPath -Append
    exit
}

# Crear carpeta temporal para informes si no existe
if (-not (Test-Path -Path $tempReportDir)) {
    try {
        New-Item -ItemType Directory -Path $tempReportDir -Force | Out-Null
    } catch {
        "Error al crear el directorio de informes: $_" | Out-File -FilePath $logPath -Append
        exit
    }
}

# Obtener todas las GPOs
$gpos = Get-GPO -All

$results = @()

foreach ($gpo in $gpos) {
    $foundPatterns = @()
    $reportFileName = "$($gpo.DisplayName.Replace(' ', '_').Substring(0, [Math]::Min($gpo.DisplayName.Length, 50)))_Report.xml"
    $reportPath = Join-Path -Path $tempReportDir -ChildPath $reportFileName

    if (Test-Path -Path $reportPath) {
        Remove-Item -Path $reportPath -Force
    }

    try {
        Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $reportPath

        if (-not (Test-Path -Path $reportPath)) {
            "No se pudo generar el informe para la GPO '$($gpo.DisplayName)'." | Out-File -FilePath $logPath -Append
            continue
        }

        foreach ($pattern in $SearchPatterns) {
            $matches = Select-String -Path $reportPath -Pattern $pattern
            if ($matches) {
                $foundPatterns += $pattern
                "Encontrado '$pattern' en la GPO '$($gpo.DisplayName)'" | Out-File -FilePath $logPath -Append
                foreach ($line in $matches) {
                    "    Línea: $($line.Line)" | Out-File -FilePath $logPath -Append
                }
            }
        }
    } catch {
        "Error al procesar la GPO '$($gpo.DisplayName)': $_" | Out-File -FilePath $logPath -Append
    }

    $result = [PSCustomObject]@{
        GPOName       = $gpo.DisplayName
        FoundPatterns = if ($foundPatterns.Count -gt 0) { $foundPatterns -join ', ' } else { "Ninguna" }
    }
    $results += $result
}

# Escribir resumen
"`nResumen de resultados:" | Out-File -FilePath $logPath -Append
foreach ($result in $results) {
    "GPO: $($result.GPOName) - Encontrado: $($result.FoundPatterns)" | Out-File -FilePath $logPath -Append
}

# Limpiar archivos temporales
Remove-Item -Path $tempReportDir -Recurse -Force

"==== Fin del análisis: $(Get-Date) ====" | Out-File -FilePath $logPath -Append
