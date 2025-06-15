<#
    .SYNOPSIS
        Modificación de datos de host en DNS
    .DESCRIPTION
        El script agregará, editará o eliminará un host tanto en fowarder como en inverse, revisando previamente si existe el puntero
    .INPUTS
        Ninguno
    .OUTPUTS
        Fichero de backup y log con las acciones realizadas
    .NOTES
        Version: 1.2
        Author: Juan L. Clemente 
        Last Mod: 05 2025
    .EXAMPLE
        .\changeDNS.ps1
#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------
$allLogPaths = @(
    "C:\Windows\Logs\changeDNS.log",
    "\\vdc.adm\sysvol\vdc.adm\Logs\DNS\changeDNS.log"
)

$logPaths = @()
foreach ($path in $allLogPaths) {
    $folder = Split-Path $path
    try {
        if (-not (Test-Path $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }

        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType File -Force | Out-Null
        }

        Add-Content -Path $path -Value "$(Get-Date) - Verificación de acceso a log"
        $logPaths += $path
    }
    catch {
        Write-Host "No se puede acceder a: $path. Será omitido del log." -ForegroundColor Yellow
    }
}

$backupPath = "C:\Windows\Logs\backupDNS.log"

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Write-Log {
    param (
        [string]$message
    )
    foreach ($path in $logPaths) {
        $message | Out-File -FilePath $path -Append -Encoding UTF8
    }
}

function Backup-HostRecord {
    param (
        [string]$zoneName,
        [string]$recordName
    )

    $record = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -ErrorAction SilentlyContinue
    if ($record) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $record | ForEach-Object {
            "$timestamp - BACKUP - Zona: $zoneName - Host: $recordName - Tipo: $($_.RecordType) - Datos: $($_.RecordData.IPv4Address)" |
            Out-File $backupPath -Append
        }
        Write-Host "Copia de seguridad realizada para el host $recordName en la zona $zoneName." -ForegroundColor Green
    }
    else {
        Write-Host "No se encontró ningún registro existente para el host $recordName en la zona $zoneName." -ForegroundColor Yellow
    }
}

function Add-PTRRecord {
    param (
        [string]$ipAddress,
        [string]$fqdn
    )

    $ipParts = $ipAddress -split '\.'
    $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
    $ptrRecordName = "$($ipParts[3])"

    try {
        Add-DnsServerResourceRecordPtr -ZoneName $reverseZone -Name $ptrRecordName -PtrDomainName $fqdn -ErrorAction Stop
        Write-Log "$(Get-Date) - PTR agregado para $fqdn en $reverseZone"
        Write-Host "PTR agregado correctamente para $fqdn en la zona inversa $reverseZone." -ForegroundColor Green
        Write-Host "Las evidencias estan guardadas en c:\windows\logs\chageDNS.log"
    }
    catch {
        Write-Host "Error al agregar PTR para ${fqdn}: $_" -ForegroundColor Red
    }
}

function Remove-PTRRecord {
    param (
        [string]$ipAddress,
        [string]$fqdn
    )

    $ipParts = $ipAddress -split '\.'
    $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
    $ptrRecordName = "$($ipParts[3])"

    $ptrExists = Get-DnsServerResourceRecord -ZoneName $reverseZone -Name $ptrRecordName -RRType PTR -ErrorAction SilentlyContinue
    if ($ptrExists) {
        Remove-DnsServerResourceRecord -ZoneName $reverseZone -Name $ptrRecordName -RRType PTR -RecordData $fqdn -Force
        Write-Log "$(Get-Date) - Eliminado PTR record $ptrRecordName de zona $reverseZone"
        Write-Host "PTR eliminado para $fqdn en la zona $reverseZone." -ForegroundColor Green
        Write-Host "Las evidencias estan guardadas en c:\windows\logs\chageDNS.log"
    }
    else {
        Write-Host "No se encontró un registro PTR existente para eliminar." -ForegroundColor Yellow
    }
}

function Remove-HostRecord {
    param (
        [string]$zoneName,
        [string]$recordName,
        [string]$ipAddress
    )

    Backup-HostRecord -zoneName $zoneName -recordName $recordName

    try {
        Remove-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -RRType "A" -RecordData $ipAddress -Force
        Write-Log "$(Get-Date) - Eliminado A record $recordName ($ipAddress) de zona $zoneName"
        Write-Host "Registro A eliminado correctamente para $recordName en la zona $zoneName." -ForegroundColor Green
        Write-Host "Las evidencias estan guardadas en c:\windows\logs\chageDNS.log"
        Remove-PTRRecord -ipAddress $ipAddress -fqdn "$recordName.$zoneName."
    }
    catch {
        Write-Host "Error al eliminar registros: $_" -ForegroundColor Red
    }
}

function Edit-HostRecord {
    param (
        [string]$zoneName,
        [string]$recordName,
        [string]$newIpAddress
    )

    Backup-HostRecord -zoneName $zoneName -recordName $recordName

    $existingRecord = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -ErrorAction SilentlyContinue
    if ($existingRecord) {
        $oldIpAddress = $existingRecord.RecordData.IPv4Address.ToString()
        Remove-HostRecord -zoneName $zoneName -recordName $recordName -ipAddress $oldIpAddress
    }

    try {
        Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $recordName -IPv4Address $newIpAddress
        Write-Log "$(Get-Date) - Actualizado host $recordName con nueva IP $newIpAddress en zona $zoneName"
        Write-Host "Registro A actualizado correctamente para $recordName con IP $newIpAddress." -ForegroundColor Green
        Write-Host "Las evidencias estan guardadas en c:\windows\logs\chageDNS.log"

        Add-PTRRecord -ipAddress $newIpAddress -fqdn "$recordName.$zoneName."
    }
    catch {
        Write-Host "Error al editar registros: $_" -ForegroundColor Red
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------
function Show-Menu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "         GESTIÓN DE HOSTS DNS" -ForegroundColor Cyan
    Write-Host "            Telefónica TCCT"
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Agregar host"
    Write-Host "2. Eliminar host"
    Write-Host "3. Editar host"
    Write-Host "4. Cargar archivo CSV"
    Write-Host "5. Salir"
    Write-Host ""
}

do {
    Show-Menu
    $option = Read-Host "Seleccione una opción (1-4)"

    switch ($option) {
        '1' {
            $zoneName = Read-Host "Ingrese el nombre de la zona (ej. midominio.local)"
            $recordName = Read-Host "Ingrese el nombre del host"
            $ipAddress = Read-Host "Ingrese la dirección IP"

            Write-Host "Verificando si el host ya existe en la zona $zoneName..."

            $existingRecord = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -ErrorAction SilentlyContinue

            if ($existingRecord) {
                Write-Host "El host '$recordName' ya existe en la zona '$zoneName'." -ForegroundColor Yellow
            } else {
                try {
                    Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $recordName -IPv4Address $ipAddress -ErrorAction Stop
                    Write-Log "$(Get-Date) - Host $recordName agregado con IP $ipAddress en zona $zoneName"
                    Write-Host "Host agregado correctamente en la zona $zoneName." -ForegroundColor Green

                    Add-PTRRecord -ipAddress $ipAddress -fqdn "$recordName.$zoneName."
                }
                catch {
                    Write-Host "Error al agregar el host: $_" -ForegroundColor Red
                }
            }

            Pause
        }
        '2' {
            $zoneName = Read-Host "Ingrese el nombre de la zona"
            $recordName = Read-Host "Ingrese el nombre del host a eliminar"
            $ipAddress = Read-Host "Ingrese la IP asociada al host"

            Remove-HostRecord -zoneName $zoneName -recordName $recordName -ipAddress $ipAddress
            Pause
        }
        '3' {
            $zoneName = Read-Host "Ingrese el nombre de la zona"
            $recordName = Read-Host "Ingrese el nombre del host"
            $newIp = Read-Host "Ingrese la nueva IP"

            $existingRecord = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -ErrorAction SilentlyContinue

            if (-not $existingRecord) {
                Write-Host "El host '$recordName' no existe en la zona '$zoneName'." -ForegroundColor Yellow
            } else {
                Edit-HostRecord -zoneName $zoneName -recordName $recordName -newIpAddress $newIp
            }

            Pause
        }
        '4' {
            $csvPath = Read-Host "Ingrese la ruta completa del archivo CSV"
            $zoneName = Read-Host "Ingrese el nombre de la zona DNS (ej. midominio.local)"

            if (-not (Test-Path $csvPath)) {
                Write-Host "Archivo no encontrado en la ruta especificada." -ForegroundColor Red
                Pause
                return
            }

            try {
                $entries = Import-Csv -Path $csvPath

                foreach ($entry in $entries) {
                    $recordName = $entry.host
                    $ipAddress = $entry.ip

                    if (-not $recordName -or -not $ipAddress) {
                        Write-Host "Línea inválida en el CSV: host o IP vacíos. Saltando..." -ForegroundColor Yellow
                        continue
                    }

                    $fqdn = "$recordName.$zoneName"
                    $existingRecord = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -ErrorAction SilentlyContinue

                    if ($existingRecord) {
                        Write-Host "El host '$recordName' ya existe en la zona '$zoneName'. No se agregó." -ForegroundColor Yellow
                        Write-Log "$(Get-Date) - El host '$recordName' ya existe. No se agregó."
                    } else {
                        try {
                            Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $recordName -IPv4Address $ipAddress -ErrorAction Stop
                            Write-Log "$(Get-Date) - Host $recordName agregado con IP $ipAddress en zona $zoneName desde CSV"
                            Write-Host "Host $recordName agregado correctamente." -ForegroundColor Green
                            Write-Host "Las evidencias estan guardadas en c:\windows\logs\chageDNS.log"

                            Add-PTRRecord -ipAddress $ipAddress -fqdn $fqdn
                        }
                        catch {
                            Write-Host "Error al agregar el host ${recordName}: $_" -ForegroundColor Red
                            Write-Log "$(Get-Date) - Error al agregar host $recordName desde CSV: $_"
                        }
                    }
                }
            }
            catch {
                Write-Host "Error al procesar el archivo CSV: $_" -ForegroundColor Red
                Write-Log "$(Get-Date) - Error al procesar archivo CSV: $_"
            }

            Pause
        }

        '5' {
            Write-Host "Saliendo del script..." -ForegroundColor Cyan
        }
        default {
            Write-Host "Opción no válida. Intente de nuevo." -ForegroundColor Red
            Pause
        }
    }
} while ($option -ne '5')
