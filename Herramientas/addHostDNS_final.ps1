<#
    .SYNOPSIS
        Agregar nuevo host a DNS
    .DESCRIPTION
        El script agregara un nuevo host tanto en fowarder como en inverse, revisando previamente si exite el puntero

    .INPUTS
        Ninguno
    .OUTPUTS
        Fichero de backup y log con las acciones realizadas
    .NOTES
        Version: 1.0
        Author: Juan L. Clemente 
        Last Mod: 04 2025
    .EXAMPLE
        .\addHostDNS.ps1
#>
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$logPath = "C:\script\dns_changes.log"
$backupPath = "C:\script\dns_backup.txt"
$folderPath = "C:\script"
#-----------------------------------------------------------[Functions]------------------------------------------------------------
# Función para hacer backup de un registro
function Backup-Record {
    param(
        [string]$zoneName,
        [string]$recordName,
        [string]$rrType
    )
    try {
        $record = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -RRType $rrType -ErrorAction Stop
        Add-Content -Path $backupPath -Value "Backup $rrType Record [$recordName] in zone [$zoneName]:"
        Add-Content -Path $backupPath -Value ($record | Out-String)
        Write-Log "Backup realizado del registro $rrType [$recordName] en zona [$zoneName]."
    } catch {
        Write-Log "No se encontró el registro $rrType [$recordName] en zona [$zoneName] para backup."
    }
}
# Función para escribir en el log
function Write-Log {
    param(
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp - $message"
}
#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Solicitar datos al usuario
$hostName = Read-Host "Introduce el nombre del host"
$domainName = Read-Host "Introduce el nombre del dominio"
$expectedIP = Read-Host "Introduce la IP esperada"

if (-Not (Test-Path -Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
    Write-Host "Carpeta creada en $folderPath"
} else {
    Write-Host "La carpeta ya existe en $folderPath"
}

# Crear el FQDN
$fqdn = "$hostName.$domainName"

# Intentar resolver el FQDN a IP (Forward Lookup)
try {
    $resolvedIPs = [System.Net.Dns]::GetHostAddresses($fqdn) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -ExpandProperty IPAddressToString
} catch {
    $resolvedIPs = $null
}

$needToAdd = $false
$needToUpdate = $false
$currentIP = $null

if ($resolvedIPs) {
    Write-Host "El host $fqdn existe y resuelve a: $($resolvedIPs -join ", ")" -ForegroundColor Green
    Write-Log "Host $fqdn resuelve a: $($resolvedIPs -join ", ")"

    if ($resolvedIPs -contains $expectedIP) {
        Write-Host "La IP coincide con la esperada." -ForegroundColor Cyan
        Write-Log "La IP de $fqdn coincide con la esperada: $expectedIP."
    } else {
        Write-Host "La IP es diferente a la esperada." -ForegroundColor Yellow
        Write-Log "La IP de $fqdn es diferente. Actual: $($resolvedIPs -join ", "), Esperada: $expectedIP."
        $needToUpdate = $true
        $currentIP = $resolvedIPs[0]
    }
} else {
    Write-Host "El host $fqdn NO existe o no se puede resolver." -ForegroundColor Red
    Write-Log "Host $fqdn no existe en DNS."
    $needToAdd = $true
}

if ($needToAdd) {
    $addRecord = Read-Host "¿Deseas agregar el registro en la zona FORWARD y REVERSE? (S/N)"
    if ($addRecord -match "^[Ss]$") {
        try {
            Add-DnsServerResourceRecordA -Name $hostName -ZoneName $domainName -IPv4Address $expectedIP
            Write-Host "Registro A agregado correctamente en la zona FORWARD." -ForegroundColor Green
            Write-Log "Registro A [$fqdn -> $expectedIP] agregado en zona $domainName."
        } catch {
            Write-Host "Error al agregar el registro A: $_" -ForegroundColor Red
            Write-Log "Error al agregar registro A: $_"
        }

        # Crear registro PTR
        $ipParts = $expectedIP.Split('.')
        $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
        $ptrName = "$($ipParts[3])"

        try {
            Add-DnsServerResourceRecordPtr -Name $ptrName -ZoneName $reverseZone -PtrDomainName $fqdn
            Write-Host "Registro PTR agregado correctamente en la zona REVERSE." -ForegroundColor Green
            Write-Log "Registro PTR [$expectedIP -> $fqdn] agregado en zona $reverseZone."
        } catch {
            Write-Host "Error al agregar el registro PTR: $_" -ForegroundColor Red
            Write-Log "Error al agregar registro PTR: $_"
        }
    } else {
        Write-Host "No se realizará ninguna acción." -ForegroundColor Yellow
        Write-Log "Usuario decidió no agregar el registro."
    }
}

if ($needToUpdate) {
    $updateRecord = Read-Host "¿Deseas actualizar el registro A y PTR a la nueva IP? (S/N)"
    if ($updateRecord -match "^[Ss]$") {

        # Backup y eliminar registro A existente
        Backup-Record -zoneName $domainName -recordName $hostName -rrType "A"
        try {
            Remove-DnsServerResourceRecord -ZoneName $domainName -Name $hostName -RRType "A" -Force
            Write-Host "Registro A antiguo eliminado." -ForegroundColor Green
            Write-Log "Registro A [$fqdn] eliminado en zona $domainName."
        } catch {
            Write-Host "Error al eliminar el registro A antiguo: $_" -ForegroundColor Red
            Write-Log "Error al eliminar registro A antiguo: $_"
        }

        # Agregar nuevo registro A
        try {
            Add-DnsServerResourceRecordA -Name $hostName -ZoneName $domainName -IPv4Address $expectedIP
            Write-Host "Registro A actualizado correctamente." -ForegroundColor Green
            Write-Log "Registro A [$fqdn -> $expectedIP] actualizado en zona $domainName."
        } catch {
            Write-Host "Error al agregar el nuevo registro A: $_" -ForegroundColor Red
            Write-Log "Error al agregar el nuevo registro A: $_"
        }

        # Eliminar PTR antiguo si existe
        $oldIpParts = $currentIP.Split('.')
        $oldReverseZone = "$($oldIpParts[2]).$($oldIpParts[1]).$($oldIpParts[0]).in-addr.arpa"
        $oldPtrName = "$($oldIpParts[3])"

        Backup-Record -zoneName $oldReverseZone -recordName $oldPtrName -rrType "PTR"
        try {
            Remove-DnsServerResourceRecord -ZoneName $oldReverseZone -Name $oldPtrName -RRType "PTR" -Force
            Write-Host "Registro PTR antiguo eliminado." -ForegroundColor Green
            Write-Log "Registro PTR [$currentIP] eliminado de zona $oldReverseZone."
        } catch {
            Write-Host "No se encontró PTR antiguo para eliminar (puede no existir)." -ForegroundColor Yellow
            Write-Log "PTR antiguo [$currentIP] no encontrado o no pudo ser eliminado."
        }

        # Crear nuevo PTR
        $newIpParts = $expectedIP.Split('.')
        $newReverseZone = "$($newIpParts[2]).$($newIpParts[1]).$($newIpParts[0]).in-addr.arpa"
        $newPtrName = "$($newIpParts[3])"

        try {
            Add-DnsServerResourceRecordPtr -Name $newPtrName -ZoneName $newReverseZone -PtrDomainName $fqdn
            Write-Host "Registro PTR actualizado correctamente." -ForegroundColor Green
            Write-Log "Registro PTR [$expectedIP -> $fqdn] agregado en zona $newReverseZone."
        } catch {
            Write-Host "Error al agregar el nuevo registro PTR: $_" -ForegroundColor Red
            Write-Log "Error al agregar el nuevo registro PTR: $_"
        }
    } else {
        Write-Host "No se realizará ninguna actualización." -ForegroundColor Yellow
        Write-Log "Usuario decidió no actualizar los registros."
    }
}

Write-Host "Proceso terminado. Consulta los ficheros de log y backup en C:\script" -ForegroundColor Cyan

# Función para eliminar un registro DNS
function Remove-HostRecord {
    param (
        [string]$zoneName,
        [string]$recordName,
        [string]$ipAddress
    )
    try {
        # Eliminar registro A
        Remove-DnsServerResourceRecord -ZoneName $zoneName -RRType "A" -Name $recordName -Confirm:\$false
        Write-Output "$(Get-Date) - Registro A $recordName eliminado de la zona $zoneName" | Out-File $logPath -Append

        # Calcular zona inversa
        $ipParts = $ipAddress -split '\.'
        $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
        $ptrRecordName = "$($ipParts[3])"

        # Eliminar registro PTR
        Remove-DnsServerResourceRecord -ZoneName $reverseZone -RRType "PTR" -Name $ptrRecordName -Confirm:\$false
        Write-Output "$(Get-Date) - Registro PTR $ptrRecordName eliminado de la zona $reverseZone" | Out-File $logPath -Append
    } catch {
        Write-Output "$(Get-Date) - Error eliminando el registro: $_" | Out-File $logPath -Append
    }
}

# Función para editar un registro DNS
function Edit-HostRecord {
    param (
        [string]$zoneName,
        [string]$recordName,
        [string]$oldIpAddress,
        [string]$newIpAddress
    )
    # Eliminar registro antiguo
    Remove-HostRecord -zoneName $zoneName -recordName $recordName -ipAddress $oldIpAddress
    # Agregar nuevo registro
    Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $recordName -IPv4Address $newIpAddress
    Write-Output "$(Get-Date) - Registro A $recordName modificado a nueva IP $newIpAddress en zona $zoneName" | Out-File $logPath -Append

    # Crear nuevo registro PTR
    $ipParts = $newIpAddress -split '\.'
    $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
    $ptrRecordName = "$($ipParts[3])"
    Add-DnsServerResourceRecordPtr -ZoneName $reverseZone -Name $ptrRecordName -PtrDomainName "$recordName.$zoneName."
    Write-Output "$(Get-Date) - Registro PTR $ptrRecordName creado en zona $reverseZone apuntando a $recordName.$zoneName" | Out-File $logPath -Append
}


#-----------------------------------------------------------[Menú Principal]------------------------------------------------------------

function Show-Menu {
    Clear-Host
    Write-Host "========================================"
    Write-Host "         Gestión de Hosts DNS"
    Write-Host "========================================"
    Write-Host "1. Agregar host"
    Write-Host "2. Eliminar host"
    Write-Host "3. Editar host"
    Write-Host "4. Salir"
    Write-Host ""
}

do {
    Show-Menu
    $option = Read-Host "Seleccione una opción (1-4)"

    switch ($option) {
        '1' {
            $zoneName = Read-Host "Nombre de la zona (ej. midominio.local)"
            $recordName = Read-Host "Nombre del host"
            $ipAddress = Read-Host "Dirección IP"

            Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $recordName -IPv4Address $ipAddress
            Write-Output "$(Get-Date) - Host $recordName agregado con IP $ipAddress en zona $zoneName" | Out-File $logPath -Append

            $ipParts = $ipAddress -split '\.'
            $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
            $ptrRecordName = "$($ipParts[3])"
            Add-DnsServerResourceRecordPtr -ZoneName $reverseZone -Name $ptrRecordName -PtrDomainName "$recordName.$zoneName."
            Write-Output "$(Get-Date) - PTR agregado para $recordName en $reverseZone" | Out-File $logPath -Append

            Pause
        }
        '2' {
            $zoneName = Read-Host "Nombre de la zona"
            $recordName = Read-Host "Nombre del host a eliminar"
            $ipAddress = Read-Host "IP asociada al host"

            Remove-HostRecord -zoneName $zoneName -recordName $recordName -ipAddress $ipAddress
            Pause
        }
        '3' {
            $zoneName = Read-Host "Nombre de la zona"
            $recordName = Read-Host "Nombre del host"
            $oldIp = Read-Host "IP actual"
            $newIp = Read-Host "Nueva IP"

            Edit-HostRecord -zoneName $zoneName -recordName $recordName -oldIpAddress $oldIp -newIpAddress $newIp
            Pause
        }
        '4' {
            Write-Host "Saliendo del script..."
        }
        default {
            Write-Host "Opción no válida. Intente de nuevo." -ForegroundColor Red
            Pause
        }
    }
} while ($option -ne '4')
