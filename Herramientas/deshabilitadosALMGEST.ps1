<#
    .SYNOPSIS
        Deshabilitados usuarios con 90 dias sin uso y eliminado usuarios con 60 dias deshabilitados
    .DESCRIPTION
        El script deshabilitará aquellos usuarios que no hayan entrado en 90 dias y eliminará los que lleven 60 dias deshabilitados
    .INPUTS
        -ModoTest
    .OUTPUTS
        Fichero log con las acciones realizadas en c:\windows\Logs\deshabilitados.log
    .NOTES
        Version: 1.0
        Author: Juan L. Clemente 
        Last Mod: 06 2025
    .EXAMPLE
        .\deshabilitadosALMGEST.ps1 -ModoTest
        .\deshabilitadosALMGEST.ps1
#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------
param (
    [switch]$ModoTest
)

Import-Module ActiveDirectory

# Solicitar ticket
$Ticket = Read-Host "Introduce el número de ticket (ej. TICKET-1234)"

# Configuración
$DiasInactividad = 90
$DiasDeshabilitado = 60
$OUDestino = "OU=Usuarios deshabilitados,DC=almgest,DC=adm"
$Ahora = Get-Date
$Filtros = @("tz1", "zc", "zcx", "cb", "zu")
$LogFile = if ($ModoTest) { "C:\Windows\Logs\deshabilitados_TEST.log" } else { "C:\Windows\Logs\deshabilitados.log" }

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Crear log si no existe
if (-not (Test-Path $LogFile)) {
    New-Item -Path $LogFile -ItemType File -Force | Out-Null
    Write-Host "Log creado en $LogFile"
}

# Obtener todos los usuarios
$Usuarios = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, sAMAccountName, DistinguishedName, whenChanged, Name

# Deshabilitar y mover usuarios inactivos que coincidan con filtros
Write-Host "`nProcesando usuarios inactivos que coincidan con filtros"

$UsuariosInactivos = $Usuarios | Where-Object {
    $usuario = $_
    $usuario.Enabled -eq $true -and
    $usuario.LastLogonDate -ne $null -and
    ($Ahora - $usuario.LastLogonDate).Days -gt $DiasInactividad -and
    (($Filtros | Where-Object { 
        $filtro = $_.ToLower()
        $usuario.sAMAccountName.ToLower().Contains($filtro)
    }) | Measure-Object).Count -gt 0
}

foreach ($Usuario in $UsuariosInactivos) {
    try {
        $DiasSinActividad = ($Ahora - $Usuario.LastLogonDate).Days
        $OUOrigen = ($Usuario.DistinguishedName -replace "^CN=[^,]+,", "")
        $NombreCompleto = $Usuario.Name

        if (-not $ModoTest) {
            Disable-ADAccount -Identity $Usuario
            Move-ADObject -Identity $Usuario.DistinguishedName -TargetPath $OUDestino
        }

        $Prefix = if ($ModoTest) { "[SIMULADO - DESHABILITAR/MOVER]" } else { "[REAL]" }
        $LogMsg = "{0} | {1} | {2} | {3} | {4}" -f $Ahora.ToString("yyyy-MM-dd HH:mm:ss"), $Ticket, $NombreCompleto, $OUOrigen, $DiasSinActividad
        Add-Content -Path $LogFile -Value "$Prefix $LogMsg"
        Write-Host "$Prefix $LogMsg"
    }
    catch {
        $ErrorMsg = "[ERROR] {0} | {1} | {2}" -f $Ahora.ToString("yyyy-MM-dd HH:mm:ss"), $Ticket, $_.Exception.Message
        Add-Content -Path $LogFile -Value $ErrorMsg
        Write-Host $ErrorMsg -ForegroundColor Red
    }
}

# Eliminar usuarios deshabilitados hace más de $DiasDeshabilitado días y que coincidan con filtros
Write-Host "`nProcesando eliminación de usuarios deshabilitados hace más de $DiasDeshabilitado días que coincidan con filtros"

$UsuariosDeshabilitados = $Usuarios | Where-Object {
    $usuario = $_
    $usuario.Enabled -eq $false -and
    $usuario.whenChanged -ne $null -and
    ($usuario.whenChanged -is [datetime]) -and
    ($Ahora - [datetime]$usuario.whenChanged).Days -gt $DiasDeshabilitado -and
    (($Filtros | Where-Object { 
        $filtro = $_.ToLower()
        $usuario.sAMAccountName.ToLower().Contains($filtro)
    }) | Measure-Object).Count -gt 0
}

foreach ($Usuario in $UsuariosDeshabilitados) {
    try {
        if ($Usuario.whenChanged -eq $null) { throw "whenChanged es nulo" }
        $whenChangedDate = [datetime]$Usuario.whenChanged
        $DiasDesdeCambio = ($Ahora - $whenChangedDate).Days
        $OUOrigen = ($Usuario.DistinguishedName -replace "^CN=[^,]+,", "")
        $NombreCompleto = $Usuario.Name

        if (-not $ModoTest) {
            Remove-ADUser -Identity $Usuario -Confirm:$false
        }

        $Prefix = if ($ModoTest) { "[SIMULADO - ELIMINAR]" } else { "[REAL]" }
        $LogMsg = "{0} | {1} | {2} | {3} | {4}" -f $Ahora.ToString("yyyy-MM-dd HH:mm:ss"), $Ticket, $NombreCompleto, $OUOrigen, $DiasDesdeCambio
        Add-Content -Path $LogFile -Value "$Prefix $LogMsg"
        Write-Host "$Prefix $LogMsg"
    }
    catch {
        $ErrorMsg = "[ERROR] {0} | {1} | {2}" -f $Ahora.ToString("yyyy-MM-dd HH:mm:ss"), $Ticket, $_.Exception.Message
        Add-Content -Path $LogFile -Value $ErrorMsg
        Write-Host $ErrorMsg -ForegroundColor Red
    }
}

Write-Host "`nProceso completado. Log generado en: $LogFile"
