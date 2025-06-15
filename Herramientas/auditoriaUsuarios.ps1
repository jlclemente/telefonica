# Obtener nombre del equipo
$nombreEquipo = $env:COMPUTERNAME

# Rutas
$csvPath = "C:\script\usuario.csv"
$logPath = "C:\Windows\Logs\auditoriaUsuarios_$nombreEquipo.log"

# Crear el log si no existe
if (-not (Test-Path $logPath)) {
    New-Item -ItemType File -Path $logPath -Force | Out-Null
}

# Función para escribir en log y pantalla con timestamp
function Escribir-Log {
    param (
        [string]$mensaje
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea = "$timestamp`t$mensaje"
    Add-Content -Path $logPath -Value $linea
    Write-Host $linea
}

# Leer CSV
$usuarios = Import-Csv -Path $csvPath

# Guardar nombres de cuenta del CSV para comparación posterior
$cuentasCsv = $usuarios.cuenta | ForEach-Object { if ($_ -ne $null) { $_.Trim() } else { "" } }

# Función para obtener info usuario usando net user
function Obtener-EstadoUsuario {
    param(
        [string]$nombreUsuario
    )
    $info = net user $nombreUsuario 2>$null
    if ($info) {
        foreach ($linea in $info) {
            if ($linea -match "Account active\s+Yes") {
                return "HABILITADO"
            } elseif ($linea -match "Account active\s+No") {
                return "DESHABILITADO"
            }
        }
        return "ESTADO DESCONOCIDO"
    } else {
        return "NO EXISTE"
    }
}

# Encabezado del log con nombre de equipo
Escribir-Log "========================================="
Escribir-Log "       AUDITORÍA DE USUARIOS"
Escribir-Log "       Fecha y hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Escribir-Log "       Equipo: $nombreEquipo"
Escribir-Log "========================================="
Escribir-Log ""

# 1. Auditoría de usuarios definidos en el CSV
Escribir-Log "USUARIOS DEFINIDOS EN CSV"
Escribir-Log "Cuenta`tEstado CSV`tEstado Local`tObservaciones"
Escribir-Log "------`t-----------`t-----------`t-------------"

foreach ($usuario in $usuarios) {
    $cuenta = if ($null -ne $usuario.cuenta) { $usuario.cuenta.Trim() } else { "" }
    $estado = if ($null -ne $usuario.estado) { $usuario.estado.Trim() } else { "" }
    
    $estadoActual = Obtener-EstadoUsuario -nombreUsuario $cuenta
    $observacion = ""

    switch ($estado.ToLower()) {
        "" {
            if ($estadoActual -ne "NO EXISTE") {
                $observacion = "Estado no establecido en CSV. Cuenta local EXISTE."
            } else {
                $observacion = "Estado no establecido en CSV. Cuenta local NO EXISTE."
            }
        }
        "baja" {
            if ($estadoActual -ne "NO EXISTE") {
                if ($estadoActual -eq "HABILITADO") {
                    $observacion = "Marcado BAJA pero cuenta local HABILITADA. ¡REVISAR!"
                } else {
                    $observacion = "Marcado BAJA. Cuenta local DESHABILITADA."
                }
            } else {
                $observacion = "Marcado BAJA. Cuenta local NO EXISTE."
            }
        }
        "alta" {
            if ($estadoActual -ne "NO EXISTE") {
                if ($estadoActual -eq "HABILITADO") {
                    $observacion = "Correctamente ALTA y habilitado."
                } else {
                    $observacion = "Marcado ALTA pero cuenta local DESHABILITADA. ¡REVISAR!"
                }
            } else {
                $observacion = "Marcado ALTA. Cuenta local NO EXISTE. ¡REVISAR!"
            }
        }
        "baja?" {
            if ($estadoActual -ne "NO EXISTE") {
                $observacion = "Estado 'baja?'. Cuenta local EXISTE."
            } else {
                $observacion = "Estado 'baja?'. Cuenta local NO EXISTE."
            }
        }
        default {
            if ($estadoActual -ne "NO EXISTE") {
                $observacion = "Estado '$estado' no reconocido. Cuenta local EXISTE y está $estadoActual."
            } else {
                $observacion = "Estado '$estado' no reconocido. Cuenta local NO EXISTE."
            }
        }
    }

    Escribir-Log "$cuenta`t$estado`t$estadoActual`t$observacion"
}

# 2. Verificar usuarios locales no incluidos en el CSV
Escribir-Log ""
Escribir-Log "USUARIOS LOCALES NO INCLUIDOS EN CSV"
Escribir-Log "Cuenta`tEstado Local"
Escribir-Log "------`t-----------"

# Obtener todos los usuarios locales con net user y filtrar robustamente
$usuariosLocalesRaw = net user

# Filtrar líneas válidas, eliminar encabezados, mensajes y líneas vacías
$lineasValidas = $usuariosLocalesRaw | Where-Object {
    ($_ -and
    ($_ -notmatch "User accounts for") -and
    ($_ -notmatch "The command completed successfully") -and
    ($_ -notmatch "^\s*-{5,}\s*$") -and
    ($_ -notmatch "^\s*$"))
}

# Lista para almacenar usuarios
$usuariosLocales = @()

foreach ($linea in $lineasValidas) {
    # Separar por espacios, eliminar elementos vacíos y validar que parezcan usuarios válidos
    $posiblesUsuarios = $linea -split '\s+' | Where-Object { $_ -and $_ -notmatch '^\W+$' }
    $usuariosLocales += $posiblesUsuarios
}

# Eliminar posibles duplicados y limpiar valores vacíos
$usuariosLocales = $usuariosLocales | Where-Object { $_ } | Select-Object -Unique

# Usuarios excluidos típicos
$usuariosExcluidos = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")

foreach ($localUser in $usuariosLocales) {
    if (
        ($cuentasCsv -notcontains $localUser) -and
        ($usuariosExcluidos -notcontains $localUser) -and
        (-not $localUser.StartsWith("WDAG"))
    ) {
        $estadoLocal = Obtener-EstadoUsuario -nombreUsuario $localUser
        Escribir-Log "$localUser`t$estadoLocal"
    }
}

Escribir-Log ""
Escribir-Log "========================================="
Escribir-Log "             FIN DE AUDITORÍA"
Escribir-Log "========================================="
