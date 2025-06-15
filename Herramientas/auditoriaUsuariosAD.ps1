# Parámetros
$csvPath = "C:\script\usuario.csv"
$nombreEquipo = $env:COMPUTERNAME
$logPath = "C:\Windows\Logs\auditoriaUsuarios_$nombreEquipo.log"

# Crear log si no existe
if (-not (Test-Path $logPath)) {
    New-Item -ItemType File -Path $logPath -Force | Out-Null
}

# Función para escribir en log y pantalla
function Escribir-Log {
    param ([string]$mensaje)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea = "$timestamp`t$mensaje"
    Add-Content -Path $logPath -Value $linea
    Write-Host $linea
}

# Función para buscar usuario en AD y obtener su estado habilitado / deshabilitado
function Obtener-EstadoUsuario {
    param([string]$nombreUsuario)

    try {
        # Crear búsqueda LDAP en el dominio actual
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$nombreUsuario))"
        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
        $result = $searcher.FindOne()

        if ($result -ne $null) {
            # userAccountControl: bit 2 deshabilita la cuenta si está activo
            $uac = $result.Properties["userAccountControl"][0]

            # bit 2 (value 2) indica cuenta deshabilitada
            $habilitado = -not ($uac -band 2)

            if ($habilitado) {
                return "HABILITADO"
            } else {
                return "DESHABILITADO"
            }
        } else {
            return "NO EXISTE"
        }
    } catch {
        return "ERROR CONSULTA AD"
    }
}

# Leer CSV
$usuarios = Import-Csv -Path $csvPath

# Guardar nombres para comparación
$cuentasCsv = $usuarios.cuenta | ForEach-Object { if ($_ -ne $null) { $_.Trim() } else { "" } }

# Encabezado
Escribir-Log "========================================="
Escribir-Log "       AUDITORÍA DE USUARIOS DE DOMINIO"
Escribir-Log "       Fecha y hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Escribir-Log "       Equipo: $nombreEquipo"
Escribir-Log "========================================="
Escribir-Log ""

Escribir-Log "USUARIOS DEFINIDOS EN CSV"
Escribir-Log "Cuenta`tEstado CSV`tEstado Dominio`tObservaciones"
Escribir-Log "------`t-----------`t--------------`t-------------"

foreach ($usuario in $usuarios) {
    $cuenta = if ($null -ne $usuario.cuenta) { $usuario.cuenta.Trim() } else { "" }
    $estado = if ($null -ne $usuario.estado) { $usuario.estado.Trim() } else { "" }

    $estadoActual = Obtener-EstadoUsuario -nombreUsuario $cuenta
    $observacion = ""

    switch ($estado.ToLower()) {
        "" {
            if ($estadoActual -ne "NO EXISTE") {
                $observacion = "Estado no establecido en CSV. Cuenta DOMINIO EXISTE."
            } else {
                $observacion = "Estado no establecido en CSV. Cuenta DOMINIO NO EXISTE."
            }
        }
        "baja" {
            if ($estadoActual -ne "NO EXISTE") {
                if ($estadoActual -eq "HABILITADO") {
                    $observacion = "Marcado BAJA pero cuenta dominio HABILITADA. ¡REVISAR!"
                } else {
                    $observacion = "Marcado BAJA. Cuenta dominio DESHABILITADA."
                }
            } else {
                $observacion = "Marcado BAJA. Cuenta dominio NO EXISTE."
            }
        }
        "alta" {
            if ($estadoActual -ne "NO EXISTE") {
                if ($estadoActual -eq "HABILITADO") {
                    $observacion = "Correctamente ALTA y habilitado."
                } else {
                    $observacion = "Marcado ALTA pero cuenta dominio DESHABILITADA. ¡REVISAR!"
                }
            } else {
                $observacion = "Marcado ALTA. Cuenta dominio NO EXISTE. ¡REVISAR!"
            }
        }
        "baja?" {
            if ($estadoActual -ne "NO EXISTE") {
                $observacion = "Estado 'baja?'. Cuenta dominio EXISTE."
            } else {
                $observacion = "Estado 'baja?'. Cuenta dominio NO EXISTE."
            }
        }
        default {
            if ($estadoActual -ne "NO EXISTE") {
                $observacion = "Estado '$estado' no reconocido. Cuenta dominio EXISTE y está $estadoActual."
            } else {
                $observacion = "Estado '$estado' no reconocido. Cuenta dominio NO EXISTE."
            }
        }
    }

    Escribir-Log "$cuenta`t$estado`t$estadoActual`t$observacion"
}

# Obtener todos los usuarios del dominio para comprobar quién no está en CSV
Escribir-Log ""
Escribir-Log "USUARIOS DOMINIO NO INCLUIDOS EN CSV"
Escribir-Log "Cuenta`tEstado Dominio"
Escribir-Log "------`t-------------"

try {
    $searcherAll = New-Object System.DirectoryServices.DirectorySearcher
    $searcherAll.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcherAll.PageSize = 1000
    $searcherAll.PropertiesToLoad.Add("sAMAccountName") | Out-Null
    $searcherAll.PropertiesToLoad.Add("userAccountControl") | Out-Null

    $resultAll = $searcherAll.FindAll()

    foreach ($res in $resultAll) {
        $userName = $res.Properties["sAMAccountName"][0]

        # Evitar cuentas sin nombre o especiales
        if (-not [string]::IsNullOrEmpty($userName) -and ($cuentasCsv -notcontains $userName)) {
            # Obtener estado (habilitado/deshabilitado)
            $uac = $res.Properties["userAccountControl"][0]
            $habilitado = -not ($uac -band 2)
            $estadoDominio = if ($habilitado) { "HABILITADO" } else { "DESHABILITADO" }

            Escribir-Log "$userName`t$estadoDominio"
        }
    }
} catch {
    Escribir-Log "ERROR: No se pudieron obtener usuarios del dominio: $_"
}

Escribir-Log ""
Escribir-Log "========================================="
Escribir-Log "             FIN DE AUDITORÍA"
Escribir-Log "========================================="
