# Importar módulo de Active Directory (si no está cargado)
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# === INFORMACIÓN DEL SISTEMA ===
$nombreDominio = ""
$nombreEquipo = $env:COMPUTERNAME
$esDC = $false
$fechaHora = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Rutas de log
$rutaLogLocal = "C:\Windows\Logs\userMgmt.log"
$rutaLogSYSVOL = ""

# Función: Detectar si es un Controlador de Dominio
function Es-ControladorDominio {
    $roles = (Get-WmiObject -Class Win32_ServerFeature).Name
    return $roles -contains "Active Directory Domain Services"
}

# Función: Obtener nombre del dominio
function Obtener-NombreDominio {
    try {
        $dominio = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        return $dominio.Name
    } catch {
        return "No disponible (no en dominio)"
    }
}

# === DETECCIÓN INICIAL ===
$esDC = Es-ControladorDominio
$nombreDominio = Obtener-NombreDominio

if ($esDC -and $nombreDominio -ne "No disponible (no en dominio)") {
    $rutaLogSYSVOL = "\\$nombreDominio\sysvol\$nombreDominio\Logs\userMgmt.log"
}

# Crear directorios necesarios para el log local
if (!(Test-Path (Split-Path $rutaLogLocal))) {
    New-Item -ItemType Directory -Path (Split-Path $rutaLogLocal) | Out-Null
}

# Crear log de eventos personalizado si no existe
$logNombre = "RegistroUsuarios"
$origen = "userMgmtScript"

if (![System.Diagnostics.EventLog]::SourceExists($origen)) {
    if (![System.Diagnostics.EventLog]::Exists($logNombre)) {
        New-EventLog -LogName $logNombre -Source $origen
    } else {
        New-EventLog -Source $origen -LogName $logNombre
    }
}

# Función de registro de logs
function Registrar-Log {
    param (
        [string]$tipoEvento,
        [string]$incidencia,
        [string]$usuarioRealizador,
        [string]$usuarioAfectado = "",
        [string]$ouDestino = "",
        [string[]]$gruposAsignados = @(),
        [string]$descripcion = "",
        [string]$autorizadoRSO = "No aplica",
        [string]$resultado
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Formato del log en archivo
    $entryLog = "$timestamp | $tipoEvento | $nombreEquipo | $usuarioAfectado | $incidencia | $autorizadoRSO | OU: $ouDestino | Grupos: $($gruposAsignados -join ', ') | Descripción: $descripcion | Resultado: $resultado"

    # Escribe en archivo local
    try {
        Add-Content -Path $rutaLogLocal -Value $entryLog -Encoding UTF8
    } catch {
        Write-Host "Error al escribir en el log local: $_" -ForegroundColor Red
    }

    # Escribe en SYSVOL si es DC y accesible
    if ($esDC -and $rutaLogSYSVOL) {
        try {
            if (!(Test-Path (Split-Path $rutaLogSYSVOL))) {
                New-Item -ItemType Directory -Path (Split-Path $rutaLogSYSVOL) -Force | Out-Null
            }
            Add-Content -Path $rutaLogSYSVOL -Value $entryLog -Encoding UTF8
        } catch {
            Write-Host "Error al escribir en el log de SYSVOL: $_" -ForegroundColor Yellow
        }
    }

    # Mapeo de tipos de evento como cadenas válidas
    $eventEntryType = switch ($tipoEvento) {
        "Información" { "Information"; break }
        "Advertencia" { "Warning"; break }
        "Error"       { "Error"; break }
        "Éxito"       { "SuccessAudit"; break }
        default       { "Information" }
    }

    # Asigna ID de evento según tipo
    $eventId = switch ($tipoEvento) {
        "Información" { 5005; break }
        "Advertencia" { 5006; break }
        "Error"       { 5007; break }
        "Éxito"       { 5008; break }
        default       { 5005 }
    }

    # Mensaje para Event Viewer
    $mensajeEvento = "[$timestamp] Acción: $tipoEvento.`n"
    $mensajeEvento += "Incidencia: $incidencia`n"
    $mensajeEvento += "Usuario que aplica el cambio: $usuarioRealizador`n"
    if ($usuarioAfectado) { $mensajeEvento += "Usuario afectado: $usuarioAfectado`n" }
    if ($ouDestino) { $mensajeEvento += "OU destino: $ouDestino`n" }
    if ($gruposAsignados.Count -gt 0) { $mensajeEvento += "Grupos asignados: $($gruposAsignados -join ', ')`n" }
    if ($descripcion) { $mensajeEvento += "Descripción: $descripcion`n" }
    $mensajeEvento += "Resultado: $resultado"

    # Escribe en Event Viewer
    try {
        Write-EventLog -LogName $logNombre -Source $origen -EntryType $eventEntryType -EventId $eventId -Message $mensajeEvento
    } catch {
        Write-Host "Error al escribir en el registro de eventos: $_" -ForegroundColor Red
    }
}

# Mostrar información en la cabecera
function MostrarCabecera {
    Clear-Host
    Write-Host "================== Gestíon de usuarios =================="
    Write-Host "================== Telefonica TCCT ================="
    Write-Host ""
    Write-Host "Servidor:      $nombreEquipo"
    Write-Host "Dominio:       $nombreDominio"
    Write-Host "Rol:           " -NoNewline
    if ($esDC) {
        Write-Host "Controlador de Dominio" -ForegroundColor Green
    } else {
        Write-Host "Miembro de Dominio / Trabajo" -ForegroundColor Yellow
    }
    Write-Host "Fecha/Hora:    $fechaHora"
    Write-Host ""
}

# Funciones vacías o implementadas

# Función auxiliar: Generar contraseña segura
function Generar-ContrasenaSegura {
    param ([int]$longitud = 16)

    $mayusculas = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $minusculas = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $numeros = '0123456789'.ToCharArray()
    $especiales = '!@#$%^&*'.ToCharArray()
    $todos = $mayusculas + $minusculas + $numeros + $especiales

    $random = New-Object Random
    $password = @()

    $password += $mayusculas[$random.Next($mayusculas.Length)]
    $password += $minusculas[$random.Next($minusculas.Length)]
    $password += $numeros[$random.Next($numeros.Length)]
    $password += $especiales[$random.Next($especiales.Length)]

    for ($i = $password.Length; $i -lt $longitud; $i++) {
        $password += $todos[$random.Next($todos.Length)]
    }

    $password = $password | Get-Random -Count $password.Length
    return -join $password
}

# Función: Agregar un usuario
function Agregar-Usuario {
    Write-Host "=== FUNCION: Agregar un usuario ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    # Solicita información inicial
    $incidencia = Read-Host "Ingrese la incidencia/motivo del cambio"

    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))
    }

    # Preguntar por autorización del RSO con 3 opciones
    do {
        Write-Host "`n¿Acción autorizada por el RSO? Elija una opción:"
        Write-Host "1. Sí"
        Write-Host "2. No"
        Write-Host "3. No Aplica"
        $opcionRSO = Read-Host "Seleccione una opción (1, 2 o 3)"
        
        switch ($opcionRSO) {
            "1" { 
                $rsoEstado = "Autorizada" 
                $continuar = $true
            }
            "2" { 
                $rsoEstado = "No autorizada" 
                $continuar = $false 
            }
            "3" { 
                $rsoEstado = "No aplica" 
                $continuar = $true 
            }
            default {
                Write-Host "Opción inválida. Por favor, seleccione 1, 2 o 3." -ForegroundColor Red
                $continuar = $null
            }
        }
    } while ($continuar -eq $null)

    if (-not $continuar) {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por falta de autorización"
        Write-Host "La acción fue cancelada." -ForegroundColor Red
        Pause
        return
    }

    Registrar-Log -tipoEvento "Información" `
                  -incidencia $incidencia `
                  -usuarioRealizador $usuarioAplicador `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Iniciando proceso de creación"

    # Recolección de datos del nuevo usuario
    do {
        $matricula = Read-Host "Ingrese la matrícula (sAMAccountName)"
        $nombre = Read-Host "Ingrese el nombre del usuario"
        $apellidos = Read-Host "Ingrese los apellidos del usuario"
        $mail = Read-Host "Ingrese el correo electrónico"

        # Generar o solicitar contraseña
        $opcionPass = Read-Host "¿Desea ingresar una contraseña manualmente? (S/N)"
        if ($opcionPass.ToUpper() -eq 'S') {
            $password = Read-Host "Ingrese la contraseña" -AsSecureString
            $contrasenaMostrada = "********** (manual)"
        } else {
            $passwordPlana = Generar-ContrasenaSegura -longitud 16
            $password = $passwordPlana | ConvertTo-SecureString -AsPlainText -Force
            $contrasenaMostrada = "$passwordPlana (autogenerada)"
            Registrar-Log -tipoEvento "Información" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Contraseña: $passwordPlana"
        }

        # Confirmar datos
        Clear-Host
        Write-Host "Verifique los datos del nuevo usuario:" -ForegroundColor Green
        Write-Host "Matrícula:      $matricula" -ForegroundColor White
        Write-Host "Nombre:         $nombre $apellidos" -ForegroundColor White
        Write-Host "Correo:         $mail" -ForegroundColor White
        Write-Host "Contraseña:     $contrasenaMostrada" -ForegroundColor White

        $confirmar = Read-Host "¿Los datos son correctos? (S/N)"
    } while ($confirmar.ToUpper() -ne 'S')

    # Seleccionar OU
    $ouValida = $false
    do {
        $rutaOU = Read-Host "Ingrese la ruta de la OU donde crear el usuario (ej: OU=Usuarios,DC=dominio,DC=com)"
        try {
            $ou = Get-ADOrganizationalUnit -Identity $rutaOU -ErrorAction Stop
            $ouValida = $true
        } catch {
            Write-Host "OU no válida: $_" -ForegroundColor Red
            $ouValida = $false
        }
    } while (-not $ouValida)

    # Construir descripción
    $descripcion = "Alta usuario $incidencia. Autorizado por RSO: $rsoEstado"
    Write-Host "Descripción del usuario: $descripcion" -ForegroundColor Yellow

    # Buscar grupos en la OU
    Write-Host "`nBuscando grupos en la OU destino..." -ForegroundColor Magenta
    $gruposEnOU = Get-ADGroup -Filter * -SearchBase $rutaOU | Select-Object -ExpandProperty Name

    if ($gruposEnOU.Count -eq 0) {
        Write-Host "No hay grupos disponibles en esta OU." -ForegroundColor Yellow
    } else {
        Write-Host "Grupos disponibles en la OU:" -ForegroundColor Green
        $gruposEnOU | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
    }

    # Asignar grupos
    $gruposAAgregar = @()
    $grupoInput = Read-Host "¿Desea asociar este usuario a algún grupo? (S/N)"
    if ($grupoInput.ToUpper() -eq 'S') {
        $gruposAAgregar = $gruposEnOU
    }

    # Resumen final
    Clear-Host
    Write-Host "=== RESUMEN DE CREACIÓN DE USUARIO ===" -ForegroundColor Cyan
    Write-Host "Matrícula:      $matricula" -ForegroundColor White
    Write-Host "Nombre:         $nombre $apellidos" -ForegroundColor White
    Write-Host "Correo:         $mail" -ForegroundColor White
    Write-Host "Contraseña:     $contrasenaMostrada" -ForegroundColor White
    Write-Host "Descripción:    $descripcion" -ForegroundColor White
    Write-Host "OU destino:     $rutaOU" -ForegroundColor White
    Write-Host "Grupos asignados:"
    foreach ($g in $gruposAAgregar) {
        Write-Host " - $g" -ForegroundColor Green
    }

    $crear = Read-Host "¿Crear usuario ahora? (S/N)"
    if ($crear.ToUpper() -eq 'S') {
        try {
            New-ADUser -Name "$nombre $apellidos" `
                       -GivenName $nombre `
                       -Surname $apellidos `
                       -SamAccountName $matricula `
                       -UserPrincipalName "$matricula@$nombreDominio" `
                       -EmailAddress $mail `
                       -AccountPassword $password `
                       -Enabled $true `
                       -Path $rutaOU `
                       -Description $descripcion

            if ($gruposAAgregar.Count -gt 0) {
                Add-ADGroupMember -Identity $gruposAAgregar -Members $matricula
                Write-Host "Usuario creado y grupos asignados." -ForegroundColor Green
            } else {
                Write-Host "Usuario creado sin grupos." -ForegroundColor Yellow
            }

            Registrar-Log -tipoEvento "Éxito" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -ouDestino $rutaOU `
                          -gruposAsignados $gruposAAgregar `
                          -descripcion $descripcion `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Usuario creado correctamente."

            Write-Host "Usuario creado correctamente." -ForegroundColor Green
        } catch {
            Registrar-Log -tipoEvento "Error" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Error al crear el usuario: $_"
            Write-Host "Error al crear el usuario: $_" -ForegroundColor Red
        }
    } else {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Creación cancelada por el usuario."
        Write-Host "Creación cancelada por el usuario." -ForegroundColor Red
    }

    Pause
}

# Función: Ver estado de un usuario
function Ver-EstadoUsuario {
    Write-Host "=== FUNCION: Ver estado de un usuario ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    # Pedir sAMAccountName del usuario afectado
    do {
        $matricula = Read-Host "Ingrese la matrícula (sAMAccountName) del usuario"
        try {
            $user = Get-ADUser -Identity $matricula -Properties Name, GivenName, Surname, EmailAddress, Enabled, LockedOut, LastLogonDate, LastLogonTimestamp, DistinguishedName, MemberOf
            Write-Host "Usuario encontrado: $($user.Name)" -ForegroundColor Green
            break
        } catch {
            Write-Host "Usuario no encontrado: $_" -ForegroundColor Red
        }
    } while ($true)

    $nombreCompleto = "$($user.GivenName) $($user.Surname)"
    $correo = $user.EmailAddress
    $estadoCuenta = if ($user.Enabled) { "Habilitada" } else { "Deshabilitada" }
    $estadoBloqueo = if ($user.LockedOut) { "Bloqueada" } else { "Desbloqueada" }

    # Último inicio de sesión
    if ($user.LastLogonDate) {
        $ultimaConexion = $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")
    } elseif ($user.LastLogonTimestamp) {
        $ultimaConexion = [datetime]::FromFileTime($user.LastLogonTimestamp).ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        $ultimaConexion = "Nunca ha iniciado sesión"
    }

    # OU actual
    $ouActual = $user.DistinguishedName -replace '^CN=.*?(OU=.*)','$1'

    # Grupos a los que pertenece
    $grupos = @()
    foreach ($grupoDN in $user.MemberOf) {
        $grupo = Get-ADGroup -Identity $grupoDN -ErrorAction SilentlyContinue
        if ($grupo) {
            $grupos += $grupo.Name
        }
    }

    # Mostrar información
    Clear-Host
    Write-Host "=== ESTADO ACTUAL DEL USUARIO ===" -ForegroundColor Yellow
    Write-Host "Matrícula:       $matricula" -ForegroundColor White
    Write-Host "Nombre:         $nombreCompleto" -ForegroundColor White
    Write-Host "Correo:         $correo" -ForegroundColor White
    Write-Host "Estado cuenta:   $estadoCuenta" -ForegroundColor White
    Write-Host "Estado bloqueo:  $estadoBloqueo" -ForegroundColor White
    Write-Host "Último acceso:  $ultimaConexion" -ForegroundColor White
    Write-Host "OU actual:      $ouActual" -ForegroundColor White
    Write-Host "Grupos:" -ForegroundColor Yellow
    if ($grupos.Count -gt 0) {
        foreach ($g in $grupos) {
            Write-Host " - $g" -ForegroundColor Green
        }
    } else {
        Write-Host " - El usuario no pertenece a ningún grupo" -ForegroundColor Yellow
    }

    Pause
}

# Función: Modificar un usuario
function Modificar-Usuario {
    Write-Host "=== FUNCION: Modificar un usuario ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    # Solicita información inicial
    $incidencia = Read-Host "Ingrese la incidencia/motivo del cambio"

    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))
    }

    # Preguntar por autorización del RSO con 3 opciones
    do {
        Write-Host "`n¿Acción autorizada por el RSO? Elija una opción:"
        Write-Host "1. Sí"
        Write-Host "2. No"
        Write-Host "3. No Aplica"
        $opcionRSO = Read-Host "Seleccione una opción (1, 2 o 3)"
        
        switch ($opcionRSO) {
            "1" { 
                $rsoEstado = "Autorizada" 
                $continuar = $true
            }
            "2" { 
                $rsoEstado = "No autorizada" 
                $continuar = $false 
            }
            "3" { 
                $rsoEstado = "No aplica" 
                $continuar = $true 
            }
            default {
                Write-Host "Opción inválida. Por favor, seleccione 1, 2 o 3." -ForegroundColor Red
                $continuar = $null
            }
        }
    } while ($continuar -eq $null)

    if (-not $continuar) {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por falta de autorización"
        Write-Host "La acción fue cancelada." -ForegroundColor Red
        Pause
        return
    }

    Registrar-Log -tipoEvento "Información" `
                  -incidencia $incidencia `
                  -usuarioRealizador $usuarioAplicador `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Iniciando proceso de modificación"

    # Buscar usuario
    do {
        $matricula = Read-Host "Ingrese la matrícula (sAMAccountName) del usuario"
        try {
            $user = Get-ADUser -Identity $matricula -Properties Name, GivenName, Surname, EmailAddress, Enabled, DistinguishedName, MemberOf
            $nombreCompletoActual = "$($user.GivenName) $($user.Surname)"
            Write-Host "Usuario encontrado: $nombreCompletoActual" -ForegroundColor Green
            break
        } catch {
            Write-Host "Usuario no encontrado: $_" -ForegroundColor Red
        }
    } while ($true)

    # Datos actuales
    $ouActual = $user.DistinguishedName -replace '^CN=.*?(OU=.*)','$1'
    $correoActual = $user.EmailAddress
    $nombreActual = $user.GivenName
    $apellidoActual = $user.Surname
    $estadoCuentaActual = if ($user.Enabled) { "Habilitada" } else { "Deshabilitada" }

    # Edición de datos
    Write-Host "`n=== EDICIÓN DE DATOS ===" -ForegroundColor Magenta
    $nombreNuevo = Read-Host "Nuevo nombre (deje vacío para mantener '$nombreActual')"
    if ([string]::IsNullOrWhiteSpace($nombreNuevo)) { $nombreNuevo = $nombreActual }

    $apellidoNuevo = Read-Host "Nuevos apellidos (deje vacío para mantener '$apellidoActual')"
    if ([string]::IsNullOrWhiteSpace($apellidoNuevo)) { $apellidoNuevo = $apellidoActual }

    $correoNuevo = Read-Host "Nuevo correo (deje vacío para mantener '$correoActual')"
    if ([string]::IsNullOrWhiteSpace($correoNuevo)) { $correoNuevo = $correoActual }

    # Cambiar estado de cuenta
    $estadoNuevo = $user.Enabled
    Write-Host "`nEstado actual de cuenta: $estadoCuentaActual"
    $cambiarEstado = Read-Host "¿Desea cambiar el estado de la cuenta? (S/N)"
    if ($cambiarEstado.ToUpper() -eq 'S') {
        $estadoNuevo = -not $user.Enabled
    }

    # Mover de OU
    $rutaOUNueva = $ouActual
    Write-Host "`n¿Desea mover el usuario a otra OU?"
    $moverOU = Read-Host "(S/N)"
    if ($moverOU.ToUpper() -eq 'S') {
        do {
            $rutaOUNueva = Read-Host "Escriba la nueva OU destino"
            try {
                $ouDestino = Get-ADOrganizationalUnit -Identity $rutaOUNueva -ErrorAction Stop
                Write-Host "OU válida." -ForegroundColor Green
                break
            } catch {
                Write-Host "OU no válida: $_" -ForegroundColor Red
            }
        } while ($true)
    }

    # Mostrar grupos de la OU actual
    Write-Host "`nBuscando grupos en la OU actual..." -ForegroundColor Magenta
    $gruposEnOUActual = Get-ADGroup -Filter * -SearchBase $ouActual | Select-Object -ExpandProperty Name

    if ($gruposEnOUActual.Count -gt 0) {
        Write-Host "Grupos disponibles en la OU actual:" -ForegroundColor Green
        $gruposEnOUActual | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
    } else {
        Write-Host "No hay grupos disponibles en esta OU." -ForegroundColor Yellow
    }

    # Quitar grupos
    $gruposAEliminar = @()
    Write-Host "`n=== GRUPOS ACTUALES ===" -ForegroundColor Yellow
    if ($gruposEnOUActual.Count -gt 0) {
        foreach ($g in $gruposEnOUActual) {
            $quitar = Read-Host "¿Desea quitar al usuario del grupo '$g'? (S/N)"
            if ($quitar.ToUpper() -eq 'S') {
                $gruposAEliminar += $g
            }
        }
    } else {
        Write-Host "El usuario no tiene grupos asignados." -ForegroundColor Yellow
    }

    # Agregar nuevos grupos
    $gruposAAgregar = @()
    Write-Host "`n=== AGREGAR NUEVOS GRUPOS ===" -ForegroundColor Yellow
    $agregarGrupos = Read-Host "¿Desea agregar nuevos grupos al usuario? (S/N)"
    if ($agregarGrupos.ToUpper() -eq 'S') {
        $mostrarGrupos = Read-Host "¿Mostrar grupos de la OU actual? (S/N)"
        if ($mostrarGrupos.ToUpper() -eq 'S') {
            Write-Host "Grupos disponibles en la OU actual:" -ForegroundColor Green
            $gruposEnOUActual | ForEach-Object { Write-Host " - $_" -ForegroundColor White }

            $grupoInput = Read-Host "Ingrese un grupo (dejar vacío para terminar)"
            while ($grupoInput) {
                if ($gruposEnOUActual -contains $grupoInput.Trim()) {
                    $gruposAAgregar += $grupoInput.Trim()
                    Write-Host "Grupo '$grupoInput' agregado." -ForegroundColor Green
                } else {
                    Write-Host "El grupo no está disponible en esta OU." -ForegroundColor Red
                }
                $grupoInput = Read-Host "Ingrese otro grupo (dejar vacío para terminar)"
            }
        } else {
            do {
                $grupoInput = Read-Host "Ingrese el nombre del grupo a agregar (dejar vacío para terminar)"
                if ($grupoInput) {
                    try {
                        $grupo = Get-ADGroup -Identity $grupoInput -ErrorAction Stop
                        $gruposAAgregar += $grupo.Name
                        Write-Host "Grupo '$grupoInput' agregado." -ForegroundColor Green
                    } catch {
                        Write-Host "Grupo no encontrado: $_" -ForegroundColor Red
                    }
                }
            } while ($grupoInput)
        }
    }

    # Actualizar descripción
    $descripcionAntigua = $user.Description
    $descripcionNueva = "Modificado por motivo: $incidencia. Acción realizada por: $usuarioAplicador. Fecha: $(Get-Date -Format yyyy-MM-dd)"

    if ($descripcionAntigua) {
        $descripcionFinal = "$descripcionAntigua | $descripcionNueva"
    } else {
        $descripcionFinal = $descripcionNueva
    }

    # Resumen final
    Clear-Host
    Write-Host "=== RESUMEN DE MODIFICACIÓN ===" -ForegroundColor Cyan
    Write-Host "Nombre anterior: $nombreActual $apellidoActual" -ForegroundColor White
    Write-Host "Nombre nuevo:   $nombreNuevo $apellidoNuevo" -ForegroundColor Green
    Write-Host "Correo anterior: $correoActual" -ForegroundColor White
    Write-Host "Correo nuevo:   $correoNuevo" -ForegroundColor Green
    Write-Host "Estado actual:  $estadoCuentaActual" -ForegroundColor White
    Write-Host "Nuevo estado:   $(if ($estadoNuevo) {'Habilitada'} else {'Deshabilitada'})" -ForegroundColor Green
    Write-Host "OU destino:     $rutaOUNueva" -ForegroundColor White
    Write-Host "Grupos a quitar: $($gruposAEliminar -join ', ')" -ForegroundColor White
    Write-Host "Grupos a agregar: $($gruposAAgregar -join ', ')" -ForegroundColor Green

    $proceder = Read-Host "¿Aplicar estos cambios? (S/N)"
    if ($proceder.ToUpper() -ne 'S') {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Modificación cancelada por el usuario."
        Write-Host "Modificación cancelada por el usuario." -ForegroundColor Red
        Pause
        return
    }

    # Aplicar cambios
    try {
        Set-ADUser -Identity $matricula `
                   -GivenName $nombreNuevo `
                   -Surname $apellidoNuevo `
                   -EmailAddress $correoNuevo `
                   -Enabled $estadoNuevo `
                   -Description $descripcionFinal

        if ($gruposAEliminar.Count -gt 0) {
            foreach ($grupo in $gruposAEliminar) {
                Remove-ADGroupMember -Identity $grupo -Members $matricula -Confirm:$false -ErrorAction Stop
                Write-Host "Usuario eliminado del grupo '$grupo'." -ForegroundColor Green
            }
        }

        if ($gruposAAgregar.Count -gt 0) {
            foreach ($grupo in $gruposAAgregar) {
                Add-ADGroupMember -Identity $grupo -Members $matricula -ErrorAction Stop
                Write-Host "Usuario agregado al grupo '$grupo'." -ForegroundColor Green
            }
        }

        if ($ouActual -ne $rutaOUNueva) {
            Move-ADObject -Identity $user.DistinguishedName -TargetPath $rutaOUNueva -ErrorAction Stop
            Write-Host "Usuario movido a la OU '$rutaOUNueva'." -ForegroundColor Green
        }

        Registrar-Log -tipoEvento "Éxito" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -ouDestino $rutaOUNueva `
                      -gruposAsignados ($gruposAAgregar + $gruposAEliminar) `
                      -descripcion $descripcionFinal `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Datos modificados: Nombre, Apellidos, Correo, Estado, Grupos, OU."

        Write-Host "Usuario modificado correctamente." -ForegroundColor Green
    } catch {
        Registrar-Log -tipoEvento "Error" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Error al modificar el usuario: $_"
        Write-Host "Error al modificar el usuario: $_" -ForegroundColor Red
    }

    Pause
}

# Función: Eliminar un usuario (realmente deshabilita o elimina)
function Eliminar-Usuario {
    Write-Host "=== FUNCION: Eliminar / Deshabilitar un usuario ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    # Solicita información inicial
    $incidencia = Read-Host "Ingrese la incidencia/motivo del cambio"

    # Confirmar usuario que aplica el cambio
    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))
    }

    # Preguntar por autorización del RSO con 3 opciones
    do {
        Write-Host "`n¿Acción autorizada por el RSO? Elija una opción:"
        Write-Host "1. Sí"
        Write-Host "2. No"
        Write-Host "3. No Aplica"
        $opcionRSO = Read-Host "Seleccione una opción (1, 2 o 3)"
        
        switch ($opcionRSO) {
            "1" { 
                $rsoEstado = "Autorizada" 
                $continuar = $true
            }
            "2" { 
                $rsoEstado = "No autorizada" 
                $continuar = $false 
            }
            "3" { 
                $rsoEstado = "No aplica" 
                $continuar = $true 
            }
            default {
                Write-Host "Opción inválida. Por favor, seleccione 1, 2 o 3." -ForegroundColor Red
                $continuar = $null
            }
        }
    } while ($continuar -eq $null)

    if (-not $continuar) {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por falta de autorización"
        Write-Host "La acción fue cancelada." -ForegroundColor Red
        Pause
        return
    }

    Registrar-Log -tipoEvento "Información" `
                  -incidencia $incidencia `
                  -usuarioRealizador $usuarioAplicador `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Iniciando proceso de eliminación/deshabilitación"

    # Pedir sAMAccountName del usuario afectado
    do {
        $matricula = Read-Host "Ingrese la matrícula (sAMAccountName) del usuario a gestionar"
        try {
            $user = Get-ADUser -Identity $matricula -Properties Name, DistinguishedName, Enabled, Description, GivenName, Surname
            Write-Host "Nombre completo: $($user.GivenName) $($user.Surname)" -ForegroundColor Green
            break
        } catch {
            Write-Host "Usuario no encontrado: $_" -ForegroundColor Red
        }
    } while ($true)

    $nombreCompleto = "$($user.GivenName) $($user.Surname)"
    $ouActual = $user.DistinguishedName -replace '^CN=.*?(OU=.*)','$1'

    # ¿Eliminar o deshabilitar?
    Write-Host "`n¿Qué desea hacer con el usuario?" -ForegroundColor Yellow
    Write-Host "1. Eliminar completamente"
    Write-Host "2. Deshabilitar y mover (opcionalmente) a OU de deshabilitados"
    $opcionAccion = Read-Host "Elija una opción (1 o 2)"

    if ($opcionAccion -notin @("1", "2")) {
        Write-Host "Opción inválida." -ForegroundColor Red
        Registrar-Log -tipoEvento "Error" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Opción inválida seleccionada: $accionElegida"
        Pause
        return
    }

    # Confirmación final
    Write-Host "`nResumen:" -ForegroundColor Magenta
    if ($opcionAccion -eq "1") {
        Write-Host "Acción: ELIMINAR PERMANENTE" -ForegroundColor Red
    } else {
        Write-Host "Acción: DESHABILITAR Y MOVER (opcional)" -ForegroundColor Yellow
    }

    Write-Host "Motivo: $incidencia" -ForegroundColor White
    Write-Host "Usuario afectado: $matricula ($nombreCompleto)" -ForegroundColor White
    Write-Host "¿Continuar? (S/N)" -ForegroundColor Yellow
    $confirmar = Read-Host

    if ($confirmar.ToUpper() -ne 'S') {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por el usuario."
        Write-Host "Acción cancelada por el usuario." -ForegroundColor Red
        Pause
        return
    }

    # Procesar acción
    if ($opcionAccion -eq "1") {
        try {
            Remove-ADUser -Identity $matricula -Confirm:$false -ErrorAction Stop
            Write-Host "Usuario '$matricula' eliminado permanentemente." -ForegroundColor Red

            Registrar-Log -tipoEvento "Éxito" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -autorizadoRSO $rsoEstado `
                          -descripcion "Usuario eliminado permanentemente por motivo: $incidencia" `
                          -resultado "Usuario '$matricula' eliminado permanentemente."
        } catch {
            Registrar-Log -tipoEvento "Error" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Error al eliminar el usuario: $_"
            Write-Host "Error al eliminar el usuario: $_" -ForegroundColor Red
        }
    } else {

        # Acción: Deshabilitar
        try {
            Disable-ADAccount -Identity $matricula -ErrorAction Stop
            Write-Host "Usuario '$matricula' deshabilitado correctamente." -ForegroundColor Green

            Registrar-Log -tipoEvento "Éxito" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -autorizadoRSO $rsoEstado `
                          -descripcion "Deshabilitado por motivo: $incidencia" `
                          -resultado "Usuario deshabilitado."

        } catch {
            Registrar-Log -tipoEvento "Error" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Error al deshabilitar el usuario: $_"
            Write-Host "Error al deshabilitar el usuario: $_" -ForegroundColor Red
            Pause
            return
        }

        # Comprobar si está en OU de deshabilitados
        if ($ouActual -match "deshabilitado") {
            Write-Host "El usuario ya está en una OU de deshabilitados." -ForegroundColor Yellow
            $moverOU = Read-Host "¿Mover a otra OU? (S/N)"
            if ($moverOU.ToUpper() -eq 'S') {
                do {
                    $rutaOU = Read-Host "Escriba la OU destino"
                    try {
                        $ouDestino = Get-ADOrganizationalUnit -Identity $rutaOU -ErrorAction Stop
                        Move-ADObject -Identity $user.DistinguishedName -TargetPath $rutaOU -ErrorAction Stop
                        Write-Host "Usuario movido a la OU destino." -ForegroundColor Green
                    } catch {
                        Write-Host "OU no válida: $_" -ForegroundColor Red
                        $rutaOU = $ouActual
                    }
                } while (-not $ouDestino)
            }
        } else {
            $rutaOU = $ouActual
        }

        # Actualizar descripción del usuario
        $descripcionAntigua = $user.Description
        $descripcionNueva = "Deshabilitado por motivo: $incidencia. Acción realizada por: $usuarioAplicador. Fecha: $(Get-Date -Format yyyy-MM-dd)"
        if ($descripcionAntigua) {
            $descripcionFinal = "$descripcionAntigua | $descripcionNueva"
        } else {
            $descripcionFinal = $descripcionNueva
        }

        Set-ADUser -Identity $matricula -Description $descripcionFinal

        if ($moverOU.ToUpper() -eq 'S') {
            Registrar-Log -tipoEvento "Éxito" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -ouDestino $rutaOU `
                          -descripcion $descripcionFinal `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Usuario deshabilitado y movido a OU '$rutaOU'"
        } else {
            Registrar-Log -tipoEvento "Éxito" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -ouDestino $ouActual `
                          -descripcion $descripcionFinal `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Usuario deshabilitado sin movimiento de OU."
        }
    }

    Write-Host ""
    Write-Host "Proceso completado." -ForegroundColor Green
    Pause
}

# Función: Auditar usuarios inactivos más de 90 días
function Auditar-UsuariosInactivos90Dias {
    Write-Host "=== FUNCION: Auditar usuarios inactivos >90 días ===" -ForegroundColor Cyan

    if ($nombreDominio -ne "vdc.adm") {
        Write-Host "Esta función solo está disponible en el dominio 'vdc.adm'." -ForegroundColor Red
        Pause
        return
    }

    # Confirmar usuario que aplica el cambio
    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))
    }

    # Preguntar por autorización del RSO
    do {
        Write-Host "`n¿Acción autorizada por el RSO? Elija una opción:"
        Write-Host "1. Sí"
        Write-Host "2. No"
        Write-Host "3. No Aplica"
        $opcionRSO = Read-Host "Elija una opción (1, 2 o 3)"
        
        switch ($opcionRSO) {
            "1" { 
                $rsoEstado = "Autorizada" 
                $continuar = $true
            }
            "2" { 
                $rsoEstado = "No autorizada" 
                $continuar = $false 
            }
            "3" { 
                $rsoEstado = "No aplica" 
                $continuar = $true 
            }
            default {
                Write-Host "Opción inválida. Por favor, seleccione 1, 2 o 3." -ForegroundColor Red
                $continuar = $null
            }
        }
    } while ($continuar -eq $null)

    if (-not $continuar) {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia "Auditar usuarios inactivos >90 días" `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por falta de autorización"
        Write-Host "La acción fue cancelada." -ForegroundColor Red
        Pause
        return
    }

    Registrar-Log -tipoEvento "Información" `
                  -incidencia "Auditar usuarios inactivos >90 días" `
                  -usuarioRealizador $usuarioAplicador `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Iniciando auditoría"

    # Definir la OU a auditar
    $rutaOU = "OU=Usuarios,$((Get-ADDomain).DistinguishedName)"

    try {
        $ou = Get-ADOrganizationalUnit -Identity $rutaOU -ErrorAction Stop
    } catch {
        Write-Host "OU no encontrada: $_" -ForegroundColor Red
        Registrar-Log -tipoEvento "Error" `
                      -incidencia "Auditar usuarios inactivos >90 días" `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "OU 'Usuarios' no encontrada: $_"
        Pause
        return
    }

    # Calcular fecha límite
    $fechaLimite = (Get-Date).AddDays(-90)
    Write-Host "`nBuscando usuarios inactivos desde antes de: $($fechaLimite.ToString('yyyy-MM-dd'))..." -ForegroundColor Yellow

    # Buscar usuarios habilitados en la OU
    $usuarios = Get-ADUser -SearchBase $rutaOU -Filter {Enabled -eq $true} -Properties LastLogonTimestamp, Name, GivenName, Surname, SamAccountName

    $usuariosInactivos = @()
    foreach ($user in $usuarios) {
        if ($user.LastLogonTimestamp) {
            $ultimaConexion = [datetime]::FromFileTime($user.LastLogonTimestamp)
            if ($ultimaConexion -lt $fechaLimite) {
                $usuariosInactivos += [PSCustomObject]@{
                    Matricula       = $user.SamAccountName
                    NombreCompleto  = "$($user.GivenName) $($user.Surname)"
                    UltimaConexion  = $ultimaConexion.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        } else {
            $usuariosInactivos += [PSCustomObject]@{
                Matricula       = $user.SamAccountName
                NombreCompleto  = "$($user.GivenName) $($user.Surname)"
                UltimaConexion  = "Nunca ha iniciado sesión"
            }
        }
    }

    if ($usuariosInactivos.Count -eq 0) {
        Write-Host "No hay usuarios inactivos en esta OU." -ForegroundColor Green
        Registrar-Log -tipoEvento "Información" `
                      -incidencia "Auditar usuarios inactivos >90 días" `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "No se encontraron usuarios inactivos."
        Pause
        return
    }

    # Mostrar listado de usuarios inactivos
    Clear-Host
    Write-Host "=== USUARIOS INACTIVOS DESDE HACE MÁS DE 90 DÍAS ===" -ForegroundColor Magenta
    $usuariosInactivos | Format-Table -AutoSize -Property Matricula, NombreCompleto, UltimaConexion

    # Opciones de acción
    Write-Host "`n¿Qué desea hacer con estos usuarios?" -ForegroundColor Yellow
    Write-Host "1. Deshabilitar y mover todos automáticamente"
    Write-Host "2. Procesar uno a uno"
    Write-Host "3. Salir sin realizar ninguna acción"
    $accionElegida = Read-Host "Elija una opción (1, 2 o 3)"

    switch ($accionElegida) {
        "1" {
            # Buscar OU que contenga 'deshabilitado'
            $ousDeshabilitados = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.Name -match "deshabilitado" } | Select-Object -First 1 -ExpandProperty DistinguishedName

            if (!$ousDeshabilitados) {
                Write-Host "No se encontró una OU de deshabilitados." -ForegroundColor Red
                Registrar-Log -tipoEvento "Error" `
                              -incidencia $incidencia `
                              -usuarioRealizador $usuarioAplicador `
                              -autorizadoRSO $rsoEstado `
                              -resultado "No se encontró OU con 'deshabilitado'."
                Pause
                return
            }

            foreach ($u in $usuariosInactivos) {
                try {
                    Disable-ADAccount -Identity $u.Matricula
                    Move-ADObject -Identity $u.Matricula -TargetPath $ousDeshabilitados -ErrorAction Stop
                    Write-Host "Usuario '$($u.Matricula)' deshabilitado y movido a '$ousDeshabilitados'" -ForegroundColor Green

                    # Actualizar descripción
                    $descAntigua = (Get-ADUser -Identity $u.Matricula -Properties Description).Description
                    $descNueva = "Deshabilitado por inactividad >90 días. Motivo: Auditoría automática. Fecha: $(Get-Date -Format yyyy-MM-dd)"
                    $descFinal = if ($descAntigua) { "$descAntigua | $descNueva" } else { $descNueva }
                    Set-ADUser -Identity $u.Matricula -Description $descFinal

                    Registrar-Log -tipoEvento "Éxito" `
                                  -incidencia $incidencia `
                                  -usuarioRealizador $usuarioAplicador `
                                  -usuarioAfectado $u.Matricula `
                                  -ouDestino $ousDeshabilitados `
                                  -descripcion $descFinal `
                                  -autorizadoRSO $rsoEstado `
                                  -resultado "Usuario deshabilitado y movido a OU '$ousDeshabilitados'"
                } catch {
                    Registrar-Log -tipoEvento "Error" `
                                  -incidencia $incidencia `
                                  -usuarioRealizador $usuarioAplicador `
                                  -usuarioAfectado $u.Matricula `
                                  -autorizadoRSO $rsoEstado `
                                  -resultado "Error al mover/deshabilitar usuario: $_"
                    Write-Host "Error al procesar '$($u.Matricula)': $_" -ForegroundColor Red
                }
            }
        }

        "2" {
            foreach ($u in $usuariosInactivos) {
                Clear-Host
                Write-Host "=== USUARIO ===" -ForegroundColor Yellow
                Write-Host "Matrícula:     $($u.Matricula)" -ForegroundColor White
                Write-Host "Nombre:        $($u.NombreCompleto)" -ForegroundColor White
                Write-Host "Última conexión: $($u.UltimaConexion)" -ForegroundColor White

                $procesar = Read-Host "¿Deshabilitar y mover este usuario? (S/N)"
                if ($procesar.ToUpper() -eq 'S') {
                    try {
                        Disable-ADAccount -Identity $u.Matricula
                        $ousDeshabilitados = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.Name -match "deshabilitado" } | Select-Object -First 1 -ExpandProperty DistinguishedName

                        if ($ousDeshabilitados) {
                            Move-ADObject -Identity $u.Matricula -TargetPath $ousDeshabilitados -ErrorAction Stop
                            Write-Host "Usuario movido a la OU destino." -ForegroundColor Green
                        }

                        # Actualizar descripción
                        $descAntigua = (Get-ADUser -Identity $u.Matricula -Properties Description).Description
                        $descNueva = "Deshabilitado por inactividad >90 días. Motivo: Auditoría manual. Fecha: $(Get-Date -Format yyyy-MM-dd)"
                        $descFinal = if ($descAntigua) { "$descAntigua | $descNueva" } else { $descNueva }
                        Set-ADUser -Identity $u.Matricula -Description $descFinal

                        Registrar-Log -tipoEvento "Éxito" `
                                      -incidencia $incidencia `
                                      -usuarioRealizador $usuarioAplicador `
                                      -usuarioAfectado $u.Matricula `
                                      -ouDestino $ousDeshabilitados `
                                      -descripcion $descFinal `
                                      -autorizadoRSO $rsoEstado `
                                      -resultado "Usuario deshabilitado y movido a OU '$ousDeshabilitados'."

                        Write-Host "Usuario '$($u.Matricula)' deshabilitado y movido." -ForegroundColor Green
                    } catch {
                        Registrar-Log -tipoEvento "Error" `
                                      -incidencia $incidencia `
                                      -usuarioRealizador $usuarioAplicador `
                                      -usuarioAfectado $u.Matricula `
                                      -autorizadoRSO $rsoEstado `
                                      -resultado "Error al mover usuario: $_"
                        Write-Host "Error al mover usuario: $_" -ForegroundColor Red
                    }
                } else {
                    Registrar-Log -tipoEvento "Información" `
                                  -incidencia $incidencia `
                                  -usuarioRealizador $usuarioAplicador `
                                  -usuarioAfectado $u.Matricula `
                                  -autorizadoRSO $rsoEstado `
                                  -resultado "Usuario omitido por decisión manual"
                    Write-Host "Usuario '$($u.Matricula)' mantenido." -ForegroundColor Yellow
                }
            }
        }

        "3" {
            Write-Host "No se han realizado cambios." -ForegroundColor Yellow
            Registrar-Log -tipoEvento "Información" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Auditoría completada sin acciones"
            Pause
            return
        }

        default {
            Write-Host "Opción inválida." -ForegroundColor Red
            Registrar-Log -tipoEvento "Error" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Opción inválida seleccionada: $accionElegida"
            Pause
            return
        }
    }

    Write-Host ""
    Write-Host "Auditoría completada." -ForegroundColor Green
    Pause
}

# Función: Auditar usuarios deshabilitados hace más de 60 días
function Auditar-UsuariosDeshabilitados60Dias {
    Write-Host "=== FUNCION: Auditar usuarios deshabilitados >60 días ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    if ($nombreDominio -ne "vdc.adm") {
        Write-Host "Esta función solo está disponible en el dominio 'vdc.adm'." -ForegroundColor Red
        Pause
        return
    }

    # Confirmar usuario que aplica el cambio
    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))
    }

    # Preguntar por autorización del RSO
    do {
        Write-Host "`n¿Acción autorizada por el RSO? Elija una opción:"
        Write-Host "1. Sí"
        Write-Host "2. No"
        Write-Host "3. No Aplica"
        $opcionRSO = Read-Host "Seleccione una opción (1, 2 o 3)"
        
        switch ($opcionRSO) {
            "1" { 
                $rsoEstado = "Autorizada" 
                $continuar = $true
            }
            "2" { 
                $rsoEstado = "No autorizada" 
                $continuar = $false 
            }
            "3" { 
                $rsoEstado = "No aplica" 
                $continuar = $true 
            }
            default {
                Write-Host "Opción inválida. Por favor, seleccione 1, 2 o 3." -ForegroundColor Red
                $continuar = $null
            }
        }
    } while ($continuar -eq $null)

    if (-not $continuar) {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia "Auditar usuarios deshabilitados >60 días" `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por falta de autorización"
        Write-Host "La acción fue cancelada." -ForegroundColor Red
        Pause
        return
    }

    Registrar-Log -tipoEvento "Información" `
                  -incidencia "Auditar usuarios deshabilitados >60 días" `
                  -usuarioRealizador $usuarioAplicador `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Iniciando auditoría"

    # Buscar usuarios deshabilitados
    $usuarios = Get-ADUser -Filter {Enabled -eq $false} -Properties whenChanged, Name, GivenName, Surname, SamAccountName

    $fechaLimite = (Get-Date).AddDays(-60)
    $usuariosInactivos = @()

    foreach ($user in $usuarios) {
        $deshabilitadoDesde = $user.whenChanged
        if ($deshabilitadoDesde -lt $fechaLimite) {
            $usuariosInactivos += [PSCustomObject]@{
                Matricula       = $user.SamAccountName
                NombreCompleto  = "$($user.GivenName) $($user.Surname)"
                DeshabilitadoDesde = $deshabilitadoDesde.ToString("yyyy-MM-dd")
            }
        }
    }

    if ($usuariosInactivos.Count -eq 0) {
        Write-Host "No hay usuarios deshabilitados desde hace más de 60 días." -ForegroundColor Green
        Registrar-Log -tipoEvento "Información" `
                      -incidencia "Auditar usuarios deshabilitados >60 días" `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "No se encontraron usuarios antiguos deshabilitados."
        Pause
        return
    }

    # Mostrar listado
    Clear-Host
    Write-Host "=== USUARIOS DESHABILITADOS HACE MÁS DE 60 DÍAS ===" -ForegroundColor Magenta
    $usuariosInactivos | Format-Table -AutoSize -Property Matricula, NombreCompleto, DeshabilitadoDesde

    # Preguntar qué hacer
    Write-Host "`n¿Qué desea hacer con estos usuarios?" -ForegroundColor Yellow
    Write-Host "1. Eliminar todos"
    Write-Host "2. Seleccionar uno a uno"
    Write-Host "3. Salir sin hacer nada"
    $accionElegida = Read-Host "Elija una opción (1, 2 o 3)"

    switch ($accionElegida) {
        "1" {
            foreach ($u in $usuariosInactivos) {
                try {
                    Remove-ADUser -Identity $u.Matricula -Confirm:$false -ErrorAction Stop
                    Write-Host "Usuario '$($u.Matricula)' eliminado permanentemente." -ForegroundColor Red

                    Registrar-Log -tipoEvento "Éxito" `
                                  -incidencia "Auditar usuarios deshabilitados >60 días" `
                                  -usuarioRealizador $usuarioAplicador `
                                  -usuarioAfectado $u.Matricula `
                                  -autorizadoRSO $rsoEstado `
                                  -resultado "Usuario eliminado permanentemente."
                } catch {
                    Registrar-Log -tipoEvento "Error" `
                                  -incidencia "Auditar usuarios deshabilitados >60 días" `
                                  -usuarioRealizador $usuarioAplicador `
                                  -usuarioAfectado $u.Matricula `
                                  -autorizadoRSO $rsoEstado `
                                  -resultado "Error al eliminar el usuario: $_"
                    Write-Host "Error al eliminar '$($u.Matricula)': $_" -ForegroundColor Red
                }
            }
        }

        "2" {
            foreach ($u in $usuariosInactivos) {
                Clear-Host
                Write-Host "=== USUARIO ===" -ForegroundColor Yellow
                Write-Host "Matrícula:     $($u.Matricula)" -ForegroundColor White
                Write-Host "Nombre:        $($u.NombreCompleto)" -ForegroundColor White
                Write-Host "Deshabilitado desde: $($u.DeshabilitadoDesde)" -ForegroundColor White

                $eliminar = Read-Host "¿Eliminar este usuario? (S/N)"
                if ($eliminar.ToUpper() -eq 'S') {
                    try {
                        Remove-ADUser -Identity $u.Matricula -Confirm:$false -ErrorAction Stop
                        Write-Host "Usuario '$($u.Matricula)' eliminado permanentemente." -ForegroundColor Red

                        Registrar-Log -tipoEvento "Éxito" `
                                      -incidencia "Auditar usuarios deshabilitados >60 días" `
                                      -usuarioRealizador $usuarioAplicador `
                                      -usuarioAfectado $u.Matricula `
                                      -autorizadoRSO $rsoEstado `
                                      -resultado "Usuario eliminado correctamente."
                    } catch {
                        Registrar-Log -tipoEvento "Error" `
                                      -incidencia "Auditar usuarios deshabilitados >60 días" `
                                      -usuarioRealizador $usuarioAplicador `
                                      -usuarioAfectado $u.Matricula `
                                      -autorizadoRSO $rsoEstado `
                                      -resultado "Error al eliminar el usuario: $_"
                        Write-Host "Error al eliminar '$($u.Matricula)': $_" -ForegroundColor Red
                    }
                } else {
                    Registrar-Log -tipoEvento "Información" `
                                  -incidencia "Auditar usuarios deshabilitados >60 días" `
                                  -usuarioRealizador $usuarioAplicador `
                                  -usuarioAfectado $u.Matricula `
                                  -autorizadoRSO $rsoEstado `
                                  -resultado "Usuario omitido por decisión manual."
                    Write-Host "Usuario '$($u.Matricula)' mantenido." -ForegroundColor Yellow
                }
            }
        }

        "3" {
            Write-Host "No se han realizado cambios." -ForegroundColor Yellow
            Registrar-Log -tipoEvento "Información" `
                          -incidencia "Auditar usuarios deshabilitados >60 días" `
                          -usuarioRealizador $usuarioAplicador `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Auditoría completada sin acciones"
            Pause
            return
        }

        default {
            Write-Host "Opción inválida." -ForegroundColor Red
            Registrar-Log -tipoEvento "Error" `
                          -incidencia "Auditar usuarios deshabilitados >60 días" `
                          -usuarioRealizador $usuarioAplicador `
                          -autorizadoRSO $rsoEstado `
                          -resultado "Opción inválida seleccionada: $accionElegida"
            Pause
            return
        }
    }

    Write-Host ""
    Write-Host "Auditoría completada." -ForegroundColor Green
    Pause
}

# Función: Desbloquear usuario / Restablecer contraseña
function Desbloquear-UsuarioContraseña {
    Write-Host "=== FUNCION: Desbloquear usuario / Restablecer contraseña ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    # Solicita información inicial
    $incidencia = Read-Host "Ingrese la incidencia/motivo del cambio"

    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))

        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -resultado "Iniciando proceso de desbloqueo/restablecimiento"
    }

    # Pedir sAMAccountName del usuario afectado
    do {
        $matricula = Read-Host "Ingrese la matrícula (sAMAccountName) del usuario"
        try {
            $user = Get-ADUser -Identity $matricula -Properties Name, DistinguishedName, Enabled, LockedOut, Description, GivenName, Surname
            Write-Host "Usuario encontrado: $($user.Name)" -ForegroundColor Green
            break
        } catch {
            Write-Host "Usuario no encontrado: $_" -ForegroundColor Red
        }
    } while ($true)

    $nombreCompleto = "$($user.GivenName) $($user.Surname)"
    $ouActual = $user.DistinguishedName -replace '^CN=.*?(OU=.*)','$1'

    # Mostrar estado actual
    Clear-Host
    Write-Host "=== ESTADO ACTUAL DEL USUARIO ===" -ForegroundColor Yellow
    Write-Host "Matrícula:      $matricula" -ForegroundColor White
    Write-Host "Nombre:         $nombreCompleto" -ForegroundColor White
    Write-Host "OU actual:     $ouActual" -ForegroundColor White
    Write-Host "Habilitado:     $($user.Enabled)" -ForegroundColor White
    Write-Host "Bloqueado:      $($user.LockedOut)" -ForegroundColor White

    # Confirmar acción
    $confirmar = Read-Host "¿Desea continuar con este usuario? (S/N)"
    if ($confirmar.ToUpper() -ne 'S') {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por el usuario."
        Write-Host "Acción cancelada por el usuario." -ForegroundColor Red
        Pause
        return
    }

    # Iniciar acciones
    $accionesRealizadas = @()

    if ($user.LockedOut) {
        Unlock-ADAccount -Identity $matricula
        $accionesRealizadas += "Cuenta desbloqueada"
    }

    if (-not $user.Enabled) {
        Write-Host "La cuenta está deshabilitada." -ForegroundColor Yellow
        $habilitar = Read-Host "¿Desea habilitar la cuenta? (S/N)"
        if ($habilitar.ToUpper() -eq 'S') {
            Enable-ADAccount -Identity $matricula
            $accionesRealizadas += "Cuenta habilitada"
        }
    }

    # Comprobar si está en OU de deshabilitados
    if ($ouActual -match "deshabilitado") {
        Write-Host "El usuario está en una OU que contiene 'deshabilitado'." -ForegroundColor Yellow
        $moverOU = Read-Host "¿Mover a otra OU? (S/N)"
        if ($moverOU.ToUpper() -eq 'S') {
            do {
                $rutaOU = Read-Host "Escriba la OU destino"
                try {
                    $ouDestino = Get-ADOrganizationalUnit -Identity $rutaOU -ErrorAction Stop
                    Move-ADObject -Identity $user.DistinguishedName -TargetPath $ouDestino -ErrorAction Stop
                    $accionesRealizadas += "Movido a OU: $rutaOU"
                    Write-Host "Usuario movido a la OU destino." -ForegroundColor Green
                } catch {
                    Write-Host "OU no válida: $_" -ForegroundColor Red
                }
            } while ($true)
        } else {
            $rutaOU = $ouActual
        }
    } else {
        $rutaOU = $ouActual
    }

    # Cambiar contraseña (opcional)
    $contrasenaMostrada = "No se cambió"
    $cambiarPass = Read-Host "¿Cambiar contraseña? (S/N)"
    if ($cambiarPass.ToUpper() -eq 'S') {
        $opcionPass = Read-Host "¿Contraseña manual? (S/N)"
        if ($opcionPass.ToUpper() -eq 'S') {
            $password = Read-Host "Ingrese la nueva contraseña" -AsSecureString
            $contrasenaMostrada = "********** (manual)"
        } else {
            $passwordPlano = Generar-ContrasenaSegura -longitud 16
            $password = $passwordPlano | ConvertTo-SecureString -AsPlainText -Force
            $contrasenaMostrada = "$passwordPlano (autogenerada)"
            Write-Host "Contraseña generada: $passwordPlano" -ForegroundColor Yellow
        }

        try {
            Set-ADAccountPassword -Identity $matricula -Reset -NewPassword $password -ErrorAction Stop
            $accionesRealizadas += "Contraseña cambiada"
            Write-Host "Contraseña actualizada." -ForegroundColor Green
        } catch {
            Registrar-Log -tipoEvento "Error" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -resultado "Error al cambiar contraseña: $_"
            Write-Host "Error al cambiar contraseña: $_" -ForegroundColor Red
        }
    }

    # Actualizar descripción
    $descripcionAntigua = $user.Description
    $descripcionNueva = "Deshabilitado por motivo: $incidencia. Acción realizada por: $usuarioAplicador. Fecha: $(Get-Date -Format yyyy-MM-dd)"
    if ($descripcionAntigua) {
        $descripcionFinal = "$descripcionAntigua | $descripcionNueva"
    } else {
        $descripcionFinal = $descripcionNueva
    }

    Set-ADUser -Identity $matricula -Description $descripcionFinal

    # Registro final
    Registrar-Log -tipoEvento "Éxito" `
                  -incidencia $incidencia `
                  -usuarioRealizador $usuarioAplicador `
                  -usuarioAfectado $matricula `
                  -ouDestino $rutaOU `
                  -gruposAsignados @() `
                  -descripcion $descripcionFinal `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Acciones realizadas: $($accionesRealizadas -join ', ') | Contraseña: $contrasenaMostrada"

    # Resumen final
    Clear-Host
    Write-Host "=== RESUMEN DE ACCIÓN ===" -ForegroundColor Cyan
    Write-Host "Matrícula:      $matricula" -ForegroundColor White
    Write-Host "Nombre:         $nombreCompleto" -ForegroundColor White
    Write-Host "Acciones realizadas:"
    foreach ($accion in $accionesRealizadas) {
        Write-Host " - $accion" -ForegroundColor Green
    }

    Write-Host "Contraseña:     $contrasenaMostrada" -ForegroundColor White
    Write-Host "Descripción actualizada: $descripcionFinal" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Proceso completado." -ForegroundColor Green
    Pause
}

# Función: Agregar listado de usuarios desde CSV
function Agregar-ListadoUsuarios {
    Write-Host "=== FUNCION: Agregar un listado de usuarios ===" -ForegroundColor Cyan

    if (-not $esDC) {
        Write-Host "Esta acción solo puede realizarse en un Controlador de Dominio." -ForegroundColor Red
        Pause
        return
    }

    # Solicita información inicial
    $incidencia = Read-Host "Ingrese la incidencia/motivo del cambio"

    $usuarioAplicadorAuto = $env:USERNAME
    $confirmarUsuario = Read-Host "¿El usuario que aplica el cambio es '$usuarioAplicadorAuto'? (S/N)"
    if ($confirmarUsuario.ToUpper() -eq 'S') {
        $usuarioAplicador = $usuarioAplicadorAuto
    } else {
        do {
            $usuarioAplicador = Read-Host "Ingrese el nombre del usuario que aplica el cambio"
            if ([string]::IsNullOrWhiteSpace($usuarioAplicador)) {
                Write-Host "Debe ingresar un nombre válido." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($usuarioAplicador))
    }

    # Preguntar por autorización del RSO
    do {
        Write-Host "`n¿Acción autorizada por el RSO? Elija una opción:"
        Write-Host "1. Sí"
        Write-Host "2. No"
        Write-Host "3. No Aplica"
        $opcionRSO = Read-Host "Elija una opción (1, 2 o 3)"
        
        switch ($opcionRSO) {
            "1" { 
                $rsoEstado = "Autorizada" 
                $continuar = $true
            }
            "2" { 
                $rsoEstado = "No autorizada" 
                $continuar = $false 
            }
            "3" { 
                $rsoEstado = "No aplica" 
                $continuar = $true 
            }
            default {
                Write-Host "Opción inválida. Por favor, seleccione 1, 2 o 3." -ForegroundColor Red
                $continuar = $null
            }
        }
    } while ($continuar -eq $null)

    if (-not $continuar) {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por falta de autorización"
        Write-Host "La acción fue cancelada." -ForegroundColor Red
        Pause
        return
    }

    Registrar-Log -tipoEvento "Información" `
                  -incidencia $incidencia `
                  -usuarioRealizador $usuarioAplicador `
                  -autorizadoRSO $rsoEstado `
                  -resultado "Iniciando alta masiva"

    # Pedir ubicación del CSV
    do {
        $rutaCSV = Read-Host "Ingrese la ruta completa del fichero CSV"
        if (Test-Path $rutaCSV) {
            try {
                $usuariosCSV = Import-Csv -Path $rutaCSV -Encoding Default
                $cabeceras = $usuariosCSV[0].PSObject.Properties.Name
                if ($cabeceras -contains "matricula" -and $cabeceras -contains "nombre" -and $cabeceras -contains "apellidos" -and $cabeceras -contains "mail") {
                    Write-Host "Fichero CSV válido." -ForegroundColor Green
                    break
                } else {
                    Write-Host "El CSV debe tener columnas: matricula, nombre, apellidos, mail" -ForegroundColor Red
                }
            } catch {
                Write-Host "Archivo no compatible: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "El archivo no existe." -ForegroundColor Red
        }
    } while ($true)

    # Seleccionar OU destino
    $ouValida = $false
    do {
        $rutaOU = Read-Host "Ingrese la OU destino"
        try {
            $ou = Get-ADOrganizationalUnit -Identity $rutaOU -ErrorAction Stop
            $ouValida = $true
        } catch {
            Write-Host "OU no válida: $_" -ForegroundColor Red
            $ouValida = $false
        }
    } while (-not $ouValida)

    # Buscar grupos en la OU destino
    $gruposEnOU = Get-ADGroup -Filter * -SearchBase $rutaOU | Select-Object -ExpandProperty Name

    if ($gruposEnOU.Count -gt 0) {
        Write-Host "Grupos disponibles en la OU destino:" -ForegroundColor Green
        $gruposEnOU | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
    }

    # Confirmar grupos a asignar
    $gruposAAgregar = $gruposEnOU
    $confirmar = Read-Host "¿Crear usuarios ahora? (S/N)"
    if ($confirmar.ToUpper() -ne 'S') {
        Registrar-Log -tipoEvento "Información" `
                      -incidencia $incidencia `
                      -usuarioRealizador $usuarioAplicador `
                      -usuarioAfectado $matricula `
                      -autorizadoRSO $rsoEstado `
                      -resultado "Acción cancelada por el usuario."
        Write-Host "Acción cancelada por el usuario." -ForegroundColor Red
        Pause
        return
    }

    # Procesar cada usuario del CSV
    foreach ($u in $usuariosCSV) {
        $matricula = $u.matricula.Trim()
        $nombre = $u.nombre.Trim()
        $apellido = $u.apellidos.Trim()
        $mail = $u.mail.Trim()

        try {
            # Generar contraseña segura
            $passwordPlano = Generar-ContrasenaSegura -longitud 16
            $password = $passwordPlano | ConvertTo-SecureString -AsPlainText -Force

            # Crear usuario
            New-ADUser -Name "$nombre $apellido" `
                       -GivenName $nombre `
                       -Surname $apellido `
                       -SamAccountName $matricula `
                       -UserPrincipalName "$matricula@$nombreDominio" `
                       -EmailAddress $mail `
                       -AccountPassword $password `
                       -Enabled $true `
                       -Path $rutaOU `
                       -Description "Alta por listado. Incidencia: $incidencia. Autorizado por RSO: $rsoEstado"

            Add-ADGroupMember -Identity $gruposAAgregar -Members $matricula -ErrorAction Stop

            Write-Host "Usuario '$matricula' creado y grupos asignados." -ForegroundColor Green
            Registrar-Log -tipoEvento "Éxito" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -ouDestino $rutaOU `
                          -gruposAsignados $gruposAAgregar `
                          -descripcion "Alta por listado. Incidencia: $incidencia. Autorizado por RSO: $rsoEstado"
            -resultado "Usuario creado correctamente."
        } catch {
            Registrar-Log -tipoEvento "Error" `
                          -incidencia $incidencia `
                          -usuarioRealizador $usuarioAplicador `
                          -usuarioAfectado $matricula `
                          -resultado "Error al crear el usuario: $_"
            Write-Host "Error al crear el usuario: $_" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Usuarios creados correctamente." -ForegroundColor Green
    Pause
}

# Menú principal
function MostrarMenu {
    Write-Host "Menú Principal"
    Write-Host "=============="
    Write-Host "1. Agregar-Usuario"
    Write-Host "2. Ver-EstadoUsuario"
    Write-Host "3. Modificar-Usuario"
    Write-Host "4. Eliminar-Usuario"
    Write-Host "5. Auditar-UsuariosInactivos90Dias"
    Write-Host "6. Auditar-UsuariosDeshabilitados60Dias"
    Write-Host "7. Desbloquear-UsuarioContraseña"
    Write-Host "8. Agregar-ListadoUsuarios"
    Write-Host "Q. Salir"
}

# Bucle del menú
do {
    MostrarCabecera
    MostrarMenu
    $selection = Read-Host "Por favor, seleccione una opción"

    switch ($selection) {
        '1' { Agregar-Usuario }
        '2' { Ver-EstadoUsuario }
        '3' { Modificar-Usuario }
        '4' { Eliminar-Usuario }
        '5' { Auditar-UsuariosInactivos90Dias }
        '6' { Auditar-UsuariosDeshabilitados60Dias }
        '7' { Desbloquear-UsuarioContraseña }
        '8' { Agregar-ListadoUsuarios }
        'q' { 
            Write-Host "Saliendo..."
            Registrar-Log -tipoEvento "Información" `
                          -incidencia "El script ha finalizado." `
                          -usuarioRealizador $env:USERNAME `
                          -resultado "Finalizado por el usuario"
            break
        }
        default { Write-Host "Opción inválida." -ForegroundColor Red }
    }

    Write-Host ""
} while ($selection -ne 'q')