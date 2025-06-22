<#
.SYNOPSIS
    Gestor de usuarios para Workstations y Controladores de Dominio.
.DESCRIPTION
    Herramienta de gestión de usuarios para Workstations y Controladores de Dominio (DC), versión Beta.
    - Interfaz gráfica moderna con botones verticales y logo corporativo.
    - Sistema de autenticación inicial: requiere credenciales y pertenencia a un grupo de seguridad ('Change Administrators') para operar.
    - Auditoría completa: todas las acciones se registran en un archivo de log local/centralizado y en el Visor de Eventos de Windows (en DC), incluyendo siempre al operador responsable.
    - Funciones de gestión de ciclo de vida del usuario:
      - Creación de usuarios individuales o importación masiva desde CSV.
      - Consulta detallada de información.
      - Modificación de datos (nombre, email, descripción) con renombrado del objeto en AD.
      - Reseteo de contraseñas (manual o automático).
      - Gestión de membresía de grupos.
      - Movimiento de usuarios entre OUs.
      - Deshabilitación/Habilitación/Eliminación de cuentas con lógica contextual.
    - Funciones de auditoría y limpieza:
      - Auditoría de usuarios inactivos con opción de deshabilitación masiva o selectiva.
      - Limpieza de usuarios deshabilitados por antigüedad.
    - Funcionalidad específica para el dominio 'cueva.local':
      - Movimiento masivo de miembros de un grupo a otra OU.
.VERSION
    Beta 1.0
.AUTHOR
    Juan L Clemente
    Licencia 
.DATE
    22/06/2025
.NOTES
    =============================================================================
     © Copyright 2025, TCCT. Todos los derechos reservados.
    =============================================================================
     AVISO DE LICENCIA:
     Este script es software propietario y confidencial de TCCT. Su uso está
     restringido exclusivamente al personal autorizado de TCCT para fines
     internos. Queda estrictamente prohibida la distribución, modificación o
     reproducción no autorizada de este script.
    =============================================================================
#>

# --- INICIO: Bloque de Requisitos y Comprobaciones Iniciales ---

# Declaración de variables globales
$ScriptVersion = "Beta 1.0"
$EventLogSource = "UserMgmtScript"
$EventLogName = "Application" # Log estándar para máxima compatibilidad

$LogFileName = "usermgmt.log"
$Global:LocalLogPath = ""
$Global:DCLogPath = ""
$Global:IsDomainController = $false
$Global:OperatingMode = ""
$Global:EventLoggingActive = $true
$Global:OperatorUsername = ""

# IDs de Evento en el rango 6000
$EID_ScriptStart = 6000
$EID_ScriptStop = 6001
$EID_ActionCancelled = 6002
$EID_UserCreatedSuccess = 6101
$EID_UserCreatedFailure = 6102
$EID_GroupAddSuccess = 6111
$EID_GroupAddWarning = 6112
$EID_GetUserSuccess = 6201
$EID_GetUserFailure = 6202
$EID_ReportGenerated = 6211
$EID_UserDisabledSuccess = 6301
$EID_UserDisabledFailure = 6302
$EID_UserDeletedSuccess = 6311
$EID_UserDeletedFailure = 6312
$EID_UserMovedSuccess_Disable = 6321
$EID_UserMovedFailure_Disable = 6322
$EID_UserModifiedSuccess = 6401
$EID_UserModifiedFailure = 6402
$EID_UserUnlockedSuccess = 6411
$EID_UserUnlockedFailure = 6412
$EID_UserEnabledSuccess = 6421
$EID_UserEnabledFailure = 6422
$EID_GroupRemovedSuccess = 6431
$EID_GroupRemovedFailure = 6432
$EID_PasswordResetSuccess = 6441
$EID_PasswordResetFailure = 6442
$EID_UserRenamedSuccess = 6451
$EID_UserRenamedFailure = 6452
$EID_UserMovedSuccess = 6501
$EID_UserMovedFailure = 6502
$EID_AuditInactiveUsers = 6601
$EID_AuditDisabledUsers = 6701
$EID_DeleteDisabledSuccess = 6711
$EID_DeleteDisabledFailure = 6712
$EID_BulkImportStart = 6800
$EID_BulkImportComplete = 6810
$EID_ClientMoveStart = 6900
$EID_ClientGroupMoveComplete = 6901
$EID_ClientGroupUserMovedSuccess = 6911
$EID_ClientGroupUserMovedFailure = 6912
$EID_SourceGroupDeleteSuccess = 6921
$EID_SourceGroupDeleteFailure = 6922


# Comprobación manual de privilegios de Administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Este script requiere privilegios de Administrador para funcionar correctamente."
    Write-Warning "Por favor, cierre esta ventana y ejecute el script de nuevo haciendo clic derecho > Ejecutar como administrador."
    Read-Host "Presione Enter para salir."
    exit
}


# --- Función de Logging Centralizada (SIEM) ---
function Write-Log {
    param([hashtable]$EventData)
    $EventData.timestamp = (Get-Date -Format "u").Replace(" ","T")
    $EventData.hostname = $env:COMPUTERNAME
    $EventData.scriptVersion = $ScriptVersion
    $EventData.operatingMode = $Global:OperatingMode
    $EventData.eventSource = $EventLogSource
    $jsonMessage = $EventData | ConvertTo-Json -Compress -Depth 5
    $eventType = "Information"; if ($EventData.eventType) { $eventType = $EventData.eventType }
    try { Add-Content -Path $Global:LocalLogPath -Value $jsonMessage -ErrorAction Stop } catch { Write-Warning "FATAL: No se pudo escribir en el log local: $($Global:LocalLogPath). Error: $_" }
    if ($Global:IsDomainController -and -not([string]::IsNullOrEmpty($Global:DCLogPath))) {
        try { Add-Content -Path $Global:DCLogPath -Value $jsonMessage -ErrorAction Stop } catch { Write-Warning "FATAL: No se pudo escribir en el log de red: $($Global:DCLogPath). Error: $_" }
    }
    if ($Global:IsDomainController -and $Global:EventLoggingActive) {
        $eventLogEntryType = [System.Diagnostics.EventLogEntryType]::$eventType
        try { Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventData.eventId -EntryType $eventLogEntryType -Message $jsonMessage -ErrorAction Stop
        } catch { Write-Host -ForegroundColor Red "FALLO: No se pudo escribir en el Visor de Sucesos. Log: '$EventLogName', Origen: '$EventLogSource'. Error: $_" }
    }
}


# --- Comprobación del Rol del Servidor ---
Write-Host "Realizando comprobaciones iniciales del sistema..." -ForegroundColor Gray
try { $computerRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole; if ($computerRole -in 4, 5) { $Global:IsDomainController = $true } } catch { Write-Host -ForegroundColor Red "Error fatal al intentar determinar el rol del servidor."; Read-Host "Presione Enter para salir."; exit }


# --- Configuración del Entorno de Logging ---
$Global:LocalLogPath = "C:\Windows\Logs\$LogFileName"
if ($Global:IsDomainController) {
    $Global:OperatingMode = "Controlador de Dominio"
} else {
    $Global:OperatingMode = "Workstation"; $Global:EventLoggingActive = $false 
}


# --- Función de Autenticación y Autorización ---
function Invoke-Authentication {
    $requiredGroup = "Change Administrators"
    $credential = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" -Message "Por favor, introduzca sus credenciales para usar UserMgmt"
    if (-not $credential) {
        Write-Warning "Operación cancelada por el usuario."
        return $false
    }
    
    $cleanUsername = ($credential.UserName -split '\\')[-1]
    Write-Host "Validando usuario '$cleanUsername'..." -ForegroundColor Gray
    
    $userPrincipal = $null

    if ($Global:IsDomainController) {
        try {
            $userPrincipal = Get-ADUser -Identity $cleanUsername -ErrorAction Stop
        } catch {
            Write-Warning "Credenciales no válidas o usuario '$cleanUsername' no encontrado en el dominio."
            return $false
        }
        
        Write-Host "Usuario '$cleanUsername' encontrado. Comprobando pertenencia a grupo..." -ForegroundColor Gray
        
        try {
            $groupToCheck = Get-ADGroup -Identity $requiredGroup -ErrorAction Stop
        } catch {
            Write-Warning "El grupo de seguridad '$requiredGroup' no se encuentra en el dominio. No se puede continuar."
            return $false
        }
        
        Write-Host "Grupo '$requiredGroup' encontrado. Verificando membresía..." -ForegroundColor Gray
        $isMember = $false
        $userGroups = Get-ADPrincipalGroupMembership -Identity $userPrincipal
        foreach ($group in $userGroups) {
            if ($group.DistinguishedName -eq $groupToCheck.DistinguishedName) {
                $isMember = $true
                break 
            }
        }
        
        if ($isMember) {
            $Global:OperatorUsername = $userPrincipal.SamAccountName
            return $true
        } else {
            Write-Warning "Acceso denegado. El usuario '$cleanUsername' no pertenece al grupo '$requiredGroup'."
            return $false
        }

    } else { # Workstation
        try {
            $userPrincipal = Get-LocalUser -Name $cleanUsername -ErrorAction Stop
        } catch {
            Write-Warning "Usuario local '$cleanUsername' no encontrado en este equipo."
            return $false
        }
        
        Write-Host "Usuario local '$cleanUsername' encontrado. Comprobando pertenencia a grupo..." -ForegroundColor Gray
        
        try {
            $groupToCheck = Get-LocalGroup -Name $requiredGroup -ErrorAction Stop
        } catch {
            Write-Warning "El grupo local '$requiredGroup' no existe en este equipo. No se puede continuar."
            return $false
        }

        Write-Host "Grupo '$requiredGroup' encontrado. Verificando membresía..." -ForegroundColor Gray
        $isMember = $false
        $groupMembers = Get-LocalGroupMember -Group $groupToCheck -ErrorAction Stop
        foreach ($member in $groupMembers) {
            if ($member.SID -eq $userPrincipal.SID) {
                $isMember = $true
                break
            }
        }

        if ($isMember) {
            $Global:OperatorUsername = $userPrincipal.Name
            return $true
        } else {
            Write-Warning "Acceso denegado. El usuario '$cleanUsername' no pertenece al grupo local '$requiredGroup'."
            return $false
        }
    }
}

# --- Flujo de Ejecución Principal ---

Write-Host "Iniciando proceso de autenticación..." -ForegroundColor Gray
if (-not (Invoke-Authentication)) {
    Read-Host "Presione Enter para salir."
    exit
}
Write-Host "Autenticación correcta. Operador:" -NoNewline; Write-Host " $Global:OperatorUsername" -ForegroundColor Green

Write-Host "Configurando entorno de ejecución..." -ForegroundColor Gray
if ($Global:IsDomainController) {
    Write-Host "Sistema detectado: $Global:OperatingMode." -ForegroundColor Green
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { Write-Host -ForegroundColor Red "Módulo de Active Directory no encontrado."; Read-Host "Presione Enter para salir."; exit }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    try {
        $domainInfo = Get-ADDomain; $sysvolPath = "\\$($domainInfo.DNSRoot)\SYSVOL\$($domainInfo.DNSRoot)\Logs"; $Global:DCLogPath = Join-Path -Path $sysvolPath -ChildPath $LogFileName
        if (-not (Test-Path -Path $sysvolPath -PathType Container)) { New-Item -Path $sysvolPath -ItemType Directory -Force | Out-Null }
    } catch { Write-Host -ForegroundColor Red "Error al configurar la ruta de log en SYSVOL."; Read-Host "Presione Enter para salir."; exit }
    if (-not ([System.Diagnostics.EventLog]::SourceExists($EventLogSource))) {
        Write-Host "Intentando registrar el origen de eventos '$EventLogSource' en el log '$EventLogName'..." -ForegroundColor Yellow
        try { New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop; Write-Host "Origen de eventos registrado con éxito." -ForegroundColor Green
        } catch { Write-Host -ForegroundColor Red "AVISO: No se pudo registrar el origen de eventos. La escritura en el Visor de Eventos se desactivará."; $Global:EventLoggingActive = $false }
    }
} else {
    Write-Host "Sistema detectado: $Global:OperatingMode." -ForegroundColor Green
}
if (-not (Test-Path $Global:LocalLogPath)) { try { New-Item -Path $Global:LocalLogPath -ItemType File -Force -ErrorAction Stop | Out-Null } catch { Write-Host -ForegroundColor Red "No se pudo crear el archivo de log en '$($Global:LocalLogPath)'."; Read-Host "Presione Enter para salir."; exit } }
if ($Global:IsDomainController -and -not (Test-Path $Global:DCLogPath)) { try { New-Item -Path $Global:DCLogPath -ItemType File -Force -ErrorAction Stop | Out-Null } catch { Write-Host -ForegroundColor Red "No se pudo crear el archivo de log en '$($Global:DCLogPath)'."; Read-Host "Presione Enter para salir."; exit } }

Write-Log -EventData @{ eventId = $EID_ScriptStart; eventType = "Information"; action = "ScriptStart"; operatorId = $Global:OperatorUsername; outcome = "success"; reason = "El script se ha iniciado." }
Write-Host "Log principal configurado en: $Global:LocalLogPath" -ForegroundColor Cyan
if ($Global:IsDomainController) { Write-Host "Log de red configurado en: $Global:DCLogPath" -ForegroundColor Cyan; Write-Host "Log de eventos configurado en: '$EventLogName' (Origen: '$EventLogSource')" -ForegroundColor Cyan }
Start-Sleep -Seconds 2


# --- INICIO: Definición de Funciones ---

function Show-VerticalButtonMenu {
    param(
        [string]$Title,
        [hashtable]$MenuOptions,
        [int]$Width = 300
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form; $form.Text = $Title; $form.StartPosition = 'CenterScreen'; $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
    $form.BackColor = [System.Drawing.Color]::White

    $yPosition = 15
    foreach ($option in $MenuOptions.GetEnumerator()) {
        $button = New-Object System.Windows.Forms.Button; $button.Text = $option.Name; $button.Tag = $option.Value; $button.Location = New-Object System.Drawing.Point(15, $yPosition); $button.Size = New-Object System.Drawing.Size(($Width - 40), 35); $button.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $button.add_Click({ $form.Tag = $this.Tag; $form.Close() })
        $form.Controls.Add($button); $yPosition += 40
    }
    
    $yPosition += 10 
    try {
        $imageUrl = "https://info.telefonicatech.com/hs-fs/hubfs/telefonica-tech-logo-positive.png?width=3406&height=593&name=telefonica-tech-logo-positive.png"
        $pictureBox = New-Object System.Windows.Forms.PictureBox
        
        $webClient = New-Object System.Net.WebClient
        $imageData = $webClient.DownloadData($imageUrl)
        $imageStream = New-Object System.IO.MemoryStream(,$imageData)
        $pictureBox.Image = [System.Drawing.Image]::FromStream($imageStream)
        
        $pictureBox.SizeMode = 'Zoom'
        $logoHeight = 25 
        $pictureBox.Size = New-Object System.Drawing.Size(($Width - 40), $logoHeight)
        $pictureBox.Location = New-Object System.Drawing.Point(15, $yPosition)
        
        $form.Controls.Add($pictureBox)
        $yPosition += $logoHeight
    } catch {
        Write-Warning "No se pudo cargar el logo desde la URL. Error: $_"
    }

    $form.Height = $yPosition + 50
    $form.Width = $Width
    
    $form.ShowDialog() | Out-Null
    
    return $form.Tag
}


function Get-ActionPrerequisites {
    param(
        [string]$ActionName,
        [bool]$RequireTicket = $true,
        [bool]$RequireRSO = $true
    )
    Write-Host "--- Auditoría para la acción: $ActionName ---" -ForegroundColor Cyan
    $ticketId = "N/A"
    if ($RequireTicket) { do { $ticketId = Read-Host "Introduzca el número de incidencia" } while ([string]::IsNullOrWhiteSpace($ticketId)) }
    $operatorId = $Global:OperatorUsername
    $rsoApproval = "No Aplica"
    if ($Global:IsDomainController -and $RequireRSO) {
        $choices = [System.Management.Automation.Host.ChoiceDescription[]]@('&Sí', '&No', 'No &aplica')
        $decision = $Host.UI.PromptForChoice("Aprobación RSO", "¿La acción está aprobada por el RSO?", $choices, 1)
        switch ($decision) {
            0 { $rsoApproval = "Si" }
            1 { Write-Host "Acción cancelada." -ForegroundColor Red; Write-Log -EventData @{ eventId = $EID_ActionCancelled; eventType = "Warning"; action = $ActionName; outcome = "failure"; operatorId = $operatorId; ticketId = $ticketId; reason = "Acción cancelada (Aprobación RSO denegada)." }; Start-Sleep 2; return $null }
            2 { $rsoApproval = "No Aplica" }
        }
    }
    return [PSCustomObject]@{ TicketId = $ticketId; OperatorId = $operatorId; RsoApproval = $rsoApproval; IsApproved = $true }
}

function New-SecureRandomPassword { param([int]$Length = 16) $charSets = @( [char[]]'abcdefghijklmnopqrstuvwxyz', [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ', [char[]]'0123456789', [char[]]'!@#$%^&*' ); $password = ""; $charSets.ForEach({ $password += $_ | Get-Random }); for ($i = $password.Length; $i -lt $Length; $i++) { $password += $charSets | Get-Random | Get-Random }; return ($password.ToCharArray() | Get-Random -Count $password.Length) -join '' }

function Show-OUSelectorGUI { Add-Type -AssemblyName System.Windows.Forms; $form = New-Object System.Windows.Forms.Form; $form.Text = "Seleccionar Unidad Organizativa"; $form.Size = New-Object System.Drawing.Size(400, 500); $form.StartPosition = "CenterScreen"; $treeView = New-Object System.Windows.Forms.TreeView; $treeView.Dock = "Top"; $treeView.Height = 380; $form.Controls.Add($treeView); $okButton = New-Object System.Windows.Forms.Button; $okButton.Text = "Aceptar"; $okButton.Location = New-Object System.Drawing.Point(220, 420); $okButton.DialogResult = "OK"; $form.Controls.Add($okButton); $cancelButton = New-Object System.Windows.Forms.Button; $cancelButton.Text = "Cancelar"; $cancelButton.Location = New-Object System.Drawing.Point(300, 420); $cancelButton.DialogResult = "Cancel"; $form.Controls.Add($cancelButton); function Add-ChildOUs($parentNode, $parentDN) { $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $parentDN -SearchScope OneLevel -ErrorAction SilentlyContinue; foreach ($ou in $ous) { $childNode = New-Object System.Windows.Forms.TreeNode; $childNode.Text = $ou.Name; $childNode.Tag = $ou.DistinguishedName; $parentNode.Nodes.Add($childNode) | Out-Null; Add-ChildOUs $childNode $ou.DistinguishedName } }; $domainDN = (Get-ADDomain).DistinguishedName; $rootNode = New-Object System.Windows.Forms.TreeNode; $rootNode.Text = $domainDN; $rootNode.Tag = $domainDN; $treeView.Nodes.Add($rootNode) | Out-Null; Add-ChildOUs $rootNode $domainDN; $rootNode.Expand(); if ($form.ShowDialog() -eq "OK") { if ($treeView.SelectedNode) { return $treeView.SelectedNode.Tag } }; return $null }

function Show-CreateNewUserUI {
    Clear-Host
    $actionName = "CreateUser"; $prereqInfo = Get-ActionPrerequisites -ActionName $actionName
    if ($null -eq $prereqInfo) { return }
    Write-Host "--- 1. Creación de Nuevo Usuario ---" -ForegroundColor Yellow; $matricula = Read-Host "Matrícula (será el nombre de inicio de sesión)"; $nombre = Read-Host "Nombre"; $apellidos = Read-Host "Apellidos"; $mail = Read-Host "Correo electrónico"; $departamento = Read-Host "Departamento"
    if (-join($matricula, $nombre, $apellidos, $mail, $departamento).Trim() -eq "") { Write-Host -ForegroundColor Red "Al menos un campo debe contener información."; Start-Sleep 2; return }
    $nombreCompleto = "$nombre $apellidos"; $descripcion = "$departamento - Alta en $($prereqInfo.TicketId)"; $selectedGroups = @(); $ou = ""
    $passwordChoice = $Host.UI.PromptForChoice("Gestión de Contraseña", "¿Cómo desea establecer la contraseña?", ("&Manual", "&Generar Automáticamente"), 1)
    $passwordPlainText = ""; if ($passwordChoice -eq 0) { $passwordSecureString = Read-Host -AsSecureString "Introduzca la contraseña manualmente" } else { $passwordPlainText = New-SecureRandomPassword; $passwordSecureString = ConvertTo-SecureString $passwordPlainText -AsPlainText -Force }
    if ($Global:IsDomainController) {
        Write-Host "Abriendo selector de Unidad Organizativa..." -ForegroundColor Cyan; $ou = Show-OUSelectorGUI
        if ([string]::IsNullOrEmpty($ou)) { Write-Host "Operación cancelada. No se seleccionó ninguna OU." -ForegroundColor Red; Start-Sleep 2; return }
        Write-Host "OU Seleccionada: $ou" -ForegroundColor Green
        $selectedGroups = @(Get-ADGroup -Filter * -SearchBase $ou | Out-GridView -Title "Seleccione los grupos de la OU '$ou' para '$nombreCompleto'" -PassThru)
        if ((Read-Host "¿Desea añadir grupos de otra ubicación? (s/n)").ToLower() -eq 's') { $selectedGroups += @(Get-ADGroup -Filter * | Out-GridView -Title "Seleccione grupos adicionales de todo el dominio" -PassThru) }
    } else { $selectedGroups = @(Get-LocalGroup | Out-GridView -Title "Seleccione los grupos locales para '$nombreCompleto'" -PassThru) }
    Clear-Host; Write-Host "--- Por favor, confirme los datos ---" -ForegroundColor Yellow; Write-Host " Matrícula (Login):" -NoNewline; Write-Host " $matricula" -ForegroundColor Cyan; Write-Host " Nombre Completo:   " -NoNewline; Write-Host " $nombreCompleto" -ForegroundColor Cyan; Write-Host " Mail:              " -NoNewline; Write-Host " $mail" -ForegroundColor Cyan; Write-Host " Departamento:      " -NoNewline; Write-Host " $departamento" -ForegroundColor Cyan; Write-Host " Descripción:       " -NoNewline; Write-Host " $descripcion" -ForegroundColor Cyan
    if ($Global:IsDomainController) { Write-Host " OU de destino:     " -NoNewline; Write-Host " $ou" -ForegroundColor Cyan }
    if ($passwordPlainText) { Write-Host " Contraseña Generada:" -NoNewline; Write-Host " $passwordPlainText" -ForegroundColor Magenta -BackgroundColor Black; Write-Host "(¡Anótela ahora! No se guardará en el log por seguridad)" -ForegroundColor Yellow }
    if ($selectedGroups.Count -gt 0) { $groupNames = $selectedGroups | Select-Object -ExpandProperty Name; Write-Host " Grupos a añadir:   " -NoNewline; Write-Host ($groupNames -join ', ') -ForegroundColor Cyan } else { Write-Host " Grupos a añadir:    (Ninguno)" -ForegroundColor Gray }
    if ((Read-Host "¿Son correctos todos los datos para proceder? (s/n)").ToLower() -ne 's') { Write-Host "Operación cancelada por el usuario." -ForegroundColor Red; Start-Sleep 2; return }
    $userCreatedSuccessfully = $false; $newUserObject = $null
    try {
        Write-Host "Procesando creación del usuario..." -ForegroundColor Green
        if ($Global:IsDomainController) { $userParams = @{ SamAccountName = $matricula; Name = $nombreCompleto; GivenName = $nombre; Surname = $apellidos; UserPrincipalName = "$matricula@$((Get-ADDomain).DNSRoot)"; EmailAddress = $mail; Description = $descripcion; Path = $ou; AccountPassword = $passwordSecureString; Enabled = $true; ChangePasswordAtLogon = $true }; $newUserObject = New-ADUser @userParams -ErrorAction Stop -PassThru
        } else { $localUserParams = @{ Name = $matricula; Password = $passwordSecureString; FullName = $nombreCompleto; Description = $descripcion }; New-LocalUser @localUserParams -ErrorAction Stop; $newUserObject = Get-LocalUser -Name $matricula -ErrorAction Stop }
        $userCreatedSuccessfully = $true
        Write-Log -EventData @{ eventId = $EID_UserCreatedSuccess; eventType = "Information"; action = $actionName; outcome = "success"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; rsoApproval = $prereqInfo.RsoApproval; targetUserName = $matricula; details = @{ fullName = $nombreCompleto; email = $mail; department = $departamento; ou = $ou }; reason = "Usuario creado con éxito." }
        Write-Host -ForegroundColor Green "¡Usuario '$matricula' creado con éxito!"
    } catch { $errorMessage = $_.Exception.Message; Write-Log -EventData @{ eventId = $EID_UserCreatedFailure; eventType = "Error"; action = $actionName; outcome = "failure"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; rsoApproval = $prereqInfo.RsoApproval; targetUserName = $matricula; reason = $errorMessage }; Write-Host -ForegroundColor Red "ERROR FATAL: No se pudo crear el usuario. Operación abortada."; Write-Host -ForegroundColor Red $errorMessage }
    if ($userCreatedSuccessfully -and $selectedGroups) {
        Write-Host "Asignando membresías a grupos..." -ForegroundColor Green
        if ($newUserObject) {
            foreach ($group in $selectedGroups) {
                try { 
                    if ($Global:IsDomainController) { Add-ADPrincipalGroupMembership -Identity $newUserObject -MemberOf $group -ErrorAction Stop 
                    } else { Add-LocalGroupMember -Group $group.Name -Member $newUserObject -ErrorAction Stop }
                    Write-Log -EventData @{ eventId = $EID_GroupAddSuccess; eventType = "Information"; action = "AddGroupMembership"; outcome = "success"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; targetUserName = $matricula; details = @{ groupName = $group.Name }; reason = "Usuario añadido al grupo con éxito."}; 
                    Write-Host -ForegroundColor Cyan "  - Añadido a '$($group.Name)'"
                } catch { $errorMessage = $_.Exception.Message.Trim(); Write-Log -EventData @{ eventId = $EID_GroupAddWarning; eventType = "Warning"; action = "AddGroupMembership"; outcome = "failure"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; targetUserName = $matricula; details = @{ groupName = $group.Name }; reason = $errorMessage}; Write-Host -ForegroundColor Yellow "  - AVISO al añadir a '$($group.Name)': $errorMessage" }
            }
        } else { Write-Host -ForegroundColor Red "AVISO: No se pudo obtener el objeto del nuevo usuario. No se añadirán grupos." }
    }
    Read-Host "Operación finalizada. Presione Enter para volver al menú principal."
}

# ... (El resto de funciones se mantienen igual)

# --- CAMBIO: Nueva función para Importar Usuarios desde CSV ---
function Show-ImportCsvUI {
    Clear-Host
    $actionName = "BulkImportUsers"
    $prereqInfo = Get-ActionPrerequisites -ActionName $actionName
    if (-not $prereqInfo) { return }

    Add-Type -AssemblyName System.Windows.Forms
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Seleccione el archivo CSV para importar"
    $openFileDialog.Filter = "Archivos CSV (*.csv)|*.csv"
    if ($openFileDialog.ShowDialog() -ne 'OK') {
        Write-Host "Operación de importación cancelada." -ForegroundColor Yellow
        Read-Host "Presione Enter para continuar..."
        return
    }
    $csvPath = $openFileDialog.FileName

    $ou = ""
    if ($Global:IsDomainController) {
        Write-Host "Seleccione la Unidad Organizativa de destino para los nuevos usuarios..." -ForegroundColor Cyan
        $ou = Show-OUSelectorGUI
        if ([string]::IsNullOrEmpty($ou)) {
            Write-Host "No se seleccionó ninguna OU. Operación cancelada." -ForegroundColor Red
            Read-Host "Presione Enter para continuar..."
            return
        }
    }

    $passwordChoice = $Host.UI.PromptForChoice("Gestión de Contraseñas", "¿Cómo desea establecer las contraseñas?", ("&Común para todos", "&Generar automáticamente para cada uno"), 1)
    $commonPasswordPlainText = ""
    $commonPasswordSecure = $null
    if ($passwordChoice -eq 0) {
        $commonPasswordSecure = Read-Host -AsSecureString "Introduzca la contraseña común"
        $commonPasswordPlainText = (New-Object System.Net.NetworkCredential("", $commonPasswordSecure)).Password
    }

    try {
        $usersToImport = Import-Csv -Path $csvPath -Delimiter ';'
    } catch {
        Write-Warning "Error al leer el archivo CSV en '$csvPath'."
        Write-Warning $_.Exception.Message
        Read-Host "Presione Enter para continuar..."
        return
    }
    
    $createdUsersReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Log -EventData @{ eventId = $EID_BulkImportStart; eventType = "Information"; action = $actionName; outcome = "success"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; rsoApproval = $prereqInfo.RsoApproval; details = @{ file = $csvPath; userCount = $usersToImport.Count }; reason = "Iniciando importación masiva." }

    foreach ($row in $usersToImport) {
        $matricula = $row.matricula
        $nombre = $row.nombre
        $apellidos = $row.apellidos
        $mail = $row.mail
        $servicio = $row.servicio

        $nombreCompleto = "$nombre $apellidos"
        $descripcion = "$servicio - Alta en $($prereqInfo.TicketId)"
        $passwordPlainTextForUser = ""
        $passwordSecureForUser = $null

        if ($passwordChoice -eq 0) {
            $passwordPlainTextForUser = $commonPasswordPlainText
            $passwordSecureForUser = $commonPasswordSecure
        } else {
            $passwordPlainTextForUser = New-SecureRandomPassword
            $passwordSecureForUser = ConvertTo-SecureString $passwordPlainTextForUser -AsPlainText -Force
        }

        try {
            Write-Host "Creando usuario '$matricula'..." -NoNewline
            if ($Global:IsDomainController) {
                $userParams = @{
                    SamAccountName      = $matricula
                    Name                = $nombreCompleto
                    GivenName           = $nombre
                    Surname             = $apellidos
                    UserPrincipalName   = "$matricula@$((Get-ADDomain).DNSRoot)"
                    EmailAddress        = $mail
                    Description         = $descripcion
                    Path                = $ou
                    AccountPassword     = $passwordSecureForUser
                    Enabled             = $true
                    ChangePasswordAtLogon = $true
                }
                New-ADUser @userParams -ErrorAction Stop
            } else {
                $localUserParams = @{
                    Name        = $matricula
                    Password    = $passwordSecureForUser
                    FullName    = $nombreCompleto
                    Description = $descripcion
                }
                New-LocalUser @localUserParams -ErrorAction Stop
            }
            $createdUsersReport.Add([PSCustomObject]@{Usuario = $matricula; Contraseña = $passwordPlainTextForUser; Estado = "Creado con éxito"})
            Write-Host " OK" -ForegroundColor Green
            Write-Log -EventData @{ eventId = $EID_UserCreatedSuccess; eventType = "Information"; action = "CreateUser"; outcome = "success"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; rsoApproval = $prereqInfo.RsoApproval; targetUserName = $matricula; details = @{ source = "CSV Import"; fullName = $nombreCompleto; email = $mail; department = $servicio; ou = $ou }; reason = "Usuario creado con éxito desde CSV." }
        } catch {
            $errorMessage = $_.Exception.Message
            $createdUsersReport.Add([PSCustomObject]@{Usuario = $matricula; Contraseña = "N/A"; Estado = "FALLO: $errorMessage"})
            Write-Host " FALLO" -ForegroundColor Red
            Write-Log -EventData @{ eventId = $EID_UserCreatedFailure; eventType = "Error"; action = "CreateUser"; outcome = "failure"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; rsoApproval = $prereqInfo.RsoApproval; targetUserName = $matricula; details = @{ source = "CSV Import" }; reason = $errorMessage }
        }
    }
    
    Write-Host "`n--- Resumen de la Importación ---" -ForegroundColor Yellow
    $createdUsersReport | Format-Table -AutoSize
    
    Write-Log -EventData @{ eventId = $EID_BulkImportComplete; eventType = "Information"; action = $actionName; outcome = "success"; operatorId = $prereqInfo.OperatorId; ticketId = $prereqInfo.TicketId; rsoApproval = $prereqInfo.RsoApproval; details = @{ createdCount = ($createdUsersReport | Where-Object { $_.Estado -like "*éxito*" }).Count; failedCount = ($createdUsersReport | Where-Object { $_.Estado -like "*FALLO*" }).Count }; reason = "Importación masiva finalizada." }
    Read-Host "`nOperación finalizada. Presione Enter para volver al menú principal."
}


# --- INICIO: Bucle Principal del Menú Interactivo ---
$mainMenuLoop = $true
do {
    Clear-Host
    
    $mainMenuOptions = [ordered]@{
        'Crear un nuevo usuario' = { Show-CreateNewUserUI }
        'Importar Usuarios desde CSV' = { Show-ImportCsvUI } # Se añade el botón
        'Información del usuario' = { Show-GetUserInfoUI }
        'Cambiar datos del usuario' = { 
            Clear-Host
            Write-Host "--- Modificar Datos del Usuario ---" -ForegroundColor Yellow
            $matricula = Read-Host "Introduzca la matrícula (SamAccountName) del usuario a modificar"
            if (-not [string]::IsNullOrWhiteSpace($matricula)) {
                try {
                    $user = if ($Global:IsDomainController) { Get-ADUser -Identity $matricula -Properties "GivenName", "Surname", "EmailAddress", "Description", "DisplayName" -ErrorAction Stop } else { Get-LocalUser -Name $matricula -ErrorAction Stop }
                    Show-ModifyUserDataUI -userObject $user
                } catch {
                    Write-Host -ForegroundColor Red "ERROR: No se pudo encontrar el usuario '$matricula'. Verifique la matrícula e inténtelo de nuevo."
                    Read-Host "Presione Enter para continuar..."
                }
            } else {
                Write-Host "La matrícula no puede estar vacía." -ForegroundColor Yellow
                Start-Sleep 2
            }
        }
        'Resetear Contraseña' = { Show-ResetPasswordUI }
    }
    if ($Global:IsDomainController) {
        $mainMenuOptions['Mover usuario de OU'] = { Show-MoveUserUI }
        if ((Get-ADDomain).NetBIOSName -ieq 'CUEVA') {
             $mainMenuOptions['Mover Clientes de OU'] = { Show-MoveOUClientsUI }
        }
    }
    $mainMenuOptions['Deshabilitar/Habilitar/Eliminar Cuenta'] = { Show-DisableEnableDeleteUI }
    $mainMenuOptions['Agregar/Quitar Grupos de Usuario'] = { Show-ManageGroupsUI }
    $mainMenuOptions['Auditar usuarios inactivos'] = { Show-AuditInactiveUsersUI }
    $mainMenuOptions['Eliminar Usuarios Deshabilitados'] = { Show-DeleteDisabledUsersUI } 
    $mainMenuOptions['Salir del script'] = { 
        Write-Log -EventData @{ eventId = $EID_ScriptStop; eventType = "Information"; action = "ScriptStop"; outcome = "success"; reason = "El script ha finalizado." }
        $script:mainMenuLoop = $false 
    }

    $action = Show-VerticalButtonMenu -Title "Gestor de Usuarios - Menú Principal" -MenuOptions $mainMenuOptions
    
    if ($null -ne $action) {
        # Ejecuta el bloque de script asociado a la opción del menú
        & $action
    } else {
        # Si el usuario cierra la ventana, salimos del bucle
        Write-Host "Operación cancelada. Saliendo del script." -ForegroundColor Yellow
        $mainMenuLoop = $false
    }

} while ($mainMenuLoop)

Write-Host "Script finalizado."
