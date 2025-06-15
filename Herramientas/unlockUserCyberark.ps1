# Lista de usuarios a comprobar
$usuarios = @("CyberWinN2B", "CyberWinN2A")

# Ruta del archivo de log
$rutaLog = "C:\Windows\logs\users.log"

# Crear archivo de log si no existe
if (-not (Test-Path $rutaLog)) {
    New-Item -Path $rutaLog -ItemType File -Force | Out-Null
}

foreach ($usuario in $usuarios) {
    try {
        $user = Get-ADUser -Identity $usuario -Properties LockedOut

        $fecha = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

        if ($user.LockedOut) {
            # Desbloquear el usuario
            Unlock-ADAccount -Identity $usuario

            # Log de desbloqueo
            $logEntry = "[$fecha] Usuario desbloqueado: $usuario - Se desbloqueó la cuenta por script automático."
        } else {
            # Log si no estaba bloqueado
            $logEntry = "[$fecha] Usuario no bloqueado: $usuario - No se realizó ninguna acción."
        }

        Add-Content -Path $rutaLog -Value $logEntry
    } catch {
    $fecha = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $errorMsg = $_.Exception.Message
    $logEntry = "[$fecha] ERROR procesando usuario " + $usuario + ": " + $errorMsg
    Add-Content -Path $rutaLog -Value $logEntry
}

}
