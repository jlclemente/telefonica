# --- CONFIGURACIÓN ---
$usuariosPermitidos = @(
    "DefaultAccount", "WDAGUtilityAccount", "spadmin", "servicenow",
    "CLIUSR", "Guest", "RVTools", "UUSGGESTSOL","CyberN1","CyberWinN2A","CyberWinN2B"
)
$registro = "RegistroUsuarios"
$origen = "GestionUsuariosScript"

# --- Crear registro y origen si no existen ---
if (-not [System.Diagnostics.EventLog]::SourceExists($origen)) {
    New-EventLog -LogName $registro -Source $origen
    "Registro y origen creados. Ejecuta de nuevo el script para continuar."
    exit
}

# --- Función para registrar evento ---
function Registrar-Evento {
    param (
        [string]$mensaje,
        [string]$tipo = "Information",
        [int]$eventoId = 5001
    )
    Write-EventLog -LogName $registro -Source $origen -EntryType $tipo -EventId $eventoId -Message $mensaje
}

# --- Obtener todos los usuarios locales ---
$usuarios = Get-LocalUser

foreach ($usuario in $usuarios) {
    $nombre = $usuario.Name

    if ($usuariosPermitidos -contains $nombre) {
        continue
    }

    if ($nombre -in @("Administrator", "Administrador") -and $usuario.Enabled) {
        Disable-LocalUser -Name $nombre
        Registrar-Evento "El usuario '$nombre' fue DESHABILITADO por el script." "Warning" 5002
        continue
    }

    try {
        Remove-LocalUser -Name $nombre -ErrorAction Stop
        Registrar-Evento "El usuario '$nombre' fue ELIMINADO por el script." "Information" 5003
    } catch {
        Registrar-Evento "No se pudo eliminar '$nombre': $_" "Error" 5004
    }
}
