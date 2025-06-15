# changeOU.ps1

param()

# Ruta del log
$logPath = "C:\Windows\Logs\changeOU.log"
if (!(Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType File -Force | Out-Null
}

function Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logPath -Append
}

# Solicitar OU origen y destino
$ouOrigen = Read-Host "Introduce la ruta completa de la OU de origen (ej. OU=Ventas,DC=vdc,DC=adm)"
$ouDestinoNombre = Read-Host "Introduce el nombre de la nueva OU de destino (solo nombre, no ruta)"
$ouDestino = "OU=$ouDestinoNombre,OU=MasterCustomers,DC=vdc,DC=adm"

Log "Inicio del proceso"
Log "OU origen: $ouOrigen"
Log "OU destino: $ouDestino"

# Verificar si la OU de origen existe
try {
    $origenOU = Get-ADOrganizationalUnit -Identity $ouOrigen -ErrorAction Stop
    Write-Host "OU de origen existe."
    Log "OU de origen existe."
} catch {
    Write-Host "ERROR: La OU de origen NO existe. El programa finalizará."
    Log "ERROR: La OU de origen NO existe. Terminando ejecución."
    exit
}

# Verificar si la OU de destino existe
try {
    $destinoOU = Get-ADOrganizationalUnit -Identity $ouDestino -ErrorAction Stop
    Write-Host "OU de destino ya existe."
    Log "OU de destino ya existe."
} catch {
    Write-Host "OU de destino NO existe. Verificando si la ruta padre existe..."
    Log "OU de destino NO existe."

    $ouPadre = "OU=MasterCustomers,DC=vdc,DC=adm"
    try {
        Get-ADOrganizationalUnit -Identity $ouPadre -ErrorAction Stop | Out-Null
        Write-Host "La OU padre existe. Procediendo a crear la OU de destino..."
        Log "La OU padre existe."

        try {
            New-ADOrganizationalUnit -Name $ouDestinoNombre -Path $ouPadre -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
            Write-Host "OU de destino creada exitosamente."
            Log "OU de destino creada: $ouDestino"
        } catch {
            Write-Host "ERROR: No se pudo crear la OU de destino. $_"
            Log "ERROR al crear la OU de destino: $_"
            exit
        }

    } catch {
        Write-Host "ERROR: La ruta padre '$ouPadre' no existe. No se puede crear la OU de destino."
        Log "ERROR: Ruta padre '$ouPadre' no existe. No se puede crear la OU de destino."
        exit
    }
}

# Obtener solo objetos dentro de la OU de origen (excluye sub-OUs)
$objetos = Get-ADObject -LDAPFilter "(&(objectClass=*)(!(objectClass=organizationalUnit)))" -SearchBase $ouOrigen

if ($objetos.Count -eq 0) {
    Write-Host "No se encontraron objetos en la OU de origen."
    Log "OU de origen sin objetos."
} else {
    Write-Host "Objetos encontrados en la OU de origen:"
    $objetos | ForEach-Object { Write-Host " - $($_.Name)" }
    Log "Objetos detectados para mover: $($objetos.Count)"

    $confirmacion = Read-Host "¿Los objetos mostrados son correctos para mover? (S/N)"
    if ($confirmacion -eq "S") {
        foreach ($objeto in $objetos) {
            try {
                Move-ADObject -Identity $objeto.DistinguishedName -TargetPath $ouDestino
                Log "Objeto movido: $($objeto.Name)"
            } catch {
                Log "ERROR al mover $($objeto.Name): $_"
            }
        }
    } else {
        $nombres = Read-Host "Introduce los nombres de los objetos a mover, separados por coma"
        $lista = $nombres -split "," | ForEach-Object { $_.Trim() }
        foreach ($nombre in $lista) {
            $obj = $objetos | Where-Object { $_.Name -eq $nombre }
            if ($obj) {
                try {
                    Move-ADObject -Identity $obj.DistinguishedName -TargetPath $ouDestino
                    Log "Objeto movido manualmente: $($obj.Name)"
                } catch {
                    Log "ERROR al mover $($obj.Name): $_"
                }
            } else {
                Log "Objeto '$nombre' no encontrado en la OU de origen."
            }
        }
    }
}

# Verificar si quedan objetos reales en la OU de origen (excluyendo la propia OU)
$objetosRestantes = Get-ADObject -LDAPFilter "(&(objectClass=*)(!(objectClass=organizationalUnit)))" -SearchBase $ouOrigen
foreach ($obj in $objetosRestantes) {
    Log "Objeto que permanece en OU de origen: $($obj.Name)"
}

# Eliminar OU de origen si está vacía
if ($objetosRestantes.Count -eq 0) {
    $borrar = Read-Host "¿Deseas eliminar la OU de origen? (S/N)"
    if ($borrar -eq "S") {
        Set-ADOrganizationalUnit -Identity $ouOrigen -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Identity $ouOrigen -Confirm:$false
        Write-Host "OU de origen eliminada."
        Log "OU de origen eliminada."
    } else {
        Log "Eliminación de OU de origen cancelada por el usuario."
    }
} else {
    Write-Host "La OU de origen aún contiene objetos. No se eliminará."
    Log "La OU de origen aún contiene objetos. No se eliminará."
}

Log "Fin del proceso."
