# Solicitar el path donde se crearán los usuarios
$ouPath = Read-Host "Introduce el path (OU) donde se crearán los usuarios"

# Solicitar el número de ticket
$ticket = Read-Host "Introduce el número de ticket asociado a esta alta"

# Obtener el dominio actual del entorno
$dominio = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name

# Generar nombre del log solo con la fecha y asegurarse de que exista la carpeta
$fecha = Get-Date -Format "yyyyMMdd"
$logDir = "C:\Windows\Logs"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory | Out-Null
}
$logFile = Join-Path -Path $logDir -ChildPath "$fecha`_users.log"

# Función para generar contraseñas seguras
function Generar-Password {
    $longitud = 14

    $letrasMayus = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $letrasMinus = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $numeros = '0123456789'.ToCharArray()
    $especiales = '!@#$%^&*()-_=+[]{}<>?'.ToCharArray()
    $todos = $letrasMayus + $letrasMinus + $numeros + $especiales

    $password = @()

    # Garantizar al menos un carácter de cada tipo
    $password += Get-Random -InputObject $letrasMayus
    $password += Get-Random -InputObject $letrasMinus
    $password += Get-Random -InputObject $numeros
    $password += Get-Random -InputObject $especiales

    # Rellenar el resto de la contraseña
    $resto = $longitud - $password.Count
    $password += (1..$resto | ForEach-Object { Get-Random -InputObject $todos })

    # Mezclar el resultado
    -join ($password | Get-Random -Count $password.Count)
}


# Leer datos desde el CSV
$usuarios = Import-Csv -Path ".\usuario.csv" -Delimiter ";"

foreach ($usuario in $usuarios) {
    $nombre = $usuario.nombre
    $apellidos = $usuario.apellidos
    $username = $usuario.username
    $mail = $usuario.mail
    $descripcionOriginal = $usuario.descripcion
    $descripcion = "$descripcionOriginal Alta en $ticket"

    # Construir el UserPrincipalName con el dominio actual
    $userPrincipalName = "$username@$dominio"

    # Generar contraseña segura
    $password = Generar-Password
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    # Crear usuario en AD
    try {
        New-ADUser `
            -Name "$nombre $apellidos" `
            -GivenName $nombre `
            -Surname $apellidos `
            -SamAccountName $username `
            -UserPrincipalName $userPrincipalName `
            -EmailAddress $mail `
            -AccountPassword $securePassword `
            -Enabled $true `
            -Path $ouPath `
            -Description $descripcion

        Write-Host ""
        Write-Host "Usuario $username creado correctamente."
        Write-Host "Contraseña generada: $password"

        "$username | $nombre $apellidos | $mail | $userPrincipalName | $password | OK" | Out-File -Append -FilePath $logFile
    }
    catch {
    Write-Host ""
    Write-Host ("Error al crear el usuario " + $username + ": " + $_.Exception.Message)
    ($username + " | " + $nombre + " " + $apellidos + " | " + $mail + " | " + $userPrincipalName + " | " + $password + " | ERROR: " + $_.Exception.Message) | Out-File -Append -FilePath $logFile
}

}
