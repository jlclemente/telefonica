# Cargar el módulo de Active Directory
Import-Module ActiveDirectory

# Ruta del archivo CSV
$csvPath = "usuario.csv"

# Leer los datos del archivo CSV
$usuarios = Import-Csv -Path $csvPath -Delimiter ','

# Recorrer cada usuario en el CSV
foreach ($usuario in $usuarios) {
    try {
        # Crear el nombre completo
        $nombreCompleto = "$($usuario.nombre) $($usuario.apellidos)"

        # Crear el nombre de usuario (SAMAccountName) y el correo electrónico
        $usuarioLogon = $usuario.usuario
        $correo = $usuario.mail

        # Definir las propiedades para el usuario
        $usuarioAD = New-ADUser -SamAccountName $usuarioLogon `
                                -UserPrincipalName "$usuarioLogon@elenebro.com" `
                                -GivenName $usuario.nombre `
                                -Surname $usuario.apellidos `
                                -Name $nombreCompleto `
                                -DisplayName $nombreCompleto `
                                -Description $usuario.descripcion `
                                -EmailAddress $correo `
                                -AccountPassword (ConvertTo-SecureString -AsPlainText $usuario.contraseña -Force) `
                                -Enabled $true `
                                -Path "OU=Users_TCCT,DC=Elenebro,DC=com" `
                                -PasswordNeverExpires $true `
                                -PassThru

        Write-Host "Usuario '$nombreCompleto' creado correctamente."

    } catch {
        Write-Host "Error al crear el usuario '$nombreCompleto': $_"
    }
}
