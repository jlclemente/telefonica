# Ruta del archivo CSV
$csvPath = "usuario.csv"

# Leer los datos del archivo CSV
$usuarios = Import-Csv -Path $csvPath -Delimiter ','

# Recorrer cada usuario en el CSV
foreach ($usuario in $usuarios) {
    try {
        # Crear el nombre completo
        $nombreCompleto = "$($usuario.nombre) $($usuario.apellidos)"

        # Crear el nombre de usuario (para la cuenta local)
        $usuarioLogon = $usuario.usuario
        $correo = $usuario.mail

        # Crear el usuario local
        $usuarioLocal = New-LocalUser -Name $usuarioLogon `
                                      -FullName $nombreCompleto `
                                      -Description $usuario.descripcion `
                                      -Password (ConvertTo-SecureString -AsPlainText $usuario.contraseña -Force)

        # Agregar el usuario al grupo Administradores
        Add-LocalGroupMember -Group "Administradores" -Member $usuarioLogon
        Set-LocalUser -Name $usuarioLogon -PasswordNeverExpires $true
        Write-Host "Usuario local '$nombreCompleto' creado y agregado al grupo Administradores correctamente."

    } catch {
        Write-Host "Error al crear el usuario local '$nombreCompleto': $_"
    }
}
