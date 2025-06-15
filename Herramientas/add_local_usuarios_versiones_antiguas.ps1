# Cargar los usuarios desde el archivo CSV
$usuarios = Import-Csv -Path "usuario.csv"

# Iterar sobre cada usuario
foreach ($usuario in $usuarios) {
    $usuarioLogon = $usuario.usuario
    $usuarioPass = $usuario.contraseña
    $nombreCompleto = $usuario.nombre + " " + $usuario.apellidos
    $descripcion = $usuario.descripcion

    # Crear el usuario local
    try {
        # Comando para crear el usuario con net user
        $createUserCmd = "net user $usuarioLogon $usuarioPass /add"
        Invoke-Expression $createUserCmd
        Write-Host "Usuario $usuarioLogon creado exitosamente."

        # Establecer el nombre completo (FullName)
        $setFullNameCmd = "net user $usuarioLogon /fullname:`"$nombreCompleto`""
        Invoke-Expression $setFullNameCmd
        Write-Host "Nombre completo del usuario $usuarioLogon establecido."

        # Establecer la descripción
        $setDescriptionCmd = "net user $usuarioLogon /description:`"$descripcion`""
        Invoke-Expression $setDescriptionCmd
        Write-Host "Descripción del usuario $usuarioLogon establecida."

        # Añadir el usuario al grupo de administradores
        $addAdminCmd = "net localgroup Administradores $usuarioLogon /add"
        Invoke-Expression $addAdminCmd
        Write-Host "Usuario $usuarioLogon añadido al grupo Administradores."
    }
    catch {
        Write-Host "Error al crear o configurar el usuario $usuarioLogon"
    }
}