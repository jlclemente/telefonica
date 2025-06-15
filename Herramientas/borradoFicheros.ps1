# Definir las rutas de las carpetas a procesar
$logsFolder = "E:\Scripts\CopiaFicherosEditranSFTP\Logs"
$carpetaBanco1 = "E:\DATOS_BANCOS"
$carpetaBanco2 = "E:\SFTP"

# Función para borrar archivos mayores a 45 días
function BorrarArchivosAntiguos {
    param (
        [string]$directorio
    )

    # Obtener la fecha de hace 45 días
    $fechaLimite = (Get-Date).AddDays(-45)

    # Obtener los archivos en el directorio y subdirectorios
    $archivos = Get-ChildItem -Path $directorio -Recurse -File

    # Filtrar los archivos que son más antiguos que 45 días
    $archivosAntiguos = $archivos | Where-Object { $_.LastWriteTime -lt $fechaLimite }

    # Borrar los archivos antiguos
    foreach ($archivo in $archivosAntiguos) {
        Remove-Item $archivo.FullName -Force
        Write-Host "Archivo borrado: $($archivo.FullName)"
    }
}

# Borrar archivos en la carpeta Logs
BorrarArchivosAntiguos -directorio $logsFolder

# Recorrer las carpetas de los bancos en DATOS_BANCOS y SFTP
$carpetasBanco = Get-ChildItem -Path $carpetaBanco1 -Directory
$carpetasBanco += Get-ChildItem -Path $carpetaBanco2 -Directory

foreach ($banco in $carpetasBanco) {
    # Comprobar si la carpeta N43 existe en el banco
    $carpetaN43 = Join-Path $banco.FullName "N43"
    
    if (Test-Path $carpetaN43) {
        # Verificar si existen las carpetas Procesados y Erroneos
        $carpetaProcesados = Join-Path $carpetaN43 "Procesados"
        $carpetaErroneos = Join-Path $carpetaN43 "Erroneos"

        # Borrar archivos en Procesados
        if (Test-Path $carpetaProcesados) {
            BorrarArchivosAntiguos -directorio $carpetaProcesados
        }

        # Borrar archivos en Erroneos
        if (Test-Path $carpetaErroneos) {
            BorrarArchivosAntiguos -directorio $carpetaErroneos
        }
    }
}

Write-Host "Proceso completado."
