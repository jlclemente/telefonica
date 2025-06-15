## EXTRAER EQUIPOS EN EL DOMINIO BASADOS EN WINDOWS"

# Definir el directorio y archivo CSV donde se guardará la información
$directorio = "C:\script\localusers"
$archivoCsv = "$directorio\computers.csv"

# Crear el directorio si no existe
if (-not (Test-Path -Path $directorio)) {
    New-Item -Path $directorio -ItemType Directory
}

# Obtener los equipos del dominio
$equipos = Get-ADComputer -Filter * -Property OperatingSystem | Where-Object { $_.OperatingSystem -like "*Windows*" }

# Crear una lista con la información que quieres guardar (por ejemplo, nombre y sistema operativo)
$equiposInfo = $equipos | Select-Object Name

# Exportar la lista de equipos al archivo CSV
$equiposInfo | Export-Csv -Path $archivoCsv -NoTypeInformation

Write-Host "La lista de equipos se ha guardado correctamente en $archivoCsv"

## IMPORTAMOS EL FICHERO COMPUTERS.CSV Y GENERAMOS EL COMANDO A USAR EN LAS MAQUINAS REMOTAS ##

$equipos = Import-Csv -Path $archivoCsv

# Iterar sobre cada registro en el CSV
foreach ($equipo in $equipos) {
    # Extraer el nombre del equipo (asumimos que la columna se llama 'Name')
    $nombreEquipo = $equipo.Name
    $username = "$nombreEquipo\spadmin"
    $Password = ConvertTo-SecureString "C4m1n4nt3s`$1601" -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ($Username, $Password)

    Write-Host $nombreEquipo
    Write-Host ""

    Get-WmiObject Win32_UserAccount -ComputerName "vdc-ava-saltoct" -Credential $Cred | 
        Where-Object { $_.LocalAccount -eq $true } | 
        Select-Object Name
       Write-Host ""
   
}