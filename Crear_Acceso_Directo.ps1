# Crea un acceso directo en el escritorio para MODEXRE, con el icono
# ya aplicado automaticamente (no hace falta tocar "Propiedades ->
# Cambiar icono" a mano). Ejecutar UNA sola vez.
#
# Como ejecutarlo:
#   1. Clic derecho sobre este archivo -> "Ejecutar con PowerShell"
#   (Si Windows bloquea el script por politica de ejecucion, abre
#   PowerShell como administrador y ejecuta primero:
#     Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
#   y confirma con "S". Luego vuelve a ejecutar este script.)

$ProjectDir = $PSScriptRoot
$BatPath    = Join-Path $ProjectDir "Arrancar_MODEXRE.bat"
$IconPath   = Join-Path $ProjectDir "docs\MODEXRE.ico"
$Desktop    = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "MODEXRE.lnk"

if (-not (Test-Path $BatPath)) {
    Write-Host "ERROR: no se encuentra $BatPath" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $IconPath)) {
    Write-Host "ERROR: no se encuentra $IconPath" -ForegroundColor Red
    exit 1
}

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $BatPath
$Shortcut.WorkingDirectory = $ProjectDir
$Shortcut.IconLocation = $IconPath
$Shortcut.Description = "MODEXRE - Deteccion forense de intrusiones con IA explicable"
$Shortcut.WindowStyle = 1
$Shortcut.Save()

Write-Host "Acceso directo creado en el escritorio con el icono de MODEXRE." -ForegroundColor Green
Write-Host "Ruta: $ShortcutPath"
