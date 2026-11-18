# Enumerer Win32_Product declenche une reparation Windows Installer.
$produits = Get-CimInstance -ClassName Win32_Product
