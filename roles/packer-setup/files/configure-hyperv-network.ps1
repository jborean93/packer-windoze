$ErrorActionPreference = "Stop"

$inventory_file = "$PSScriptRoot\hosts.ini"
$ip_file = "$PSScriptRoot\hyper-v-ip.txt"

$ip_address = Get-Content -Path $ip_file
Remove-Item -Path $ip_file > $null
$contents = Get-Content -Path $inventory_file
$contents = $contents -replace "ansible_host=.*$", "ansible_host=$ip_address"
Set-Content -Path $inventory_file -Value $contents
