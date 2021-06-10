Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    Get-ChildItem $_.Root -Filter bootstrap.ps1 -ErrorAction SilentlyContinue
} | Select-Object -First 1 | ForEach-Object { . $_.FullName }
