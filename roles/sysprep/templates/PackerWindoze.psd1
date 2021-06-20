@{
    ModuleToProcess = 'PackerWindoze.psm1'
    ModuleVersion = '{{ windoze_version }}'
    GUID = '22645f60-5878-40ac-ac73-1054e7f3b921'
    Author = 'Jordan Borean'
    Copyright = 'Copyright (c) 2018 by Jordan Borean, licensed under MIT.'
    Description = 'Provide simple cmdlets that are used as part of the packer-windoze process like resetting the WinRM configuration'
    PowerShellVersion = '3.0'
    FunctionsToExport = @(
        'Reset-WinRMConfig'
    )
}
