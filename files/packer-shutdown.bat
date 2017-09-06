REM remove the WinRM listener so vagrant up waits until sysprep is finished
winrm delete winrm/config/Listener?Address=*+Transport=HTTP
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS

REM shutdown the host
shutdown /s /t 0
