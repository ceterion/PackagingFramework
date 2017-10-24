# Disable auto update and beta version notification
New-Item -path "HKCU:\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates" -force
New-ItemProperty -Path 'HKCU:\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates' -Name 'Period' -PropertyType 'DWord' -Value 0 -force
New-ItemProperty -Path 'HKCU:\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates' -Name 'BetaVersions' -PropertyType 'DWord' -Value 0 -force
New-ItemProperty -Path 'HKCU:\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates' -Name 'ShowOnStartup' -PropertyType 'DWord' -Value 0 -force
