[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive')
Try {

    # Import Packaging Framework modul
    if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}

    # Installation
    If ($deploymentType -ieq 'Install') {

        # Installation (Note: the silent.inf file is a full installatio including all language files to have multi language support)
        Start-Program -Path "$Files\WinSCP-5.9.4-Setup.exe" -Parameters "/SILENT /NORESTART /LOADINF=""$Files\Silent.inf"" /LOG=""$LogDir\$packagename`_SETUP_INSTALL`.log"""

		# Cleanup
        Remove-File -Path "$CommonStartMenuPrograms\WinSCP.lnk"

        # Disable Auto Update / Beta Version / Update Check on Startup (current user, and other users via Active Setup)
		If ((Get-Parameter 'DisableAutoUpdate') -eq $true) 
        {
            Set-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates' -Name 'Period' -Value 0 -Type DWord
            Set-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates' -Name 'BetaVersions' -Value 0 -Type DWord
            Set-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Updates' -Name 'ShowOnStartup' -Value 0 -Type DWord
			
			# Active Setup entry
			Set-ActiveSetup -StubExePath "$ProgramFilesX86\WinSCP\ActiveSetup.ps1"
		}
	}	

    # Uninstall
    If ($deploymentType -ieq 'Uninstall') {
	
		# Remove Active Setup
        Set-ActiveSetup -PurgeActiveSetupKey
		
		# Uninstall setup
		Start-Program -Path "$ProgramFilesX86\WinSCP\unins000.exe" -Parameters "/SILENT /NORESTART /LOG=""$LogDir\$packagename`_SETUP_UNINSTALL`.log"""

	}

	# Call the exit-Script
	Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}