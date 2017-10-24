[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive')
Try {

    # Import Packaging Framework modul
    if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}

    # Install
	If ($deploymentType -ieq 'Install') {
		
        # Install setup
        Start-Program -Path "$Files\FreeMind-Windows-Installer-1.0.1-max.exe" -Parameters '/SP- /SILENT /NORESTART /NOICONS'
        
        # Remove unwanted startmenu entries
        Remove-File -Path "$CommonDesktop\FreeMind.lnk"
        Remove-File -Path "$UserDesktop\FreeMind.lnk"
        Remove-File -Path "$CommonStartMenu\FreeMind.lnk"
        Remove-File -Path "$UserStartMenu\FreeMind.lnk"
	}

	# Uninstall
    If ($deploymentType -ieq 'Uninstall') {
        
        # Uninstall setup
        Start-Program -Path "$ProgramFiles\Template\uninstall.exe" -Parameters '/S'
	}

	# Call the exit-Script
	Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}