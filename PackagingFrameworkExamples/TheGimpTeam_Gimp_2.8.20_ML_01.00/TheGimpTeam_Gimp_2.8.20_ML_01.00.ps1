[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter)
Try {

    # Import Packaging Framework module
    $Global:DeploymentType=$Script:DeploymentType ; $Global:DeployMode=$Script:DeployMode ; $Global:CustomParameter=$Script:CustomParameter ; Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}} ; Invoke-PackageStart

    # Installation
    If ($deploymentType -ieq 'Install') {

		# Install setup
        Start-Program -Path "$Files\Gimp-2.8.20-setup.exe" -Parameters "/SILENT /NORESTART /SUPPRESSMSGBOXES /LOG=""$LogDir\$packagename`_SETUP_INSTALL`.log"""

		# Cleanup
        Remove-File -path "$CommonStartMenuPrograms\GIMP 2.lnk"
	}	

    # Uninstall
    If ($deploymentType -ieq 'Uninstall') {
	
		# Uninstall setup
        Start-Program -Path "$ProgramFiles\GIMP 2\uninst\unins000.exe" -Parameters "/SILENT /NORESTART /SUPPRESSMSGBOXES /LOG=""$LogDir\$packagename`_SETUP_UNINSTALL`.log"""
		
	}

    # Call package end and exit script
	Invoke-PackageEnd ; Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}