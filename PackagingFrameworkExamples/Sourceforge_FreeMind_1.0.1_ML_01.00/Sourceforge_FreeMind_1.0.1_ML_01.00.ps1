[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter)
Try {

    # Import Packaging Framework module
    $Global:DeploymentType=$Script:DeploymentType ; $Global:DeployMode=$Script:DeployMode ; $Global:CustomParameter=$Script:CustomParameter ; Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}} ; Invoke-PackageStart

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

    # Call package end and exit script
	Invoke-PackageEnd ; Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}