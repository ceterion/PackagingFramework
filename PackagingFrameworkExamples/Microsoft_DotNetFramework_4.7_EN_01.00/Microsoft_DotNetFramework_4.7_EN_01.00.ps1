[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter)
Try {

    # Import Packaging Framework module
    Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}

    # Install
    If ($DeploymentType -ieq 'Install') {
		Start-Program -Path "$Files\NDP47-KB3186497-x86-x64-AllOS-ENU.exe" -Parameters "/q:a /c: setup.exe /q /norestart"
	}	

    # Uninstall
    If ($DeploymentType -ieq 'Uninstall') {
		Start-Program -Path "$Files\NDP47-KB3186497-x86-x64-AllOS-ENU.exe" -Parameters "/uninstall /q /norestart"
	}

	# Call the exit-Script
	Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}