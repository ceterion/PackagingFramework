[CmdletBinding()] Param ([Parameter(Mandatory=$false)] [ValidateSet('Install','Uninstall')] [string]$DeploymentType='Install', [Parameter(Mandatory=$false)] [ValidateSet('Interactive','Silent','NonInteractive')] [string]$DeployMode='Interactive', [Parameter(Mandatory=$false)] [string]$CustomParameter)
Try {

    # Import Packaging Framework module
    Remove-Module PackagingFramework -ErrorAction SilentlyContinue ; if (Test-Path '.\PackagingFramework\PackagingFramework.psd1') {Import-Module .\PackagingFramework\PackagingFramework.psd1 -force ; Initialize-Script} else {Import-Module PackagingFramework -force ; Initialize-Script}
	
    # Installation
    If ($deploymentType -ieq 'Install') {
		
		# Create Response File
        New-Item -Path "$Temp" -Name "java.settings.cfg" -ItemType File
		Add-Content "$Temp\java.settings.cfg" "INSTALL_SILENT=Enable"
        Get-Parameter 'InstallDir' -Expand ; Add-Content "$Temp\java.settings.cfg" "INSTALLDIR=$InstallDir"
		Add-Content "$Temp\java.settings.cfg" "EULA=Disable"
		Add-Content "$Temp\java.settings.cfg" "REBOOT=Disable"
        If ((Get-Parameter 'Static') -eq $true) { Add-Content "$Temp\java.settings.cfg" "STATIC=Enable" } Else { Add-Content "$Temp\java.settings.cfg" "STATIC=Disable" }
		If ((Get-Parameter 'DisableAutoUpdate') -eq $false) { Add-Content "$Temp\java.settings.cfg" "AUTO_UPDATE=Enable" } Else { Add-Content "$Temp\java.settings.cfg" "AUTO_UPDATE=Disable" }
		If ((Get-Parameter 'WebJava') -eq $flase) { Add-Content "$Temp\java.settings.cfg" "WEB_JAVA=Disable" } Else { Add-Content "$Temp\java.settings.cfg" "WEB_JAVA=Enable" }
		Get-Parameter 'WebJavaSecurityLevel' ; If (!$WebStartSecurityLevel) { Add-Content "$Temp\java.settings.cfg" "WEB_JAVA_SECURITY_LEVEL=H" } Else { Add-Content "$Temp\java.settings.cfg" "WEB_JAVA_SECURITY_LEVEL=$WebStartSecurityLevel" }
        If ((Get-Parameter 'WebAnalytics') -eq $true) { Add-Content "$Temp\java.settings.cfg" "WEB_ANALYTICS=Enable" } Else { Add-Content "$Temp\java.settings.cfg" "WEB_ANALYTICS=Disable" }
		If ((Get-Parameter 'NoStartmenu') -eq $false) { Add-Content "$Temp\java.settings.cfg" "NOSTARTMENU=Disable" } Else { Add-Content "$Temp\java.settings.cfg" "NOSTARTMENU=Enable" }
		If ((Get-Parameter 'Sponsors') -eq $true) { Add-Content "$Temp\java.settings.cfg" "SPONSORS=Enable" } Else { Add-Content "$Temp\java.settings.cfg" "SPONSORS=Disable" }
		If ((Get-Parameter 'RemoveOutofDateJREs') -eq $true) { Add-Content "$Temp\java.settings.cfg" "REMOVEOUTOFDATEJRES=1" } Else { Add-Content "$Temp\java.settings.cfg" "REMOVEOUTOFDATEJRES=0" }

        # Get setup file name
        $SetupFile = ($SetupFile = Get-ChildItem -Path $Files -Filter *.exe ).name
		
		# Install setup		
		Start-Program -Path "$Files\$SetupFile" -Parameters "INSTALLCFG=""$Temp\java.settings.cfg"" /s /L ""$LogDir\$PackageName`_MSI.log"""
		
		# Copy response file in log folder
        Copy-File -Path "$Temp\java.settings.cfg" -Destination "$LogDir\java.settings.cfg"
		
        # Delete response file
        Remove-File -Path "$Temp\java.settings.cfg"
		
        # Remove Tray App
        Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SunJavaUpdateSched'  
        If ($is64Bit -eq $true) { Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' -Name 'SunJavaUpdateSched'  }


	}	

    # Uninstall
    If ($deploymentType -ieq 'Uninstall') {

        # Remove MSI
        Remove-MSIApplications -Name 'Java 8 Update 144 (64-bit)'

	}

	# Call the exit-Script
	Exit-Script -ExitCode $mainExitCode

}
Catch { [int32]$mainExitCode = 60001; [string]$mainErrorMessage = "$(Resolve-Error)" ; Write-Log -Message $mainErrorMessage -Severity 3 -Source $PackagingFrameworkName ; Show-DialogBox -Text $mainErrorMessage -Icon 'Stop' ; Exit-Script -ExitCode $mainExitCode}