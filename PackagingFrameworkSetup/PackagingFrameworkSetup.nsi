# Inclues
!include x64.nsh
!include MUI2.nsh

# Installer attributes
Name "ceterion Packaging Framework"
OutFile "PackagingFrameworkSetup.exe"
InstallDir "$ProgramFiles64\WindowsPowerShell\Modules\"
InstallDirRegKey HKLM "Software\PackagingFramework" ""
RequestExecutionLevel highest
BrandingText "ceterion AG"
Icon "PackagingFrameworkSetup.ico"
UninstallIcon "PackagingFrameworkSetup.ico"

# File properties
VIProductVersion "1.0.11.0"
VIAddVersionKey "ProductName" "ceterion Packaging Framework"
VIAddVersionKey "Comments" "Packaging Framework Setup"
VIAddVersionKey "FileDescription" "ceterion Packaging Framework Setup"
VIAddVersionKey "ProductVersion" "1.0.11.0"
VIAddVersionKey "LegalCopyright" "ceterion AG"
VIAddVersionKey "CompanyName" "ceterion AG"


# Interface settings
!define MUI_ABORTWARNING
!define MUI_ICON "PackagingFrameworkSetup.ico"
!define MUI_UNICON "PackagingFrameworkSetup.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "PackagingFrameworkSetupHeaderImage.bmp"
!define MUI_HEADERIMAGE_RIGHT
!define MUI_WELCOMEFINISHPAGE_BITMAP "PackagingFrameworkSetupWizardInstall.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "PackagingFrameworkSetupWizardUninstall.bmp"
!define MUI_FINISHPAGE_SHOWREADME $INSTDIR\PackagingFramework\readme.txt

# Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "PackagingFrameworkSetupLicense.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "English"
  
# Installer sections
Section "PowerShell Module" Section1
  
  # Make backup of old config file if exists (update installation)
  IfFileExists '$InstDir\PackagingFramework\PackagingFramework.json' 0 +2
  CopyFiles /FILESONLY /SILENT '$InstDir\PackagingFramework\PackagingFramework.json' '$InstDir\PackagingFramework\PackagingFramework.json.bak'

  # Install module files
  SetOutPath '$InstDir\PackagingFramework'
  File /r ..\PackagingFramework\*.*
  SetOutPath '$InstDir\PackagingFrameworkExtension'
  File /r ..\PackagingFrameworkExtension\*.*
  SetOutPath '$InstDir\PackagingFramework\SupportFiles'
  File /r ..\PackagingFrameworkSupportFiles\*.*

  # Store installation folder
  WriteRegStr HKLM "Software\PackagingFramework" "" $InstDir

  # Create uninstaller
  WriteUninstaller "$InstDir\PackagingFramework\Uninstall.exe"
  
  # Create Add/remove software entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "DisplayName" "ceterion Packaging Framework"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "DisplayVersion" "1.0.11.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "DisplayIcon" "$\"$INSTDIR\PackagingFramework\PackagingFramework.ico$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "UninstallString" "$\"$INSTDIR\PackagingFramework\uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "URLInfoAbout" "http://www.ceterion.com"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "HelpLink" "http://www.ceterion.com"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework" "Publisher" "ceterion AG"

SectionEnd

Section /o "Example Packages" Section2
  
  # Get My Documents folder
  ReadRegStr $0 HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" Personal

  # Install example packages
  SetOutPath '$0\Packaging Framework Examples'
  File /r ..\PackagingFrameworkExamples\*.*

  # Copy current modules files into each example package folder
  SetOutPath '$0\Packaging Framework Examples\Ceterion_ExamplePackage_1.0_EN_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\DonHo_NotepadPlusPlusX64_7.5.1_ML_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\IgorPavlov_7ZipX64_16.04_ML_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\MartinPrikryl_WinSCP_5.9.4_ML_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\Microsoft_DotNetFramework_4.7_EN_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\Oracle_JavaREx64_8.0.1440.11_ML_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\SimonTatham_PuTTYx64_0.70_EN_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\Sourceforge_FreeMind_1.0.1_ML_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\Sysinternals_SysinternalsSuiteJune2017_1.0_EN_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*
  SetOutPath '$0\Packaging Framework Examples\TheGimpTeam_Gimp_2.8.20_ML_01.00\PackagingFramework'
  File /r ..\PackagingFrameworkExtension\*.*
  File /r ..\PackagingFramework\*.*

  # Open example folder
  #Exec 'Explorer.exe "$0\Packaging Framework Examples"'

    # Create shortcut
  CreateShortcut "$Desktop\Packaging Framework Examples.lnk" '$0\Packaging Framework Examples'


SectionEnd

Section /o "Online Help" Section3

  # Online help 
  SetOutPath '$InstDir\PackagingFramework'
  File /r ..\PackagingFrameworkHelp\*.*

  # Create shortcut
  CreateShortcut "$Desktop\Packaging Framework Help.lnk" '$InstDir\PackagingFramework\PackagingFramework.html'

SectionEnd

# Language strings
LangString DESC_Section1 ${LANG_ENGLISH} "PowerShell Module"
LangString DESC_Section2 ${LANG_ENGLISH} "Example Packages"
LangString DESC_Section3 ${LANG_ENGLISH} "Online Help"

# Assign language strings to sections
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${Section1} $(DESC_Section1)
!insertmacro MUI_DESCRIPTION_TEXT ${Section2} $(DESC_Section2)
!insertmacro MUI_DESCRIPTION_TEXT ${Section3} $(DESC_Section3)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

# Uninstaller Section
Section "Uninstall"
  
  # Make sure InstDir is NOT the current workign dir
  SetOutPath $Temp
  
  # Remove files
  Delete "$InstDir\Uninstall.exe"
  RMDir /r "$InstDir"
  RMDir /r "$InstDir\..\PackagingFrameworkExtension"
  
  # Remove registry keys
  DeleteRegKey HKLM "Software\PackagingFramework"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ceterion Packaging Framework"

SectionEnd