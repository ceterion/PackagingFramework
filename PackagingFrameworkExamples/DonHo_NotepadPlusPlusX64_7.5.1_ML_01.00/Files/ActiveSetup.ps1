if ((Get-Culture).Name -eq "de-DE")
{
    New-Item -ItemType directory -Path "${env:AppData}\Notepad++" -ErrorAction SilentlyContinue
    Copy-Item "${env:ProgramFiles}\Notepad++\\localization\german.xml" "${env:AppData}\Notepad++\\nativeLang.xml" -Verbose -Force
}
else
{
    # do nothing, user default language (english)
}
