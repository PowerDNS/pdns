# General info:
!ifdef Debug
OutFile      "Debug\pdns-win32.exe"
!else
OutFile      "Release\pdns-win32.exe"
!endif

Name         "PowerDNS Nameserver"
BrandingText " "
#Icon         "pdns.ico"
WindowIcon   "on"
BGGradient   0080c0 0080c0 ffffff
CRCCheck     "on"

# Install info:
InstallDir   "$PROGRAMFILES\PowerDNS"
InstType     "/NOCUSTOM"
LicenseText  "PowerDNS Unpaid License 0.1"
LicenseData  "LICENSE.txt"

# Directory info:
DirShow             "show"
DirText             "Select directory to install PowerDNS:"
AllowRootDirInstall "true"

# Install page info:
AutoCloseWindow "false"
#UninstallIcon   "pdns.ico"

# Compiler info:
SetCompress  "auto"

# Install section:
Section   "Server"
SectionIn "RO"

# Check if the directory exists.
IfFileExists "$INSTDIR" NoDir
NoDir:
  CreateDirectory "$INSTDIR"

# Add files.
!ifdef Debug
File /oname=$INSTDIR\pdns.exe "Debug\pdns.exe"
!else
File /oname=$INSTDIR\pdns.exe "Release\pdns.exe"
!endif

File /oname=$INSTDIR\powerdns.mdb "backends\odbc\powerdns.mdb"

File /oname=$SYSDIR\pthreadVCE.dll C:\WINNT\System32\pthreadVCE.dll
SectionEnd

# Ask to register the service with the system:
Function .onInstSuccess
  MessageBox MB_YESNO "Installation successful, do you want to register PDNS as a NT service?" IDNO NoReadme
    Exec '"$INSTDIR\pdns.exe" --register-service'
  NoReadme:
FunctionEnd

