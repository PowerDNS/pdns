# General info:
!ifdef Debug
OutFile      "Debug\pdns-install.exe"
Name         "PowerDNS 2.9.5 (DEBUG)"
!else
OutFile      "Release\pdns-install.exe"
Name         "PowerDNS 2.9.5"
!endif

BrandingText " "
Icon         "release-scripts\pdns.ico"
WindowIcon   "on"
BGGradient   0080c0 0080c0 ffffff
CRCCheck     "on"

# Install info:
InstallDir   "$PROGRAMFILES\PowerDNS\"
InstallDirRegKey HKLM SOFTWARE\PowerDNS ""

ComponentText  "This will install PowerDNS for Windows onto your computer."
InstType       "Full"
InstType       "Minimal"
LicenseText    "Please read the PowerDNS license before installing."
LicenseData    "..\LICENSE"
EnabledBitmap  "release-scripts\enabled.bmp"
DisabledBitmap "release-scripts\disabled.bmp"


# Directory info:
DirShow             "show"
DirText             "Select directory to install PowerDNS:"
AllowRootDirInstall "true"

# Install page info:
AutoCloseWindow   "true"
#UninstallIcon   "release-scripts\pdns.ico"
ShowInstDetails   "nevershow"
ShowUninstDetails "nevershow"

# Compiler info:
SetCompress  "auto"

# Install section:
Section   "PowerDNS Executeable (required)"
SectionIn "RO"

SetOutPath $INSTDIR

# Check if the directory exists.
IfFileExists "$INSTDIR\*.*" NoDir
NoDir:
  CreateDirectory "$INSTDIR"

# Add files.
SetOverwrite on

!ifdef Debug
File /oname=$INSTDIR\pdns.exe "Debug\pdns.exe"
File /oname=$INSTDIR\pdnsmsg.dll "Debug\pdnsmsg.dll"
File /oname=$INSTDIR\zone2sql.exe "Debug\zone2sql.exe"
File /oname=$INSTDIR\pdns_control.exe "Debug\pdns_control.exe"
File /oname=$INSTDIR\pdns_recursor.exe "Debug\pdns_recursor.exe"

!else
File /oname=$INSTDIR\pdns.exe "Release\pdns.exe"
File /oname=$INSTDIR\pdnsmsg.dll "Release\pdnsmsg.dll"
File /oname=$INSTDIR\zone2sql.exe "Release\zone2sql.exe"
File /oname=$INSTDIR\pdns_control.exe "Release\pdns_control.exe"
File /oname=$INSTDIR\pdns_recursor.exe "Release\pdns_recursor.exe"

!endif

File /oname=$INSTDIR\pdns.ico "release-scripts\pdns.ico"

WriteUninstaller $INSTDIR\uninst-pdns.exe

FileOpen $R2 "$INSTDIR\pdns.exe.local" "w"
FileClose $R2
FileOpen $R2 "$INSTDIR\zone2sql.exe.local" "w"
FileClose $R2
FileOpen $R2 "$INSTDIR\pdns_control.exe.local" "w"
FileClose $R2
FileOpen $R2 "$INSTDIR\pdns_recursor.exe.local" "w"
FileClose $R2


SetOverwrite ifnewer
File /oname=$INSTDIR\pthreadVCE.dll C:\WINNT\System32\pthreadVCE.dll
File /oname=$INSTDIR\msvcrt.dll C:\WINNT\System32\msvcrt.dll


WriteRegStr HKLM SOFTWARE\PowerDNS "" $INSTDIR

WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerDNS" \
                   "DisplayName" "PowerDNS Nameserver (remove only)"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerDNS" \
                   "UninstallString" "$INSTDIR\uninst-pdns.exe"

# Create default pdns configuration file.
IfFileExists "$INSTDIR\pdns.conf" NoConfWrite
  FileOpen $R1 "$INSTDIR\pdns.conf" "w"
  
  FileWrite $R1 "# PDNS configuration file.$\r$\n$\r$\n"

  FileWrite $R1 "# Use NT logging when running as a service:$\r$\n"
  FileWrite $R1 "use-ntlog=yes$\r$\n$\r$\n"

  FileWrite $R1 "# Backends to launch at startup:$\r$\n"
  FileWrite $R1 "launch=odbc$\r$\n$\r$\n"

  FileWrite $R1 "odbc-datasource=PowerDNS$\r$\n"
  FileWrite $R1 "odbc-user=PowerDNS$\r$\n"
  FileWrite $R1 "odbc-pass=PowerDNS$\r$\n"
  FileWrite $R1 "odbc-table=records$\r$\n$\r$\n"

  FileWrite $R1 "# Launch a statistical webserver:$\r$\n"
  FileWrite $R1 "webserver=yes$\r$\n"
  FileWrite $R1 "webserver-port=8081$\r$\n$\r$\n"

  FileWrite $R1 "# EOF$\r$\n"

  FileClose $R1

NoConfWrite:

SectionEnd


# Start menu section:
Section "Start menu + shortcuts"
  SectionIn 1

  CreateDirectory "$SMPROGRAMS\PowerDNS"

  WriteINIStr "$SMPROGRAMS\PowerDNS\PowerDNS Homepage.url" \
              "InternetShortcut" "URL" "http://www.powerdns.com/"

  WriteINIStr "$SMPROGRAMS\PowerDNS\PowerDNS Documentation.url" \
              "InternetShortcut" "URL" "http://downloads.powerdns.com/documentation/html/"

  CreateShortCut "$SMPROGRAMS\PowerDNS\PowerDNS.lnk" \
                 "$INSTDIR\pdns.exe" "" \
                 "$INSTDIR\pdns.ico"

  CreateShortCut "$SMPROGRAMS\PowerDNS\Uninstall PowerDNS.lnk" \
                 "$INSTDIR\uninst-pdns.exe"
  
SectionEnd


# Example section.
Section "Example zone"
  SectionIn 1

  IfFileExists $INSTDIR\powerdns.mdb Ask
    Goto OverwriteZone

Ask:
  MessageBox MB_YESNO "powerdns.mdb already exists, overwrite?" IDNO StatusEnd
    SetOverwrite on

OverwriteZone:
  File /oname=$INSTDIR\powerdns.mdb "..\modules\odbcbackend\powerdns.mdb"

StatusEnd:
SectionEnd


# Uninstall section.
Section "Uninstall"
  MessageBox MB_YESNO "Are you sure you want to uninstall PowerDNS?" IDYES Proceed
    Quit
  
Proceed: 
  IfFileExists $INSTDIR\pdns.exe Skip
    MessageBox MB_YESNO "It does not appear that PowerDNS is installed in the directory '$INSTDIR'.$\r$\nContinue anyway (not recommended)" IDYES FSkip
      Quit

Skip:
  ExecWait '"$INSTDIR\pdns.exe" --unregister-service'

FSkip:

  DeleteRegKey HKLM "System\CurrentControlSet\Services\PDNS"
  DeleteRegKey HKLM "System\CurrentControlSet\Services\Eventlog\Application\PDNS"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerDNS"
  DeleteRegKey HKLM "SOFTWARE\PowerDNS"

  RMDir /r $SMPROGRAMS\PowerDNS

  Delete $INSTDIR\pthreadVCE.dll
  Delete $INSTDIR\msvcrt.dll
  Delete $INSTDIR\pdnsmsg.dll
  Delete $INSTDIR\uninst-pdns.exe
  Delete $INSTDIR\pdns.ico
  Delete $INSTDIR\pdns.exe
  Delete $INSTDIR\pdns.exe.local
  Delete $INSTDIR\zone2sql.exe
  Delete $INSTDIR\zone2sql.exe.local
  Delete $INSTDIR\pdns_control.exe
  Delete $INSTDIR\pdns_control.exe.local
  Delete $INSTDIR\pdns_recursor.exe
  Delete $INSTDIR\pdns_recursor.exe.local

  RMDir $INSTDIR

SectionEnd



Function .onInstSuccess

  Sleep 500

  MessageBox MB_YESNO "Do you want to register PDNS as a NT service?" IDNO NoReg
    Exec '"$INSTDIR\pdns.exe" --register-service'

NoReg:
  Sleep 500

  MessageBox MB_YESNO "Installation successful!$\r$\n$\r$\nTo use the ODBC functionality in PowerDNS you need to create a ODBC data source.$\r$\nFor more information about the ODBC backend please examine the documentation.$\r$\n$\r$\nDo you want to create a data source now?" IDNO NoODBC
    Exec '"rundll32.exe" shell32.dll,Control_RunDLL odbccp32.cpl'

NoODBC:

FunctionEnd