# Microsoft Developer Studio Project File - Name="pdns" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=pdns - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "pdns.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "pdns.mak" CFG="pdns - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "pdns - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "pdns - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "pdns - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release/"
# PROP Intermediate_Dir "Release/pdns"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GR /GX /O2 /I "./" /D "NDEBUG" /D "PtW32NoCatchWarn" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "__CLEANUP_CXX" /YX /FD /TP /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib pthreadVCE.lib ws2_32.lib /nologo /subsystem:console /machine:I386
# SUBTRACT LINK32 /profile

!ELSEIF  "$(CFG)" == "pdns - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug/"
# PROP Intermediate_Dir "Debug/pdns"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GR /GX /ZI /Od /I "./" /D "_DEBUG" /D "VERBOSELOG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "__CLEANUP_CXX" /D "PtW32NoCatchWarn" /YX /FD /TP /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib pthreadVCE.lib ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# SUBTRACT LINK32 /profile /pdb:none /map /force

!ENDIF 

# Begin Target

# Name "pdns - Win32 Release"
# Name "pdns - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\arguments.cc
# End Source File
# Begin Source File

SOURCE=.\common_startup.cc
# End Source File
# Begin Source File

SOURCE=.\communicator.cc
# End Source File
# Begin Source File

SOURCE=.\dnsbackend.cc
# End Source File
# Begin Source File

SOURCE=.\dnspacket.cc
# End Source File
# Begin Source File

SOURCE=.\dnsproxy.cc
# End Source File
# Begin Source File

SOURCE=.\dynhandler.cc
# End Source File
# Begin Source File

SOURCE=.\misc.cc
# End Source File
# Begin Source File

SOURCE=.\nameserver.cc
# End Source File
# Begin Source File

SOURCE=.\ntservice.cc
# End Source File
# Begin Source File

SOURCE=..\modules\odbcbackend\odbcbackend.cc
# End Source File
# Begin Source File

SOURCE=.\packetcache.cc
# End Source File
# Begin Source File

SOURCE=.\packethandler.cc
# End Source File
# Begin Source File

SOURCE=.\pdnsservice.cc
# End Source File
# Begin Source File

SOURCE=.\qtype.cc
# End Source File
# Begin Source File

SOURCE=.\randombackend.cc
# End Source File
# Begin Source File

SOURCE=.\resolver.cc
# End Source File
# Begin Source File

SOURCE=.\session.cc
# End Source File
# Begin Source File

SOURCE=.\statbag.cc
# End Source File
# Begin Source File

SOURCE=.\tcpreceiver.cc
# End Source File
# Begin Source File

SOURCE=.\ueberbackend.cc
# End Source File
# Begin Source File

SOURCE=.\webserver.cc
# End Source File
# Begin Source File

SOURCE=.\win32_dynlistener.cc
# End Source File
# Begin Source File

SOURCE=.\win32_dynmessenger.cc
# End Source File
# Begin Source File

SOURCE=.\win32_logger.cc
# End Source File
# Begin Source File

SOURCE=.\win32_receiver.cc
# End Source File
# Begin Source File

SOURCE=.\win32_utility.cc
# End Source File
# Begin Source File

SOURCE=.\ws.cc
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\ahuexception.hh
# End Source File
# Begin Source File

SOURCE=.\arguments.hh
# End Source File
# Begin Source File

SOURCE=.\common_startup.hh
# End Source File
# Begin Source File

SOURCE=.\communicator.hh
# End Source File
# Begin Source File

SOURCE=.\distributor.hh
# End Source File
# Begin Source File

SOURCE=.\dns.hh
# End Source File
# Begin Source File

SOURCE=.\dnsbackend.hh
# End Source File
# Begin Source File

SOURCE=.\dnspacket.hh
# End Source File
# Begin Source File

SOURCE=.\dnsproxy.hh
# End Source File
# Begin Source File

SOURCE=.\dynhandler.hh
# End Source File
# Begin Source File

SOURCE=.\dynlistener.hh
# End Source File
# Begin Source File

SOURCE=.\dynmessenger.hh
# End Source File
# Begin Source File

SOURCE=.\iputils.hh
# End Source File
# Begin Source File

SOURCE=.\lock.hh
# End Source File
# Begin Source File

SOURCE=.\logger.hh
# End Source File
# Begin Source File

SOURCE=.\misc.hh
# End Source File
# Begin Source File

SOURCE=.\nameserver.hh
# End Source File
# Begin Source File

SOURCE=.\ntservice.hh
# End Source File
# Begin Source File

SOURCE=..\modules\odbcbackend\odbcbackend.hh
# End Source File
# Begin Source File

SOURCE=.\packetcache.hh
# End Source File
# Begin Source File

SOURCE=.\packethandler.hh
# End Source File
# Begin Source File

SOURCE=.\pdnsservice.hh
# End Source File
# Begin Source File

SOURCE=.\qtype.hh
# End Source File
# Begin Source File

SOURCE=.\resolver.hh
# End Source File
# Begin Source File

SOURCE=.\session.hh
# End Source File
# Begin Source File

SOURCE=.\singleton.hh
# End Source File
# Begin Source File

SOURCE=.\statbag.hh
# End Source File
# Begin Source File

SOURCE=.\tcpreceiver.hh
# End Source File
# Begin Source File

SOURCE=.\ueberbackend.hh
# End Source File
# Begin Source File

SOURCE=.\utility.hh
# End Source File
# Begin Source File

SOURCE=.\webserver.hh
# End Source File
# Begin Source File

SOURCE=.\ws.hh
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
