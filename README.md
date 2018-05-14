# rptk
Registry Persistence Toolkit (RPTK)

@kpoppenwimer

The Registry Persistence Toolkit (RPTK) is a Python-based framework that can be leveraged by forensic analysts, incident responders, and threat hunting teams to automate the process of parsing and analyzing persistence registry keys and their associated values.  Furthermore, the framework includes built-in functionality to leverage registry key whitelisting, intelligence (i.e. indicators of compromise (IOCs)), and Base64 encoding identification and decoding.

RTPK requires Python 2 (Developed and tested in Python 2.7) and the installation of Will Ballenthin's python-registry module.  Download the module from Will's github page: https://github.com/williballenthin/python-registry

For information about RPTK and usage instructions, see the following blog posts:

RPTK Overview (http://www.haloforensics.com/?p=158)

RPTK Whitelist Generator Execution (http://www.haloforensics.com/?p=181)

RPTK Execution (http://www.haloforensics.com/?p=189)

Please note, RPTK is currently in beta and needs to be thoroughly vetted by the DFIR community.  Likewise, there are additional persistence registry keys that have not been incorporated into RPTK due to a lack of testing data.  I request that the community submit sample hive files for persistence keys that are currently missing.  I will happily incorporate the additional registry keys shoudl the community provide me the necessary testing data.  RPTK is currently lacking support for the following known persistence keys:

SOFTWARE\Microsoft\Internet Explorer\Desktop\Components
SOFTWARE\Microsoft\Internet Explorer\Explorer Bars
SOFTWARE\Microsoft\Internet Explorer\UrlSearchHooks
SOFTWARE\Classes\.cmd
SOFTWARE\Classes\.exe
SOFTWARE\Classes\Filter
SOFTWARE\Microsoft\Ctf\LangBarAddin
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Run
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Shell
SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\Scrnsave.exe
SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logoff
SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logon
SOFTWARE\Classes\Filter
SOFTWARE\Microsoft\Ctf\LangBarAddin
SOFTWARE\Microsoft\Internet Explorer\Explorer Bars
SOFTWARE\Microsoft\Windows CE Services\AutoStartOnConnect
SOFTWARE\Microsoft\Windows CE Services\AutoStartOnDisconnect
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown
SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Shell
SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logoff
SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logon
SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Shutdown
SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup
SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Explorer Bars
SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnConnect
SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnDisconnect

####################################################################################

SYSTEM\CurrentControlSet\Control\BootVerificationProgram\ImagePath
SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
SYSTEM\CurrentControlSet\Control\NetworkProvider\Order
SYSTEM\CurrentControlSet\Control\Print\Monitors
SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell
SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders
SYSTEM\CurrentControlSet\Control\ServiceControlManagerExtension
SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
SYSTEM\CurrentControlSet\Control\Session Manager\Execute
SYSTEM\CurrentControlSet\Control\Session Manager\S0InitialCommand
SYSTEM\CurrentControlSet\Control\Session Manager\SetupExecute
SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms
SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram
SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries
SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64
SYSTEM\Setup\CmdLine
