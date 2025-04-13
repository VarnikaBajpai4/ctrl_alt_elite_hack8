import "pe"

rule MALWARE_Win_Laturo {
    meta:
        author = "ditekSHen"
        description = "Laturo information stealer payload"
        clamav_sig = "MALWARE.Win.Trojan.Laturo"
    strings:
        $str1 = "cmd.exe /c ping 127.0.0.1" ascii wide
        $str2 = "cmd.exe /c start" ascii wide
        $str3 = "\\RapidLoader\\" ascii
        $str4 = "loader/gate.php" ascii wide
        $str5 = "Hwid:" ascii wide
        $str6 = "Special:" ascii wide
        $str7 = "logs=%s" ascii
        $data1 = "cookies.%u.txt" nocase ascii wide
        $data2 = "passwords.%u.txt" nocase ascii wide
        $data3 = "credentials.%u.txt" nocase ascii wide
        $data4 = "cards.%u.txt" nocase ascii wide
        $data5 = "autofill.%u.txt" nocase ascii wide
        $data6 = "loginusers.vdf" ascii wide
        $data7 = "screenshot.bmp" nocase ascii wide
        $data8 = "webcam.bmp" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 5 of ($str*) and 1 of ($data*)
}

rule MALWARE_Win_XpertRAT {
    meta:
        author = "ditekSHen"
        description = "XpertRAT payload"
        snort_sid = "920003-920006"
        clamav_sig = "MALWARE.Win.Trojan.XpertRAT"
    strings:
        $v1 = "[XpertRAT-Mutex]" fullword wide
        $v2 = "XPERTPLUGIN" fullword wide
        $v3 = "+Xpert+3." wide
        $v4 = "keylog.tmp" fullword wide
        $v5 = "\\TempReg.reg" fullword wide
        
        $s1 = "ClsKeylogger" fullword ascii nocase
        $s2 = "clsCamShot" fullword ascii nocase
        $s3 = "ClsShellCommand" fullword ascii nocase
        $s4 = "ClsRemoteDesktop" fullword ascii nocase
        $s5 = "ClsScreenRemote" fullword ascii nocase
        $s6 = "ClsSoundRemote" fullword ascii nocase
        $s7 = "MdlHidder" fullword ascii
        $s8 = "modKeylog" fullword ascii
        $s9 = "modWipe" fullword ascii
        $s10 = "modDelProcInUse" fullword ascii
        $s11= "Socket_DataArrival" fullword ascii
        $s12 = "cZip_EndCompress" fullword ascii

    condition:
        uint16(0) == 0x5a4d and (3 of ($v*) or 6 of ($s*))
}

rule MALWARE_Win_AgentTeslaV2 {
    meta:
        author = "ditekSHen"
        description = "AgenetTesla Type 2 Keylogger payload"
    strings:
        $s1 = "get_kbHook" ascii
        $s2 = "GetPrivateProfileString" ascii
        $s3 = "get_OSFullName" ascii
        $s4 = "get_PasswordHash" ascii
        $s5 = "remove_Key" ascii
        $s6 = "FtpWebRequest" ascii
        $s7 = "logins" fullword wide
        $s8 = "keylog" fullword wide
        $s9 = "1.85 (Hash, version 2, native byte-order)" wide

        $cl1 = "Postbox" fullword ascii
        $cl2 = "BlackHawk" fullword ascii
        $cl3 = "WaterFox" fullword ascii
        $cl4 = "CyberFox" fullword ascii
        $cl5 = "IceDragon" fullword ascii
        $cl6 = "Thunderbird" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}

rule MALWARE_Win_AveMaria {
    meta:
        author = "ditekSHen"
        description = "AveMaria variant payload"
    strings:
        $s1_1 = "PK11_CheckUserPassword" fullword ascii
        $s1_2 = "PK11_Authenticate" fullword ascii
        $s1_3 = "PK11SDR_Decrypt" fullword ascii
        $s1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" fullword ascii
        $s1_5 = "AVE_MARIA" ascii wide
        $s1_6 = "127.0.0." ascii

        $s2_1 = "RDPClip" fullword wide
        $s2_2 = "Grabber" fullword wide
        $s2_3 = "Ave_Maria Stealer OpenSource" wide
        $s2_4 = "\\MidgetPorn\\workspace\\MsgBox.exe" wide
        $s2_5 = "@\\cmd.exe" wide
        $s2_6 = "/n:%temp%\\ellocnak.xml" wide
        $s2_7 = "Hey I'm Admin" wide
        $s2_8 = "warzone160" fullword ascii

        $d1 = "softokn3.dll" fullword wide
        $d2 = "nss3.dll" fullword wide
        $d3 = "logins.json" wide
        $d4 = "Asend.db" fullword wide       
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s2*) and 2 of ($d*)) or (all of ($s1*))) or ((4 of ($s1*) and 2 of ($d*)) or (all of ($s1*)))
}

rule MALWARE_Win_ISRStealer {
    meta:
        author = "ditekSHen"
        description = "ISRStealer payload"
        clamav_sig = "MALWARE.Win.Trojan.ISRStealer"
    strings:
        $s1 = "&password=" wide
        $s2 = "&pcname=" wide
        $s3 = "MSVBVM60.DLL" ascii
        $s4 = "MSVBVM60.DLL" wide
        $s5 = "Core Software For : Public" wide
        $s6 = "</Host>" wide
        $s7 = "</Pass>" wide
        $s8 = "/scomma" wide
    condition:
        (uint16(0) == 0x5a4d and filesize < 4000KB and 6 of them) or all of them
}

rule MALWARE_Win_QuasarRAT {
    meta:
        author = "ditekSHen"
        description = "QuasarRAT payload"
    strings:
        $s1 = "GetKeyloggerLogsResponse" fullword ascii
        $s2 = "GetKeyloggerLogs" fullword ascii
        $s3 = "/>Log created on" wide
        $s4 = "User: {0}{3}Pass: {1}{3}Host: {2}" wide
        $s5 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide
        $s6 = "grabber_" wide
        $s7 = "<virtualKeyCode>" ascii
        $s8 = "<RunHidden>k__BackingField" fullword ascii
        $s9 = "<keyboardHookStruct>" ascii
        $s10 = "add_OnHotKeysDown" ascii
        $mutex = "QSR_MUTEX_" ascii wide
        $ua1 = "Mozilla/5.0 (Windows NT 6.3; rv:48.0) Gecko/20100101 Firefox/48.0" fullword wide
        $us2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword wide
    condition:
        uint16(0) == 0x5a4d and ($mutex or (all of ($ua*) and 2 of them) or 6 of ($s*))
}

rule MALWARE_Win_LimeRAT {
    meta:
        author = "ditekSHen"
        description = "LimeRAT payload"
    strings:
        $s1 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr" wide
        $s2 = "\\vboxhook.dll" fullword wide
        $s3 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide
        $s4 = "select CommandLine from Win32_Process where Name='{0}'" wide
        $s5 = "Minning..." fullword wide
        $s6 = "Regasm.exe" fullword wide
        $s7 = "Flood!" fullword wide
        $s8 = "Rans-Status" fullword wide
        $s9 = "cmd.exe /c ping 0"  wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_GuLoader {
    meta:
        author = "ditekSHen"
        description = "Shellcode injector and downloader"
    strings:
        $s1 = "wininet.dll" fullword ascii
        $s2 = "ShellExecuteW" fullword ascii
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii
        $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
        $s6 = "Startup key" fullword ascii
        $s7 = "\\qemu-ga\\qga.state" ascii nocase
        $s8 = "\\qga\\qga.exe" ascii nocase
        $s9 = "\\Qemu-ga\\qemu-ga.exe" ascii nocase
        $s10 = "WScript.Shell" ascii

        $l1 = "shell32" fullword ascii
        $l2 = "kernel32" fullword ascii
        $l3 = "advapi32" fullword ascii
        $l4 = "user32" fullword ascii

        $o1 = "msvbvm60.dll" fullword wide
        $o2 = "\\syswow64\\" fullword wide
        $o3 = "\\system32\\" fullword wide
        $o4 = "\\Microsoft.NET\\Framework\\" fullword wide
        $o5 = "USERPROFILE=" fullword wide
        $o6 = "windir=" fullword wide
        $o7 = "APPDATA=" fullword wide
        $o8 = "RegAsm.exe" fullword wide
        $o9 = "ProgramFiles=" fullword wide
        $o10 = "TEMP=" fullword wide

        $url1 = "https://drive.google.com/uc?export=download&id=" ascii
        $url2 = "https://onedrive.live.com/download?cid=" ascii
        $url3 = "http://myurl/myfile.bin" fullword ascii
        $url4 = "http" ascii // fallback
    condition:
        (3 of ($s*) and 2 of ($l*) and 2 of ($o*) and 1 of ($url*)) or (4 of ($s*) and 3 of ($l*) and 2 of ($o*))
}

rule MALWARE_Win_Arkei {
    meta:
        author = "ditekSHen"
        description = "Detect Arkei infostealer variants"
    strings:
        $s1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii wide
        $s2 = "/c taskkill /im " fullword ascii
        $s3 = "card_number_encrypted FROM credit_cards" ascii
        $s4 = "\\wallet.dat" ascii
        $s5 = "Arkei/" wide
        $s6 = "files\\passwords." ascii wide
        $s7 = "files\\cc_" ascii wide
        $s8 = "files\\autofill_" ascii wide
        $s9 = "files\\cookies_" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_DCRat {
    meta:
        author = "ditekSHen"
        description = "DCRat payload"
    strings:
        // DCRat
        $dc1 = "DCRatBuild" ascii
        $dc2 = "DCStlr" ascii
        $x1 = "px\"><center>DCRat Keylogger" wide
        $x2 = "DCRat-Log#" wide
        $x3 = "DCRat.Code" wide
        $string1 = "CaptureBrowsers" fullword ascii
        $string2 = "DecryptBrowsers" fullword ascii
        $string3 = "Browsers.IE10" ascii
        $string4 = "Browsers.Chromium" ascii
        $string5 = "WshShell" ascii
        $string6 = "SysMngmts" fullword ascii
        $string7 = "LoggerData" fullword ascii
        // DCRat Plugins/Libraries
        $plugin = "DCRatPlugin" fullword ascii
        // AntiVM
        $av1 = "AntiVM" ascii wide
        $av2 = "vmware" fullword wide
        $av3 = "VirtualBox" fullword wide
        $av4 = "microsoft corporation" fullword wide
        $av5 = "VIRTUAL" fullword wide
        $av6 = "DetectVirtualMachine" fullword ascii
        $av7 = "Select * from Win32_ComputerSystem" fullword wide
        // Plugin_AutoStealer, Plugin_AutoKeylogger
        $pl1 = "dcratAPI" fullword ascii
        $pl2 = "dsockapi" fullword ascii
        $pl3 = "file_get_contents" fullword ascii
        $pl4 = "classthis" fullword ascii
        $pl5 = "typemdt" fullword ascii
        $pl6 = "Plugin_AutoStealer" ascii wide
        $pl7 = "Plugin_AutoKeylogger" ascii wide
        // variant
        $v1 = "Plugin couldn't process this action!" wide
        $v2 = "Unknown command!" wide
        $v3 = "PLUGINCONFIGS" wide
        $v4 = "Saving log..." wide
        $v5 = "~Work.log" wide
        $v6 = "MicrophoneNum" fullword wide
        $v7 = "WebcamNum" fullword wide
        $v8 = "%SystemDrive% - Slow" wide
        $v9 = "%UsersFolder% - Fast" wide
        $v10 = "%AppData% - Very Fast" wide
        $v11 = /<span style=\"color: #F85C50;\">\[(Up|Down|Enter|ESC|CTRL|Shift|Win|Tab|CAPSLOCK: (ON|OFF))\]<\/span>/ wide
        $px1 = "[Browsers] Scanned elements: " wide
        $px2 = "[Browsers] Grabbing cookies" wide
        $px3 = "[Browsers] Grabbing passwords" wide
        $px4 = "[Browsers] Grabbing forms" wide
        $px5 = "[Browsers] Grabbing CC" wide
        $px6 = "[Browsers] Grabbing history" wide
        $px7 = "[StealerPlugin] Invoke: " wide
        $px8 = "[Other] Grabbing steam" wide
        $px9 = "[Other] Grabbing telegram" wide
        $px10 = "[Other] Grabbing discord tokens" wide
        $px11 = "[Other] Grabbing filezilla" wide
        $px12 = "[Other] Screenshots:" wide
        $px13 = "[Other] Clipboard" wide
        $px14 = "[Other] Saving system information" wide
    condition:
        uint16(0) == 0x5a4d and (all of ($dc*) or all of ($string*) or 2 of ($x*) or 6 of ($v*) or 5 of ($px*)) or ($plugin and (4 of ($av*) or 5 of ($pl*)))
}

rule MALWARE_Win_ObliqueRAT {
    meta:
        author = "ditekSHen"
        description = "ObliqueRAT payload"
    strings:
        $s1 = "C:\\ProgramData\\auto.txt" fullword ascii
        $s2 = "C:\\ProgramData\\System\\Dump\\" fullword ascii
        $s3 = "C:\\ProgramData\\a.txt" fullword ascii
        $s4 = "Oblique" fullword ascii
        $s5 = /(Removable|Hard|Network|CD|RAM)\sDisk\|/ ascii
        $s6 = "backed" fullword ascii
        $s7 = "restart" fullword ascii
        $s8 = "kill" fullword ascii
        $s9 = /(John|JOHN|Test|TEST|Johsnson|Artifact|Vince|Serena|Lisa|JOHNSON|VINCE|SERENA)/ ascii nocase
        $v1 = "C:\\ProgramData" fullword ascii
        $v2 = "auto" fullword ascii
        $v3 = "plit" fullword ascii
        $v4 = ":image/jpeg" fullword wide
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_FirebirdRAT {
    meta:
        author = "ditekSHen"
        description = "Firebird/Hive RAT payload"
        clamav_sig = "MALWARE.Win.Trojan.Firebird-HiveRAT"
    strings:
        $id1 = "Firebird Remote Administration Tool" fullword wide
        $id2 = "Welcome to Firebird! Your system is currently being monitored" wide
        $id3 = "Hive Remote Administration Tool" fullword wide
        $id4 = "Welcome to Hive! Your system is currently being monitored" wide
        $s1 = "REPLACETHESEKEYSTROKES" fullword wide
        $s2 = "_ENABLE_PROFILING" fullword wide
        $s3 = ": KeylogSubject" wide
        $s4 = "Firebird.CommandHandler" fullword wide        
        $s5 = "webcamenabled" fullword ascii
        $s6 = "screenlogs" fullword ascii
        $s7 = "encryptedconnection" fullword ascii
        $s8 = "monitoron" fullword ascii
        $s9 = "screenGrab" fullword ascii
        $s10 = "TCP_TABLE_OWNER_PID_ALL" fullword ascii
        $s11 = "de4fuckyou" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($id*) or 7 of ($s*))
}

rule MALWARE_Win_Phoenix {
    meta:
        author = "ditekSHen"
        description = "Phoenix/404KeyLogger keylogger payload"
        clamav_sig = "MALWARE.Win.Trojan.Phoenix-Keylogger"
    strings:
        $s1 = "FirefoxPassReader" fullword ascii
        $s2 = "StartKeylogger" fullword ascii
        $s3 = "CRYPTPROTECT_" ascii
        $s4 = "Chrome_Killer" fullword ascii
        $s5 = "Clipboardlog.txt" fullword wide
        $s6 = "Leyboardlogs.txt" fullword wide
        $s7 = "Persistence'" wide
        $s8 = "set_HKB" fullword ascii
        $s9 = "loloa" fullword ascii
        $s10 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR1.0.3705;)" fullword wide
        // Memory
        $m1 = "- Screenshot -------|" ascii wide
        $m2 = "- Clipboard -------|" ascii wide
        $m3 = "- Logs -------|" ascii wide
        $m4 = "- Passwords -------|" ascii wide
        $m5 = "PSWD" ascii wide
        $m6 = "Screenshot |" ascii wide
        $m7 = "Logs |" ascii wide
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*) or 3 of ($m*)) or 9 of them
}

rule MALWARE_Win_BackNet {
    meta:
        author = "ditekSHen"
        description = "BackNet payload"
        clamav_sig = "MALWARE.Win.Trojan.BackNet"
    strings:
        $s1 = "Slave.Commands." fullword ascii
        $s2 = "StartKeylogger" fullword ascii
        $s3 = "StopKeylogger" fullword ascii
        $s4 = "KeyLoggerCommand" fullword ascii
        $s5 = "get_keyLoggerManager" fullword ascii
        $s6 = "get_IgnoreMutex" fullword ascii
        $s7 = "ListProcesses" fullword ascii
        $s8 = "downloadurl" fullword wide
        $pdb = "\\BackNet-master\\Slave\\obj\\Release\\Slave.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and ($pdb or all of ($s*))
}

rule MALWARE_Win_AcridRain {
    meta:
        author = "ditekSHen"
        description = "AcidRain stealer payload"
    strings:
        $s1 = { 43 6f 6f 6b 69 65 73 (5c|2e) }
        $s2 = { 74 65 6d 70 6c 6f 67 69 ?? }
        $s3 = { 74 65 6d 70 50 ?? 68 }
        $s4 = "Connecting to hostname: %s%s%s" fullword ascii
        $s5 = "Found bundle for host %s: %p [%s]" fullword ascii
        $s6 = "encryptedUsernamencryptedPassworERROR Don't copy string" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Linux_ChaChaDDoS {
    meta:
        author = "ditekSHen"
        description = "ChaChaDDoS variant of XorDDoS payload"
    strings:
        $x1 = "[kworker/1:1]" ascii
        $x2 = "-- LuaSocket toolkit." ascii
        $x3 = "/etc/resolv.conf" ascii
        $x4 = "\"macaddress=\" .. DEVICE_MAC .. \"&device=\" .." ascii
        $x5 = "easy_attack_dns" ascii
        $x6 = "easy_attack_udp" ascii
        $x7 = "easy_attack_syn" ascii
        $x8 = "syn_probe" ascii
    condition:
    uint16(0) == 0x457f and 6 of them
}

rule MALWARE_Multi_Exaramel {
    meta:
        author = "ditekSHen"
        description = "Exaramel Windows/Linux backdoor payload"
        clamav_sig1 = "MALWARE_Linux.Backdoor.Exaramel"
        clamav_sig2 = "MALWARE_Win.Backdoor.Exaramel"
    strings:
        // Linux payload
        $s1 = "vendor/golang_org/x/crypto/" ascii
        $s2 = "vendor/golang_org/x/net/http2" ascii
        $s3 = "vendor/golang_org/x/text/unicode" ascii
        $s4 = "vendor/golang_org/x/text/transform" ascii
        $s5 = "config.json" ascii
        $cmd1 = "App.Update" ascii
        $cmd2 = "App.Delete" ascii
        $cmd3 = "App.SetProxy" ascii
        $cmd4 = "App.SetServer" ascii
        $cmd5 = "App.SetTimeout" ascii
        $cmd6 = "IO.WriteFile" ascii
        $cmd7 = "IO.ReadFile" ascii
        $cmd8 = "OS.ShellExecute" ascii
        $cmd9 = "awk 'match($0, /(upstart|systemd|sysvinit)/){ print substr($0, RSTART, RLENGTH);exit;" ascii
        // Windows payload
        $ws1 = "/commands/@slp" wide
        $ws2 = "/commands/cmd" wide
        $ws3 = "/settings/proxy/@password" wide
        $ws4 = "/settings/servers/server[@current='true']" wide
        $ws5 = "/settings/servers/server/@current[text()='true']" wide
        $ws6 = "/settings/servers/server[text()='%s']/@current" wide
        $ws7 = "/settings/servers/server[%d]" wide
        $ws8 = "/settings/storage" wide
        $ws9 = "/settings/check" wide
        $ws10 = "/settings/interval" wide
        $ws11 = "report.txt" wide
        $ws12 = "stg%02d.cab" ascii
        $ws13 = "urlmon.dll" ascii
        $ws14 = "ReportDir" ascii
    condition:
        (uint16(0) == 0x457f and (all of ($s*) and 6 of ($cmd*))) or (uint16(0) == 0x5a4d and 12 of ($ws*))
}

rule MALWARE_Linux_HiddenWasp {
    meta:
        author = "ditekSHen"
        description = "HiddenWasp backdoor payload"
        clamav_sig1 = "MALWARE_Linux.Trojan.HiddenWasp-ELF"
        clamav_sig2 = "MALWARE_Linux.Trojan.HiddenWasp-Script"
    strings:
        $x1 = "I_AM_HIDDEN" fullword ascii
        $x2 = "HIDE_THIS_SHELL" fullword ascii
        $x3 = "NewUploadFile" ascii
        $x4 = "fake_processname" ascii
        $x5 = "swapPayload" ascii
        $x6 = /Trojan-(Platform|Machine|Hostname|OSersion)/ fullword ascii
        $s1 = "FileOpration::GetFileData" fullword ascii
        $s2 = "FileOpration::NewUploadFile" fullword ascii
        $s3 = "Connection::writeBlock" fullword ascii
        $s4 = /hiding_(hidefile|enable_logging|hideproc|makeroot)/ fullword ascii
        $s5 = "Reverse-Port" fullword ascii
        $s6 = "hidden_services" fullword ascii
        $s7 = "check_config" fullword ascii
        $s8 = "__data_start" fullword ascii
        $s9 = /patch_(suger_lib|ld|lib)/ fullword ascii
        $s10 = "hexdump -ve '1/1 \"%%.2X\"' %s | sed \"s/%s/%s/g\" | xxd -r -p > %s.tmp"
    condition:
        uint16(0) == 0x457f and (4 of ($x*) or all of ($s*) or (3 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Multi_WellMess {
    meta:
        author = "ditekSHen"
        description = "WellMess Windows/Linux backdoor payload"
        clamav_sig1 = "MALWARE_Win.Trojan.WellMess_DotNet"
        clamav_sig2 = "MALWARE_Win.Trojan.WellMess_Golang"
        clamav_sig3 = "MALWARE_Linux.Trojan.WellMess_Golang"
    strings:
        // Linux and Windows payload
        $s1 = "-----BEGIN PUBLIC KEY-----" ascii
        $s2 = "-----END PUBLIC KEY-----" ascii
        $s3 = "net/http.(*persistConn).readResponse" ascii
        $s4 = "net/http/cookiejar.(*Jar).SetCookies" ascii
        $s5 = "_/home/ubuntu/GoProject/src/bot/botlib" ascii
        $s6 = "<;head;><;title;>" ascii
        $s7 = "<;title;><;service;>" ascii
        $s8 = "http://invalidlookup" ascii
        $s9 = "<autogenerated>" ascii wide
        //$ua1 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" ascii
        //$ua2 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0" ascii
    condition:
        (uint16(0) == 0x457f or uint16(0) == 0x5a4d) and all of them
}

rule MALWARE_Win_Konni {
    meta:
        author = "ditekSHen"
        description = "Konni payload"
    strings:
        $s1 = "uplog.tmp" fullword wide
        $s2 = "upfile.tmp" fullword wide
        $s3 = "%s-log-%s" fullword ascii wide
        $s4 = "%s-down" ascii wide
        $s5 = "%s-file-%s" fullword ascii wide
        $s6 = "\"rundll32.exe\" \"%s\" install" fullword wide
        $s7 = "subject=%s&data=" fullword ascii
        $s8 = "dll-x64.dll" fullword ascii
        $s9 = "dll-x32.dll" fullword ascii
        $pdb1 = "\\virus-dropper\\Release\\virus-dropper.pdb" ascii
        $pdb2 = "\\virus-init\\Release\\virus-init.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (3 of ($s*) and 1 of ($pdb*)))
}

rule MALWARE_Win_BitterRAT {
    meta:
        author = "ditekSHen"
        description = "BitterRAT payload"
        clamav_sig = "MALWARE.Win.Trojan.BitterRAT"
    strings:
        $s1 = "getfile" fullword wide
        $s2 = "getfolder" fullword wide
        $s3 = "winmgmts://./root/default:StdRegProv" fullword wide
        $s4 = "winlog" fullword wide
        $s5 = "winprt" fullword wide
        $s6 = "c:\\intel\\" fullword ascii
        $s7 = "AXE: #" fullword ascii
        $s8 = "Bld: %s.%s.%s" fullword ascii
        $s9 = "53656C656374202A2066726F6D2057696E33325F436F6D707574657253797374656D" wide nocase
        $pdb1 = "\\28NovDwn\\Release\\28NovDwn.pdb" ascii
        $pdb2 = "\\Shellcode\\Release\\Shellcode.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($*) or (4 of ($s*) and 1 of ($pdb*)))
}

rule MALWARE_Win_TJKeylogger {
    meta:
        author = "ditekSHen"
        description = "TJKeylogger payload"
    strings:
        $s1 = "TJKeyLogger" fullword ascii
        $s2 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii
        $s3 = "\\Passwords.txt" ascii
        $s4 = "TJKeyLogItem" fullword ascii
        $s5 = "TJKeyAsyncLog" fullword ascii
        $s6 = "FM_GETDSKLST" fullword ascii
        $s7 = "KL_GETMODE" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_W1RAT {
    meta:
        author = "ditekSHen"
        description = "W1 RAT payload"
    strings:
        $s1 = "/c /Ox /Fa\"%s/%s.asm\" /Fo\"%s/%s.obj\" \"%s/%s.%s\"" ascii
        $s2 = "this->piProcInfo.hProcess" fullword ascii
        $s3 = "index >= 0 && index < this->reg_tab->GetLen()" fullword ascii
        $s4 = "strcpy(log_font.lfFaceName,\"%s\");" fullword ascii
        $s5 = "WorkShop -- [%s]" fullword ascii
        $s6 = "HeaderFile.cpp" fullword ascii
        $s7 = "WndLog.cpp" fullword ascii
        $s8 = "assertion fail \"%s\" at file=%s line=%d" fullword ascii
        $s9 = "Stdin   pipe   creation   failed" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (all of them)
}

rule MALWARE_Win_Raccoon {
    meta:
        author = "ditekSHen"
        description = "Raccoon stealer payload"
    strings:
        $s1 = "inetcomm server passwords" fullword wide
        $s2 = "content-disposition: form-data; name=\"file\"; filename=\"data.zip\"" fullword ascii
        $s3 = ".?AVfilesystem_error@v1@filesystem@experimental@std@@" fullword ascii
        $s4 = "CredEnumerateW" fullword ascii
        $s5 = "%[^:]://%[^/]%[^" fullword ascii
        $s6 = "%99[^:]://%99[^/]%99[^" fullword ascii
        $s7 = "Login Data" wide
        $s8 = "m_it.object_iterator != m_object->m_value.object->end()" fullword wide
        $x1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $x2 = "\\json.hpp" wide
        $x3 = "Microsoft_WinInet_" fullword wide
        $x4 = "Microsoft_WinInet_*" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((3 of ($x*) and 2 of ($s*)) or (4 of ($s*) and 1 of ($x*)))
}

rule MALWARE_Win_Amadey {
    meta:
        author = "ditekSHen"
        description = "Amadey downloader payload"
    strings:
        $s1 = "_ZZ14aGetProgramDirvE11UsersDirRes" fullword ascii
        $s2 = "_libshell32_a" ascii
        $s3 = "_ShellExecuteExA@4" ascii
        $s4 = "aGetTempDirvE10TempDirRes" ascii
        $s5 = "aGetHostNamevE7InfoBuf" ascii
        $s6 = "aCreateProcessPc" ascii
        $s7 = "aGetHostNamev" ascii
        $s8 = "aGetSelfDestinationiE22aGetSelfDestinationRes" ascii
        $s9 = "aGetSelfPathvE15aGetSelfPathRes" ascii
        $s10 = "aResolveHostPcE15aResolveHostRes" ascii
        $s11 = "aUrlMonDownloadPcS" ascii
        $s12 = "aWinSockPostPcS_S_" ascii
        $s13 = "aCreateProcessPc" ascii

        $v1 = "hii^" fullword ascii
        $v2 = "plugins/" fullword ascii
        $v3 = "ProgramData\\" fullword ascii
        $v4 = "&unit=" fullword ascii
        $v5 = "runas" fullword ascii wide
        $v6 = "Microsoft Internet Explorer" fullword wide
        $v7 = "stoi argument" ascii

        $av1 = "AVAST Software" fullword ascii
        $av2 = "Avira" fullword ascii
        $av3 = "Kaspersky Lab" fullword ascii
        $av4 = "ESET" fullword ascii
        $av5 = "Panda Security" fullword ascii
        $av6 = "Doctor Web" fullword ascii
        $av7 = "360TotalSecurity" fullword ascii
        $av8 = "Bitdefender" fullword ascii
        $av9 = "Norton" fullword ascii
        $av10 = "Sophos" fullword ascii
        $av11 = "Comodo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (6 of ($v*) and 2 of ($av*)))
}


rule MALWARE_Win_Tefosteal {
    meta:
        author = "ditekSHen"
        description = "Tefosteal payload"
        clamav_sig = "MALWARE.Win.Trojan.Tefosteal"
    strings:
        $s1 = "netsh wlan show networks mode=bssid" nocase fullword wide
        $s2 = "LoginCredentialService.GetLoginCredentials$" ascii
        $s3 = "DefaultLoginCredentials.LoginEventUsrPw$" ascii
        $s4 = "SEC_E_NO_KERB_KEY" wide
        $s5 = "TList<System.Zip.TZipHeader>." ascii
        $s6 = "_Password.txt" fullword wide nocase
        $s7 = "_Cookies.txt" fullword wide nocase
        $f1 = "\\InfoPC\\BSSID.txt" wide
        $f2 = "\\Files\\Telegram\\" wide
        $f3 = "\\InfoPC\\Screenshot.png" wide
        $f4 = "\\InfoPC\\Systeminfo.txt" wide
        $f5 = "\\Steam\\config" wide
        $f6 = "\\delete.vbs" wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) and 2 of ($f*)
}

rule MALWARE_Win_CryptoStealerGo {
    meta:
        author = "ditekSHen"
        description = "CryptoStealerGo payload"
    strings:
        $s1 = "Go build ID: \"" ascii
        $s2 = "file_upload.go" ascii
        $s3 = "grequests.FileUpload" ascii
        $s4 = "runtime.newproc" ascii
        $s5 = "credit_cards" ascii
        $s6 = "zip.(*fileWriter).Write" ascii
        $s7 = "autofill_" ascii
        $s8 = "XFxVc2VyIERhdGFcXA==" ascii
        $s9 = "XFxBcHBEYXRhXFxMb2NhbFxc" ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_M00nD3v {
    meta:
        author = "ditekSHen"
        description = "M00nD3v keylogger payload"
    strings:
        $s1 = "M00nD3v Stub" ascii wide
        $s2 = "M00nD3v{0}{1} Logs{0}{2} \\ {3}{0}{0}{4}" fullword wide
        $s3 = "Anti-Keylogger Elite" wide
        $s4 = "/C TASKKILL /F /IM" wide
        $s5 = "echo.>{0}:Zone.Identifier" fullword wide
        $s6 = "> Nul & Del \"{0}\" & start \"\" \"{1}.exe\"" wide
        $s7 = "> Nul & start \"\" \"{1}.exe\"" wide
        $s8 = "Stealer" fullword wide
        $s9 = "{0}{0}++++++++++++{1} {2}++++++++++++{0}{0}" wide
        $s10 = "{4}Application: {3}{4}URL: {0}{4}Username: {1}{4}Password: {2}{4}" wide
        $s11 = "encrypted_key\":\"(?<Key>.+?)\"" wide
        $s12 = "Botkiller" fullword ascii
        $s13 = "AVKiller" fullword ascii
        $s14 = "get_pnlPawns" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of them) or (9 of them)
}

rule MALWARE_Win_VSSDestroy {
    meta:
        author = "ditekSHen"
        description = "VSSDestroy/Matrix ransomware payload"
        snort_sid = "920008-920009"
        clamav_sig = "MALWARE.Win.Ransomware.VSSDestroy"
    strings:
        $o1 = "[SHARESSCAN]" wide
        $o2 = "[LDRIVESSCAN]" wide
        $o3 = "[LOGSAVED]" wide
        $o4 = "[LPROGRESS]" wide
        $o5 = "[FINISHSAVED]" wide
        $o6 = "[ALL_LOCAL_KID]" wide
        $o7 = "[DIRSCAN" wide
        $o8 = "[GENKEY]" wide
        $s1 = "\\cmd.exe" nocase wide
        $s2 = "/C powershell \"" nocase wide
        $s3 = "%COMPUTERNAME%" wide
        $s4 = "%USERNAME%" wide
        $s5 = "Error loading Socket interface (ws2_32.dll)!" wide
        $s6 = "Old file list dump found. Want to load it? (y/n):" fullword wide
    condition:
        (uint16(0) == 0x5a4d and 4 of ($o*) and 3 of ($s*)) or (5 of ($o*) and 4 of ($s*))
}

rule MALWARE_Win_GoldenAxe {
    meta:
        author = "ditekSHen"
        description = "GoldenAxe ransomware payload"
        clamav_sig = "MALWARE.Win.Ransomware.GoldenAxe"
    strings:
        $s1 = "Go build ID: " ascii
        $s2 = "taskkill.exe" ascii
        $s3 = "cmd.exe" ascii
        $s4 = "Speak.Speak" ascii
        $s5 = "CLNTSRVRnull" ascii
        $s6 = "-----END" ascii        
        $s7 = "-----BEGIN" ascii
        $s8 = ".EncryptFile" ascii
        $g1 = "GoldenAxe/Utils." ascii
        $g2 = "GoldenAxe/Cryptography." ascii
        $g3 = "GoldenAxe/Walker." ascii
        $g4 = "C:/Users/alpha/go/src/GoldenAxe/" ascii
        $g5 = "'Golden Axe ransomware'" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($g*) and 1 of ($s*)))
}

rule MALWARE_Win_Robbinhood {
    meta:
        author = "ditekSHen"
        description = "Robbinhood ransomware payload"
        clamav_sig = "MALWARE.Win.Ransomware.Robbinhood"
    strings:
        $go = "Go build ID:" ascii
        $cmd1 = "cmd.exe /c" ascii
        $cmd2 = "net use * /DELETE" nocase ascii
        $cmd3 = "sc.exe stop" ascii
        $cmd4 = "vssadmin resize shadowstorage" nocase ascii
        $s1 = /Skipping\s(file|dir)/ ascii
        $s2 = "Encrypt[ERR] GET Size:" ascii
        $s3 = ".taskkilltasklistunknown(" ascii
        $s4 = ".sysvssadmin.exewevtutil.exe MB released" ascii
        $s5 = ".sysvssadmin.exewevtutil.exewinlogin.exewinlogon.exe MB released" ascii
        $s6 = ".enc_robbinhood" ascii
        $s7 = "c:\\windows\\temp\\pub.key" nocase ascii
        $s8 = "main.CoolMaker" ascii
        $s9 = "/valery/go/src/oldboy/" ascii
    condition:
        uint16(0) == 0x5a4d and ($go and 1 of ($cmd*) and 3 of ($s*))
}

rule MALWARE_Win_GetCrypt {
    meta:
        author = "ditekSHen"
        description = "GetCrypt ransomware payload"
        clamav_sig1 = "MALWARE_Win.Ransomware.GetCrypt-1"
        clamav_sig2 = "MALWARE_Win.Ransomware.GetCrypt-2"
    strings:
        $x1 = "delete shadows /all /quiet" wide
        $x2 = "C:\\Windows\\System32\\svchost.exe" fullword wide
        $x3 = "desk.bmp" fullword wide
        $x4 = ":\\Boot" fullword wide
        $x5 = "\\encrypted_key.bin" fullword wide
        $x6 = "vssadmin.exe" fullword wide
        $x7 = ":\\Recovery" fullword wide
        $s1 = "CryptEncrypt" fullword ascii
        $s2 = "NtWow64ReadVirtualMemory64" fullword ascii
        $s3 = "MPR.dll" fullword ascii
        $s4 = "%key%" fullword ascii
        $s5 = "CryptDestroyKey" fullword ascii
        $s6 = "ntdll.dll" fullword ascii
        $s7 = "WNetCancelConnection2W" fullword ascii
        $s8 = ".%c%c%c%c" fullword wide
        // is slowing down scanning
        //$s9 = /([Gg]uest|[Aa]dministrator|[Dd]eveloper|[Rr][0Oo]{2}t|[Aa]dmin)/ fullword ascii wide
        $s10 = { 43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 00 00
                 cb 00 43 72 79 70 74 45 6e 63 72 79 70 74 00 00
                 c1 00 43 72 79 70 74 41 63 71 75 69 72 65 43 6f
                 6e 74 65 78 74 41 00 00 c8 00 43 72 79 70 74 44
                 65 73 74 72 6f 79 4b 65 79 00 d2 00 43 72 79 70
                 74 47 65 6e 52 61 6e 64 6f 6d 00 00 c2 00 43 72
                 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78
                 74 57 00 00 41 44 56 41 50 49 33 32 2e 64 6c 6c
                 00 00 b5 01 53 68 65 6c 6c 45 78 65 63 75 74 65
                 45 78 57 00 53 48 45 4c 4c 33 32 2e 64 6c 6c 00 }
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or 8 of ($s*))
}

rule MALWARE_JoeGo {
    meta:
        author = "ditekSHen"
        description = "JoeGo ransomware payload"
        clamav_sig = "MALWARE.Win.Ransomware.JoeGo"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "%SystemRoot%\\system32\\%v." ascii
        $s2 = "REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V" ascii
        $s3 = "/t REG_SZ /F /D %userprofile%\\" ascii
        $s4 = "(sensitive) [recovered]" ascii
        $s5 = "/dev/stderr/dev/stdout/index.html" ascii
        $s6 = "%userprofile%\\SystemApps" ascii
        $s7 = "p=<br>ACDTACSTAEDTAESTAKDTAKSTAWSTA" ascii
        $cnc1 = "/detail.php" ascii
        $cnc2 = "/checkin.php" ascii
        $cnc3 = "/platebni_brana.php" ascii
        $cnc4 = "://nebezpecnyweb.eu/" ascii
    condition:
        uint16(0) == 0x5a4d and $go and (all of ($s*) or (3 of ($s*) and 1 of ($cnc*)))
}

rule MALWARE_Win_Aurora {
    meta:
        author = "ditekSHen"
        description = "Aurora ransomware payload"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii wide
        $s2 = "#DECRYPT_MY_FILES#.txt" fullword ascii
        $s3 = "/gen.php?generate=" fullword ascii
        $s4 = "geoplugin.net/php.gp" ascii
        $s5 = "/end.php?id=" fullword ascii
        $s6 = "wotreplay" fullword ascii
        $s7 = "moneywell" fullword ascii
        $s8 = "{btc}" fullword ascii
        $s9 = ".?AV_Locimp@locale@std@@" ascii
        $s10 = ".?AV?$codecvt@DDU_Mbstatet@@@std@@" ascii
        $s11 = ".?AU_Crt_new_delete@std@@" ascii
        $pdb1 = "\\z0ddak\\Desktop\\source\\Release\\Ransom.pdb" ascii
        $pdb2 = "\\Desktop\\source\\Release\\Ransom.pdb" ascii
    condition:
         uint16(0) == 0x5a4d and ((1 of ($pdb*) and 5 of ($s*)) or (8 of them))
}

rule MALWARE_Win_Buran {
    meta:
        author = "ditekSHen"
        description = "Buran ransomware payload"
        clamav_sig = "MALWARE.Win.Ransomware.Buran"
    strings:
        // Variant 1
        $v1_1 = "U?$error_info_injector@V" ascii
        $v1_2 = "Browse for Folder (FTP)" fullword ascii
        $v1_3 = "Find/Replace in Files" fullword ascii
        $v1_4 = "PAHKLM" fullword ascii
        $v1_5 = "PAHKCR" fullword ascii
        $v1_6 = "chkOpt_" ascii
        $h1 = "Search <a href=\"location\" class=\"menu\">in this folder</a>" ascii
        $h2 = "<br>to find where the text below" ascii
        $h3 = "</a> files with these extensions (separate with semi-colons)" ascii
        $h4 = "Need help with <a href=\"" ascii
        $path = "\\work\\cr\\nata\\libs\\boost_" wide
        // Variant 2
        $v2_1 = "(ShlObj" fullword ascii
        $v2_2 = "\\StreamUnit" fullword ascii
        $v2_3 = "TReadme" fullword ascii
        $v2_4 = "TDrivesAndShares" fullword ascii
        $v2_5 = "TCustomMemoryStreamD" fullword ascii
        $v2_6 = "OpenProcessToken" fullword ascii
        $v2_7 = "UrlMon" fullword ascii
        $v2_8 = "HttpSendRequestA" fullword ascii
        $v2_9 = "InternetConnectA" fullword ascii
        $v2_10 = "FindFiles" fullword ascii
        $v2_12 = "$*@@@*$@@@$" ascii
    condition:
        uint16(0) == 0x5a4d and (((all of ($v1*) and 1 of ($h*)) or ($path and 2 of ($v1*) and 1 of ($h*)) or 10 of them) or all of ($v2*))
}

rule MALWARE_Win_MassLogger {
    meta:
        author = "ditekSHen"
        description = "MassLogger keylogger payload"
    strings:
        $s1 = "MassLogger v" ascii wide
        $s2 = "MassLogger Started:" ascii wide
        $s3 = "MassLogger Process:" ascii wide
        $s4 = "/panel/upload.php" wide
        $s5 = "ftp://" wide
        $s6 = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" fullword wide
        $s7 = "^(.*/)?([^/\\\\.]+/\\\\.\\\\./)(.+)$" fullword wide
        $s8 = "Bot Killer" ascii
        $s9 = "Keylogger And Clipboard" ascii
        $c1 = "costura.ionic.zip.reduced.dll.compressed" fullword ascii
        $c2 = "CHECKvUNIQUEq" fullword ascii
        $c3 = "HOOK/MEMORY6" fullword ascii
        $c4 = "Massfile" ascii wide
        $c5 = "Fz=[0-9]*'skips*" fullword ascii
        $c6 = ":=65535zO" fullword ascii
        $c7 = "!$!%!&!'!(!)!*!.!/!0!4!" fullword ascii
        $c8 = "5!9!:!<!>!@!E!G!J!K!L!N!O!P!`!" fullword ascii
        $c9 = "dllToLoad" fullword ascii
        $c10 = "set_CreateNoWindow" fullword ascii
        $c11 = "FtpWebRequest" fullword ascii
        $c12 = "encryptedUsername" fullword ascii
        $c13 = "encryptedPassword" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 9 of ($c*)) or (5 of ($s*) or 9 of ($c*))
}

rule MALWARE_Win_Echelon {
    meta:
        author = "ditekSHen"
        description = "Echelon information stealer payload"
    strings:
        $s1 = "<GetStealer>b__" ascii
        $s2 = "clearMac" fullword ascii
        $s3 = "path2save" fullword ascii
        $s4 = "Echelon_Size" fullword ascii
        $s5 = "Echelon Stealer by" wide
        $s6 = "get__masterPassword" fullword ascii
        $s7 = "DomainDetect" fullword ascii
        $s8 = "[^\\u0020-\\u007F]" fullword wide
        $s9 = "/sendDocument?chat_id=" wide
        $s10 = "//setting[@name='Password']/value" wide
        $s11 = "Passwords_Mozilla.txt" fullword wide
        $s12 = "Passwords_Edge.txt" fullword wide
        $s13 = "@madcod" ascii wide
        $pdb = "\\Echelon-Stealer-master\\obj\\Release\\Echelon.pdb" ascii
    condition:
        (uint16(0) == 0x5a4d and (8 of ($s*) or $pdb)) or (8 of ($s*) or $pdb)
}

rule MALWARE_Win_Qulab {
    meta:
        author = "ditekSHen"
        description = "Qulab information stealer payload or artifacts"
        clamav_sig = "MALWARE.Win.Trojan.QulabZ-Stealer"
    strings:
        $x1 = "QULAB CLIPPER + STEALER" ascii wide
        $x2 = "MASAD CLIPPER + STEALER" ascii wide
        $x3 = "http://teleg.run/Qulab" ascii wide
        $x4 = "http://teleg.run/jew_seller" ascii wide
        $x5 = "BUY CLIPPER + STEALER" ascii wide
        $s1 = "\\Screen.jpg" ascii wide
        $s2 = "attrib +s +h \"" ascii wide
        $s3 = "\\x86_microsoft-windows-" ascii wide
        $s4 = "\\amd64_microsoft-windows-" ascii wide
        $s5 = "Desktop TXT File" ascii wide
        $s6 = "\\AutoFills.txt" ascii wide
        $s7 = "\\CreditCards.txt" ascii wide
        $s8 = "a -y -mx9 -ssw" ascii wide
        $s9 = "\\Passwords.txt" ascii wide
        $s10 = "\\Information.txt" ascii wide
        $s11 = "\\getMe" ascii wide
    condition:
        9 of them or ((1 of ($x*) and 4 of ($s*)) or 1 of ($x*))
}

rule MALWARE_Win_Orion {
    meta:
        author = "ditekSHen"
        description = "Orion Keylogger payload"
    strings:
        $s1 = "\\Ranger.BrowserLogging" ascii wide nocase
        $s2 = "GrabAccounts" fullword ascii
        $s3 = "DownloadFile" fullword ascii
        $s4 = "Internet Explorer Recovery" wide
        $s5 = "Outlook Recovery" wide
        $s6 = "Thunderbird Recovery" wide
        $s7 = "Keylogs -" wide
        $s8 = "WebCam_Capture.dll" wide
        $s9 = " is not installed on this computer!" wide
        $s10 = "cmd /c bfsvc.exe \"" wide
        $s11 = "/Keylogs - PC:" fullword wide
        $s12 = "/PC:" fullword wide
        $s13 = "<p style=\"color:#CC7A00\">[" wide
    condition:
        (uint16(0) == 0x5a4d and 5 of ($s*)) or (6 of ($s*))
}

rule MALWARE_Win_Aspire {
    meta:
        author = "ditekSHen"
        description = "Aspire Keylogger payload"
    strings:
        $s1 = "AspireLogger -" wide
        $s2 = "Application: @" wide
        $s3 = "encryptedUsername" wide
        $s4 = "encryptedPassword" wide
        $s5 = "Fetch users fron logins" wide
        $s6 = "URI=file:" wide
        $s7 = "signons.sqlite" wide
        $s8 = "logins.json" wide
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (7 of ($s*))
}

rule MALWARE_Win_S05Kitty {
    meta:
        author = "ditekSHen"
        description = "Sector05 Kitty RAT payload"
    strings:
        $s1 = "Execute Comand" ascii
        $s2 = "InjectExplorer" ascii
        $s3 = "targetProcess = %s" fullword ascii
        $s4 = "Process attach (%s)" fullword ascii
        $s5 = "process name: %s" fullword ascii
        $s6 = "cmd /c %s >%s" fullword ascii
        $s7 = "CmdDown: %s, failed" fullword ascii
        $s8 = "http://%s%s/%s" fullword ascii
        $s9 = "tmp.LOG" fullword ascii
        $x1 = "zerodll.dll" fullword ascii
        $x2 = "OneDll.dll" fullword ascii
        $x3 = "kkd.bat" fullword ascii
        $x4 = "%s\\regsvr32.exe /s \"%s\"" fullword ascii
        $x5 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fontchk.jse" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (8 of ($s*) or all of ($x*))
}

rule MALWARE_Win_FakeWMI {
    meta:
        author = "ditekSHen"
        description = "FakeWMI payload"
        clamav_sig = "MALWARE.Win.Trojan.Fakewmi"
    strings:
        $s1 = "-BEGIN RSA PUBLIC KEY-" ascii
        $s2 = ".exe|" ascii
        $s3 = "cmd /c wmic " ascii
        $s4 = "cmd /c sc " ascii
        $s5 = "schtasks" ascii
        $s6 = "taskkill" ascii
        $s7 = "findstr" ascii
        $s8 = "netsh interface" ascii
        $s9 = "CreateService" ascii
    condition:
       uint16(0) == 0x5a4d and (all of ($s*) and #s2 > 10)
}

rule MALWARE_Win_Baldr {
    meta:
        author = "ditekSHen"
        description = "Baldr payload"
        clamav_sig = "MALWARE.Win.Trojan.Baldr"
    strings:
        $x1 = "BALDR VERSION : {0}" fullword wide
        $x2 = "Baldr" fullword ascii wide
        $x3 = "{0}\\{1:n}.exe" fullword wide
        $x4 = ".doc;.docx;.log;.txt;" fullword wide
        $s1 = "<GetMAC>b__" ascii
        $s2 = "<ExtractPrivateKey3>b__" ascii
        $s3 = "UploadData" fullword ascii
        $s6 = "get_NetworkInterfaceType" fullword ascii
        $s5 = "get_Passwordcheck" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and all of ($x*)) or (2 of ($x*) and 4 of ($s*))
}

rule MALWARE_Win_Megumin {
    meta:
        author = "ditekSHen"
        description = "Megumin payload"
        clamav_sig = "MALWARE.Win.Trojan.Megumin"
    strings:
        $s1 = "loadpe|" fullword ascii
        $s2 = "Megumin/2.0" fullword ascii
        $s3 = "/c start /I \"\" \"" fullword ascii
        $s4 = "jsbypass|" fullword ascii

        $cnc1 = "Mozilla/5.0 (Windows NT 6.1) Megumin/2.0" fullword ascii
        $cnc2 = "/cdn-cgi/l/chk_jschl?s=" fullword ascii
        $cnc3 = "/newclip?hwid=" fullword ascii
        $cnc4 = "/isClipper" fullword ascii
        $cnc5 = "/task?hwid=" fullword ascii
        $cnc6 = "/completed?hwid=" fullword ascii
        $cnc7 = "/gate?hwid=" fullword ascii
        $cnc8 = "/addbot?hwid=" fullword ascii

        $pdb = "\\MeguminV2\\Release\\MeguminV2.pdb" ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($cnc*) or $pdb)) or 11 of them
}

rule MALWARE_Win_Rietspoof {
    meta:
        author = "ditekSHen"
        description = "Rietspoof payload"
        clamav_sig = "MALWARE.Win.Trojan.Rietspoof"
    strings:
        $c1 = "%s%s%s USER: user" fullword ascii
        $c2 = "cmd /c %s" fullword ascii
        $c3 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(" ascii
        $c4 = "WScript.Quit" fullword ascii
        $c5 = "CPU: %s(%d)" fullword ascii
        $c6 = "RAM: %lld Mb" fullword ascii
        $c7 = "data.dat" fullword ascii
        $c8 = "%s%s%s USER:" ascii

        $v1_1 = ".vbs" ascii
        $v1_2 = "HELLO" ascii
        $v1_3 = "Wscript.Sleep" ascii
        $v1_4 = "User-agent:Mozilla/5.0 (Windows; U;" ascii

        $v2_1 = "Xjoepxt!" ascii
        $v2_2 = "Content-MD5:%s" fullword ascii
        $v2_3 = "M9h5an8f8zTjnyTwQVh6hYBdYsMqHiAz" fullword ascii
        $v2_4 = "GET /%s?%s HTTP/1.1" fullword ascii
        $v2_5 = "GET /?%s HTTP/1.1" fullword ascii

        $pdb1 = "\\techloader\\loader\\loader.odb" ascii wide
        $pdb2 = "\\loader\\Release\\loader_v1.0.pdb" ascii wide
    condition:
        uint16(0) == 0x5a4d and (7 of ($c*) and (3 of ($v*) or 1 of ($pdb*)))
}

rule MALWARE_Win_MoDiRAT {
    meta:
        author = "ditekSHen"
        description = "MoDiRAT payload"
    strings:
        $s1 = "add_Connected" fullword ascii
        $s2 = "Statconnected" fullword ascii
        $s3 = "StartConnect" fullword ascii
        $s4 = "TelegramTitleDetect" fullword ascii
        $s5 = "StartTitleTelegram" fullword ascii
        $s6 = "Check_titles" fullword ascii
        $s7 = "\\MoDi RAT V" ascii
        $s8 = "IsBuzy" fullword ascii
        $s9 = "Recording_Time" fullword wide
    condition:
        (uint16(0) == 0x5a4d and 7 of them) or all of them
}

rule MALWARE_DOC_KoadicDOC {
    meta:
        author = "ditekSHen"
        description = "Koadic post-exploitation framework document payload"
    strings:
        $s1 = "&@cls&@set" ascii
        $s2 = /:~\d+,1%+/ ascii
        $s3 = "Header Char" fullword wide
        $s4 = "EMBED Package" ascii
        $b1 = ".bat\"%" ascii
        $b2 = ".bat');\\\"%" ascii
        $b3 = ".bat',%" ascii
    condition:
        uint16(0) == 0xcfd0 and all of ($s*) and 2 of ($b*)
}

rule MALWARE_BAT_KoadicBAT {
    meta:
        author = "ditekSHen"
        description = "Koadic post-exploitation framework BAT payload"
    strings:
        $s1 = "&@cls&@set" ascii
        $s2 = /:~\d+,1%+/ ascii
    condition:
        uint32(0) == 0x4026feff and all of them and #s2 > 100
}

rule MALWARE_JS_KoadicJS {
    meta:
        author = "ditekSHen"
        description = "Koadic post-exploitation framework JS payload"
    strings:
        $s1 = "window.moveTo(-" ascii
        $s2 = "window.onerror = function(sMsg, sUrl, sLine) { return false; }" fullword ascii
        $s3 = "window.onfocus = function() { window.blur(); }" fullword ascii
        $s4 = "window.resizeTo(" ascii
        $s5 = "window.blur();" fullword ascii
        $hf1 = "<hta:application caption=\"no\" windowState=\"minimize\" showInTaskBar=\"no\"" fullword ascii
        $hf2 = "<hta:application caption=\"no\" showInTaskBar=\"no\" windowState=\"minimize\" navigable=\"no\" scroll=\"no\""
        $ht1 = "<hta:application" ascii
        $ht2 = "caption=\"no\"" ascii
        $ht3 = "showInTaskBar=\"no\"" ascii
        $ht4 = "windowState=\"minimize\"" ascii 
        $ht5 = "navigable=\"no\"" ascii
        $ht6 = "scroll=\"no\"" ascii
    condition:
        all of ($s*) and (1 of ($hf*) or all of ($ht*))
}

rule MALWARE_Win_NETEAGLE {
    meta:
        author = "ditekSHen"
        description = "NETEAGLE backdoor payload"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
        $s2 = "System\\CurrentControlSet\\control\\ComputerName\\ComputerName" fullword ascii
        $s3 = "Mozilla/4.0 (compatible; MSIE 5.0; Win32)" fullword ascii
        $s4 = "/index.htm" fullword ascii
        $s5 = "Help_ME" fullword ascii
        $s6 = "GOTO ERROR" ascii
        $s7 = "127.0.0.1" fullword ascii
        $s8 = /pic\d\.bmp/ ascii wide
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule MALWARE_WIN_BACKSPACE {
    meta:
        author = "ditekSHen"
        description = "BACKSPACE backdoor payload"
    strings:
        $s1 = "Software\\Microsoft\\PnpSetup" ascii wide
        $s2 = "Mutex_lnkword_little" ascii wide
        $s3 = "(Prxy%c-%s:%u)" fullword ascii
        $s4 = "(Prxy-No)" fullword ascii
        $s5 = "/index.htm" fullword ascii
        $s6 = "CONNECT %s:%d" ascii
        $s7 = "\\$NtRecDoc$" fullword ascii
        $s8 = "qazWSX123$%^" ascii
        $s9 = "Software\\Microsoft\\Core" ascii wide
        $s10 = "Mutex_lnkch" ascii wide
        $s11 = "Event__lnkch__" ascii wide
        $s12 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Win32)" fullword ascii
        $s13 = "User-Agent: Mozilla/5.00 (compatible; MSIE 6.0; Win32)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_RHttpCtrl {
    meta:
        author = "ditekSHen"
        description = "RHttpCtrl backdoor payload"
    strings:
        $s1 = "%d_%04d%02d%02d%02d%02d%02d." ascii
        $s2 = "ver=%s&id=%06d&type=" ascii
        $s3 = "ver=%d&id=%s&random=%d&" ascii
        $s4 = "id=%d&output=%s" ascii
        $s5 = "Error:WinHttpCrackUrl failed!/n" ascii
        $s6 = "Error:SendRequest failed!/n" ascii
        $s7 = ".exe a %s %s" ascii
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0" fullword wide
        $pdb = "\\WorkSources\\RHttpCtrl\\Server\\Release\\svchost.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or ($pdb and 2 of ($s*)))
}

rule MALWARE_Win_PillowMint {
    meta:
        author = "ditekSHen"
        description = "PillowMint POS payload"
    strings:
        $s1 = "system32\\sysvols\\" ascii nocase
        $s2 = "Sysnative\\sysvols\\" ascii nocase
        $s3 = "critical.log" fullword ascii
        $s4 = "log.log" fullword ascii
        $s5 = "commands.txt" fullword ascii
        $s6 = "_EV0LuTi0N_" ascii
        $s7 = /(file|reg)\scmd:/ fullword ascii
        $s8 = "dumper_nologs_" ascii
        $s9 = "ReflectiveLoader" ascii
    condition:
       uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_BlackshadesRAT {
    meta:
        author = "ditekSHen"
        description = "BlackshadesRAT / Cambot POS payload"
        snort_sid = "920208-920210"
    strings:
        $s1 = "bhookpl.dll" fullword wide
        $s2 = "drvloadn.dll" fullword wide
        $s3 = "drvloadx.dll" fullword wide
        $s4 = "SPY_NET_RATMUTEX" fullword wide
        $s5 = "\\dump.txt" fullword wide
        $s6 = "AUTHLOADERDEFAULT" fullword wide
        $pdb = "*\\AC:\\Users\\Admin\\Desktop_old\\Blackshades project\\bs_bot\\bots\\bot\\bs_bot.vbp" fullword wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or ($pdb and 2 of ($s*)))
}

rule MALWARE_Win_GoldenSpy {
    meta:
        author = "SpiderLabs Trustwave"
        description = "GoldenSpy dropper payload"
        reference = "https://trustwave.azureedge.net/media/16908/the-golden-tax-department-and-emergence-of-goldenspy-malware.pdf"
    strings:
        $reg = "Software\\IDG\\DA" nocase wide ascii // registry entry
        $str1 = "requestStr" nocase wide ascii // POST request the machine details with this parameter
        $str2 = "nb_app_log_mutex" nocase wide ascii // Mutex 
        $str3 = { 510F4345[0-10]50518D8DCCFE[0-20]837D1C[0-20]8D45[0-15]0F4345[0-20]505157 } // Data collection and passed to requestStr in POST
    condition:
        (uint16(0) == 0x5A4D) and $reg and 2 of ($str*)
}

rule MALWARE_Win_Plurox {
    meta:
      author = "ditekSHen"
      description = "Plurox backdoor payload"
    strings:
      $s1 = "autorun.c" fullword ascii
      $s2 = "launcher.c" fullword ascii
      $s3 = "loader.c" fullword ascii
      $s4 = "stealth.c" fullword ascii
      $s5 = "RunFromMemory" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Avalon {
    meta:
      author = "ditekSHen"
      description = "Avalon infostealer payload"
    strings:
      $s1 = "Parsecards" fullword ascii
      $s2 = "Please_Gofuckyouself" fullword ascii
      $s3 = "GetDomainDetect" fullword ascii
      $s4 = "GetTotalCommander" fullword ascii
      $s5 = "KnownFolder" fullword ascii
      $s6 = "set_hidden" fullword ascii
      $s7 = "set_system" fullword ascii

      $l1 = "\\DomainDetect.txt" wide
      $l2 = "\\Grabber_Log.txt" wide
      $l3 = "\\Programs.txt" wide
      $l4 = "\\Passwords_Edge.txt" wide
      $l5 = "\\KL.txt" wide

      $w1 = "dont touch" fullword wide
      $w2 = "Grabber" fullword wide
      $w3 = "Keylogger" fullword wide
      $w4 = "password-check" fullword wide
      $w5 = "H4sIAAAAAAAEA" wide

      $p1 = "^(?!:\\/\\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$" wide
      $p2 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" wide
   condition:
      uint16(0) == 0x5a4d and 8 of them 
}

rule MALWARE_Linux_Kinsing {
    meta:
      author = "ditekSHen"
      description = "Kinsing RAT payload"
    strings:
      $s1 = "backconnect" ascii
      $s2 = "connectForSocks" ascii
      $s3 = "downloadAndExecute" ascii
      $s4 = "download_and_exec" ascii
      $s5 = "masscan" ascii
      $s6 = "UpdateCommand:" ascii
      $s7 = "exec_out" ascii
      $s8 = "doTask with type %s" ascii
   condition:
      uint16(0) == 0x457f and 6 of them
}

rule MALWARE_Win_Avaddon {
    meta:
      author = "ditekSHen"
      description = "Avaddon ransomware payload"
    strings:
      $s1 = "\\IMAGEM~1.%d\\VISUA~1\\BIN\\%s.exe" ascii
      $s2 = "\\IMAGEM~1.%.2d-\\VISUA~1\\BIN\\%s.exe" ascii
      $s3 = "\\IMAGEM~1.%d-Q\\VISUA~1\\BIN\\%s.exe" ascii
      $s4 = "\\IMAGEM~1.%d\\%s.exe" ascii
      $s5 = "EW6]>mFXDS?YBi?W5] CY 4Z8Y BY7Y BZ8Z CY7Y AY8Z CZ8Y!Y:Z" ascii
      $s6 = "FY  AY 'Z      ;W      @Y  @Y 'Z    Y  @Y (Z" ascii
      $s7 = "\"rcid\":\"" fullword ascii
      $s8 = "\"ip\":\"" fullword ascii wide
      $s9 = ".?AUANEventIsGetExternalIP@@" fullword ascii
      $s10 = ".?AUANEventGetCpuMax@@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_ProLock {
    meta:
      author = "ditekSHen"
      description = "ProLock ransomware payload"
      clamav_sig = "MALWARE.Win.Ransomware.ProLock"
    strings:
      $s1 = ".flat" fullword ascii
      $s2 = ".data" fullword ascii
      $s3 = ".api" fullword ascii
      $s4 = "RtlZeroMemory" fullword ascii
      $s5 = "LoadLibraryA" fullword ascii
      $s6 = "Sleep" fullword ascii
      $s7 = "lstrcatA" fullword ascii
      $s8 = { 55 89 E5 8B 45 08 EB 00 89 45 EC 8D 15 4F 10 40 00 8D 05 08 10 40 00 83 E8 08 29 C2 8B 45 EC 01 C2 31 }
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_PurpleWave {
     meta:
      author = "ditekSHen"
      description = "PurpleWave infostealer payload"
    strings:
      $s1 = "/loader/" fullword ascii
      $s2 = "\\load_" fullword wide
      $s3 = "boundaryaswell" fullword ascii
      $s4 = "[passwords]" ascii
      $s5 = "[is_encrypted]" ascii
      $s6 = "[cookies]" ascii
      $s7 = ".?AVMozillaBrowser@@" fullword ascii
      $s8 = ".?AVChromeBrowser@@" fullword ascii
      $s9 = ".?AV?$money" ascii
      $s10 = "at t.me/LuckyStoreSupport" ascii
   condition:
      uint16(0) == 0x5a4d and 7 of them
}

rule MALWARE_Java_Pyrogenic {
    meta:
      author = "ditekSHen"
      description = "Pyrogenic/Qealler infostealer payload"
    strings:
      $s1 = "bbb6fec5ebef0d93" ascii wide
      $s2 = "2a898bc98aaf6c96f2054bb1eadc9848eb77633039e9e9ffd833184ce553fe9b" ascii wide
      $s3 = "addShutdownHook" ascii wide
      $s4 = "obfuscated/META-INF/QeallerV" ascii wide
      $s5 = "globalIpAddress" ascii wide
    condition:
      all of them
}

rule MALWARE_Win_AgentTeslaV3 {
    meta:
      author = "ditekSHen"
      description = "AgentTeslaV3 infostealer payload"
    strings:
      $s1 = "get_kbok" fullword ascii
      $s2 = "get_CHoo" fullword ascii
      $s3 = "set_passwordIsSet" fullword ascii
      $s4 = "get_enableLog" fullword ascii
      $s5 = "bot%telegramapi%" wide
      $s6 = "KillTorProcess" fullword ascii 
      $s7 = "GetMozilla" ascii
      $s8 = "torbrowser" wide
      $s9 = "%chatid%" wide
      $s10 = "logins" fullword wide
      $s11 = "credential" fullword wide
      $s12 = "AccountConfiguration+" wide
      $s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide

      $g1 = "get_Clipboard" fullword ascii
      $g2 = "get_Keyboard" fullword ascii
      $g3 = "get_Password" fullword ascii
      $g4 = "get_CtrlKeyDown" fullword ascii
      $g5 = "get_ShiftKeyDown" fullword ascii
      $g6 = "get_AltKeyDown" fullword ascii

      $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
      $m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
      $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
      $m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
      $m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii
    condition:
      (uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($*) and all of ($g*)))) or (2 of ($m*))
}

rule MALWARE_Win_Taurus {
    meta:
      author = "ditekSHen"
      description = "Taurus infostealer payload"
    strings:
      $s1 = "t.me/taurus_se" ascii
      $s2 = "rus_seller@explo" ascii
      $s3 = "/c timeout /t 3  & del /f /q" ascii
      $s4 = "MyAwesomePrefix" ascii
      $txt1 = "LogInfo.txt" fullword ascii
      $txt2 = "Information.txt" fullword ascii
      $txt3 = "General\\passwords.txt" fullword ascii
      $txt4 = "General\\forms.txt" fullword ascii
      $txt5 = "General\\cards.txt" fullword ascii
      $txt6 = "Installed Software.txt" fullword ascii
      $txt7 = "Crypto Wallets\\WalletInfo.txt" fullword ascii
      $txt8 = "cookies.txt" fullword ascii
      $url1 = "/cfg/" wide
      $url2 = "/loader/complete/" wide
      $url3 = "/log/" wide
      $url4 = "/dlls/" wide
      $upat = /\.exe;;;\d;\d;\d\]\|\[http/
      
      $x1 = "Vaultcli.dll" fullword ascii
      $x2 = "Bcrypt.dll" fullword ascii
      $x3 = "*.localstor" ascii
      $x4 = "operator<=>" fullword ascii
      $x5 = ".data$rs" fullword ascii
      $x6 = "https_discordap" ascii
      $o1 = { 53 56 8b 75 08 8d 85 64 ff ff ff 57 6a ff 6a 01 }
      $o2 = { 6a 00 68 00 04 00 00 ff b5 a8 fe ff ff ff b5 ac }
      $o3 = { ff 75 0c 8d 85 44 ff ff ff 50 e8 aa f7 ff ff 8b }
      $o4 = { 8b 47 04 c6 40 19 01 8d 85 6c ff ff ff 8b 0f 50 }
      $o5 = { 8d 8d ?? ff ff ff e8 5b }
    condition:
      ((3 of ($s*) or (6 of ($txt*) and 2 of ($s*)) or ($upat and 1 of ($s*) and 2 of ($txt*)) or (all of ($url*) and (2 of ($txt*) or 1 of ($s*)))) or (uint16(0) == 0x5a4d and all of ($x*) or (all of ($o*) and 3 of ($x*))))
}

rule MALWARE_Win_RemoteUtilitiesRAT {
    meta:
      author = "ditekSHen"
      description = "RemoteUtilitiesRAT RAT payload"
      clamav_sig = "MALWARE.Win.Trojan.RemoteUtilitiesRAT"
    strings:
      $s1 = "rman_message" wide
      $s2 = "rms_invitation" wide
      $s3 = "rms_host_" wide
      $s4 = "rman_av_capture_settings" wide
      $s5 = "rman_registry_key" wide
      $s6 = "rms_system_information" wide
      $s7 = "_rms_log.txt" wide
      $s8 = "rms_internet_id_settings" wide
    condition:
      uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_SlothfulMedia {
     meta:
      author = "ditekSHen"
      description = "SlothfulMedia backdoor payload"
    strings:
      $x1 = /ExtKeylogger(Start|Stop)/ fullword ascii
      $x2 = /ExtService(Add|Delete|Start|Stop)/ fullword ascii
      $x3 = /ExtRegKey(Add|Del)/ fullword ascii
      $x4 = /ExtRegItem(Add|Del)/ fullword ascii
      $x5 = "ExtUnload" fullword ascii

      $s1 = "Local Security Process" fullword wide
      $s2 = "Global%s%d" fullword wide
      $s3 = "%s%s_%d.dat" fullword wide
      $s4 = "\\AppIni" fullword wide
      $s5 = "%s.tmp" fullword wide
      $s6  = "\\SetupUi" fullword wide
      $s7 = "%s|%s|%s|%s" fullword wide
      $s8 = "\\ExtInfo" fullword wide

      $cnc1 = "/v?m=" fullword ascii
      $cnc2 = "%s&i=%d" fullword ascii
      $cnc3 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75" fullword ascii
      $cnc4 = "Content-Length: %d" fullword ascii
    condition:
      uint16(0) == 0x5a4d and (3 of ($x*) or 7 of ($s*) or all of ($cnc*) or (1 of ($x*) and 4 of ($s*)))
}

rule MALWARE_Win_IRCBot {
    meta:
      author = "ditekSHen"
      description = "IRCBot payload"
    strings:
        $s1 = ".okuninstall" fullword wide
        $s2 = ".oksnapshot" fullword wide
        $s3 = "\\uspread.vbs" fullword wide
        $s4 = "KEYLogger" ascii nocase
        $s5 = "GetKeyLogs" fullword ascii
        $s6 = "GetLoocationInfo" fullword ascii
        $s7 = "CaputerScreenshot" fullword ascii
        $s8 = "get_SCRIPT_DATA" fullword ascii
        $s9 = /irc_(server|nickname|password|channle)/ fullword ascii
        $s10 = "machine_screenshot" fullword ascii
        $s11 = "CollectPassword" fullword ascii
        $s12 = "USBInfection" fullword ascii nocase

        $cnc1 = "&command=UpdateAndGetTasks&machine_id=" wide
        $cnc2 = "&machine_os=1&privateip=" wide
        $cnc3 = "&command=InsertTaskExecution&excuter_id=" wide
        $cnc4 = "&command=RegisterNewMachine" wide
        $cnc5 = "&command=UpdateNewMachine" wide
        $cnc6 = "&command=GetPayloads&keys=" wide
        $cnc7 = "&command=SaveSnapshot" wide

        $pdb = "\\Projects\\USBStarter\\USBStarter\\obj\\Release\\USBStarter.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or 3 of ($cnc*) or ($pdb and 2 of them))
}

rule MALWARE_Win_Apocalypse {
    meta:
      author = "ditekSHen"
      description = "Apocalypse infostealer payload"
    strings:
        $s1 = "OpenClipboard" fullword ascii
        $s2 = "SendARP" fullword ascii
        $s3 = "GetWebRequest" fullword ascii
        $s4 = "DotNetGuard" fullword ascii
        $s5 = "set_CreateNoWindow" fullword ascii
        $s6 = "UploadFile" fullword ascii
        $s7 = "GetHINSTANCE" fullword ascii
        $s8 = "Kill" fullword ascii
        $s9 = "GetProcesses" fullword ascii
        $s10 = "get_PrimaryScreen" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Osno {
    meta:
      author = "ditekSHen"
      description = "Osno ransomware and infostealer payload"
    strings:
        $s1 = ".HolyGate+<>c+<<FinalBoss>" ascii
        $s2 = /Osno(Keylogger|Stealer|Ransom)/ wide
        $s3 = "password,executeWebhook('Account credentials" wide
        $s4 = "-Name Osno -PropertyType" wide
        $s5 = "process.env.hook" ascii
        $s6 = "Stealer.JSON.JsonValue" ascii
        $s7 = "<DetectBrowserss>b_" ascii
        $s8 = "<TryGetDiscordPath>b_" ascii
        $s9 = "antiVM" fullword ascii
        $s10 = "downloadurl" fullword ascii
        $s11 = "set_sPassword" fullword ascii
        
        $txt0 = "{0} {1} .txt" fullword wide
        $txt1 = "\\ScanningNetworks.txt" fullword wide
        $txt2 = "\\SteamApps.txt" fullword wide
        $txt3 = "-ErrorsLogs.txt" fullword wide
        $txt4 = "-keylogs.txt" fullword wide
        $txt5 = "Hardware & Soft.txt" fullword wide

        $cnc0 = "/csharp/" ascii wide
        $cnc1 = "token=" ascii wide
        $cnc2 = "&timestamp=" ascii wide
        $cnc3 = "&session_id=" ascii wide
        $cnc4 = "&aid=" ascii wide
        $cnc5 = "&secret=" ascii wide
        $cnc6 = "&api_key" ascii wide
        $cnc7 = "&session_key=" ascii wide
        $cnc8 = "&type=" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (6 of ($s*) or 4 of ($txt*) or (4 of ($s*) and 2 of ($txt*)))) or (7 of ($cnc*))
}

rule MALWARE_Win_BetaBot {
    meta:
        author = "ditekSHen"
        description = "BetaBot payload"
    strings:
        $s1 = "__restart" fullword ascii
        $s2 = "%SystemRoot%\\SysWOW64\\tapi3.dll" fullword wide
        $s3 = "%SystemRoot%\\system32\\tapi3.dll" fullword wide
        $s4 = "publicKeyToken=\"6595b64144ccf1df\"" ascii
        $s5 = "VirtualProtectEx" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 600KB and  all of them
}

rule MALWARE_Win_WSHRAT {
    meta:
        author = "ditekSHen"
        description = "WSHRAT keylogger plugin payload"
        snort_sid = "920010-920012"
        clamav_sig = "MALWARE.Win.Trojan.WSHRAT-KLG"
    strings:
        $s1 = "GET /open-keylogger HTTP/1.1" fullword wide
        $s2 = "KeyboardChange: nCode={0}, wParam={1}, vkCode={2}, scanCode={3}, flags={4}, dwExtraInfo={6}" wide
        $s3 = "MouseChange: nCode={0}, wParam={1}, x={2}, y={3}, mouseData={4}, flags={5}, dwExtraInfo={7}" wide
        $s4 = "sendKeyLog" fullword ascii
        $s5 = "saveKeyLog" fullword ascii
        $s6 = "get_TotalKeyboardClick" fullword ascii
        $s7 = "get_SessionMouseClick" fullword ascii
        $pdb = "\\Android\\documents\\visual studio 2010\\Projects\\Keylogger\\Keylogger\\obj\\x86\\Debug\\Keylogger.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule MALWARE_Win_RevengeRAT {
    meta:
        author = "ditekSHen"
        description = "RevengeRAT and variants payload"
        snort_sid = "920000-920002"
    strings:
        $l1 = "Lime.Connection" fullword ascii
        $l2 = "Lime.Packets" fullword ascii
        $l3 = "Lime.Settings" fullword ascii
        $l4 = "Lime.NativeMethods" fullword ascii

        $s1 = "GetAV" fullword ascii
        $s2 = "keepAlivePing!" fullword ascii wide
        $s3 = "Revenge-RAT" fullword ascii wide
        $s4 = "*-]NK[-*" fullword ascii wide
        $s5 = "RV_MUTEX" fullword ascii wide
        $s6 = "set_SendBufferSize" fullword ascii
        $s7 = "03C7F4E8FB359AEC0EEF0814B66A704FC43FB3A8" fullword ascii
        $s8 = "5B1EE7CAD3DFF220A95D1D6B91435D9E1520AC41" fullword ascii
        $s9 = "\\RevengeRAT\\" ascii

        $q1 = "Select * from AntiVirusProduct" fullword ascii wide
        $q2 = "SELECT * FROM FirewallProduct" fullword ascii wide
        $q3 = "select * from Win32_Processor" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($l*) and 3 of ($s*)) or (all of ($q*) and 3 of ($s*)) or 3 of ($s*))
}

rule MALWARE_Win_TRAT {
    meta:
        author = "ditekSHen"
        description = "TRAT payload"
        clamav_sig = "MALWARE.Win.Trojan.TRAT"
    strings:
        $s1 = "^STEAM_0:[0-1]:([0-9]{1,10})$" fullword wide
        $s2 = "^7656119([0-9]{10})$" fullword wide
        $s3 = "Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)" ascii
        $s4 = "\"schtasks\", \"/delete /tn UpdateWindows /f\");" ascii
        $s5 = "ProcessWindowStyle.Hidden" ascii
        $s6 = "+<>c+<<ListCommands>" ascii
        $s7 = "//B //Nologo *Y" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_CryptBot {
    meta:
        author = "ditekSHen"
        description = "CryptBot/Fugrafa stealer payload"
        snort2_sid = "920110"
        snort3_sid = "920108"
        clamav_sig = "MALWARE.Win.Trojan.CryptBot"
    strings:
        $s1 = "Username: %wS" fullword wide
        $s2 = "Computername: %wS" fullword wide
        $s3 = "/c rd /s /q %" wide
        $s4 = "IP: N0t_IP" fullword wide
        $s5 = "Country: N0t_Country" fullword wide
        $s6 = "password-check" fullword ascii
        $s7 = "Content-Disposition: form-data; name=\"file\"; filename=\"" ascii wide
        $s8 = "[ %wS ]" wide
        $s9 = "EXE_PATH:" wide
        $s10 = "Username (Computername):" wide
        $s11 = "Operating system language:" wide
        $s12 = "/index.php" wide
        $f1 = "*ledger*.txt" fullword wide
        $f2 = "*crypto*.xlsx" fullword wide
        $f3 = "*private*.txt" fullword wide
        $f4 = "*wallet*.dat" fullword wide
        $f5 = "*pass*.txt" fullword wide
        $f6 = "*bitcoin*.txt" fullword wide
        $p1 = "%USERPROFILE%\\Desktop\\*.txt" fullword wide
        $p2 = "%USERPROFILE%\\Desktop\\secret.txt" fullword wide 
        $p3 = "%USERPROFILE%\\Desktop\\report.doc" fullword wide
        $pattern1 = /(files_|_Files)\\(_?)(cookies|cryptocurrency|forms|passwords|system_info|screenshot|screen_desktop|information|files|wallet|cc|Coinomi)\\?(\.txt|\.jpg|\.jpeg)?/ ascii wide nocase
        $pattern2 = /%(s|ws)\\%(s|ws)\\(Login Data|Cookies|Web Data)/ fullword wide
        $pattern3 = /(_AllPasswords_list.txt|_AllForms_list.txt|_AllCookies_list.txt|_All_CC_list.txt|_Information.txt|_Info.txt|_Screen_Desktop.jpeg)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and ((5 of ($s*) and 1 of ($p*)) or (4 of ($s*) and 1 of ($f*) and 1 of ($p*)) or (2 of ($pattern*) and 3 of ($s*)) or (#pattern1 > 6 and (2 of ($s*) or 1 of ($p*))))
}

rule MALWARE_Win_Matiex {
    meta:
        author = "ditekSHen"
        description = "Matiex/XetimaLogger keylogger payload"
        clamav_sig = "MALWARE.Win.Trojan.MatiexKeylogger"
    strings:
      $id = "--M-A-T-I-E-X--K-E-Y-L-O-G-E-R--" ascii wide

      $s1 = "StartKeylogger" fullword ascii
      $s2 = "_KeyboardLoggerTimer" ascii
      $s3 = "_ScreenshotLoggerTimer" ascii
      $s4 = "_VoiceRecordLogger" ascii
      $s5 = "_ClipboardLoggerTimer" ascii
      $s6 = "get_logins" fullword ascii
      $s7 = "get_processhackerFucked" fullword ascii
      $s8 = "_ThePSWDSenders" fullword ascii

      $pdb = "\\Before FprmT\\Document VB project\\FireFox Stub\\FireFox Stub\\obj\\Debug\\VNXT.pdb" ascii
    condition:
      uint16(0) == 0x5a4d and ($id or 4 of ($s*) or ($pdb and 2 of them))
}

rule MALWARE_Win_IAmTheKingKeylogger {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing Keylogger payload"
        clamav_sig = "MALWARE.Win.Trojan.IAmTheKingKeylogger"
    strings:
        $s1 = "[TIME:]%d/%d/%d %02d:%02d:%02d" fullword ascii
        $s2 = "[TITLE:]" fullword ascii
        $s3 = "%s-%02d-%02d-%02d-%02d" fullword ascii
        $s4 = "[DATA]:" fullword ascii
        $s5 = "[BK]" fullword ascii
        $s6 = "Log.txt" fullword ascii
        $s7 = "sonme hting is wrong x" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_IAmTheKingScrCap {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing screen capture payload"
    strings:
        $s1 = "@MyScreen.jpg" fullword wide
        $s2 = "DISPLAY" fullword wide
        $s3 = ".?AVCImage@ATL@@" fullword ascii
        $s4 = ".?AVGdiplusBase@Gdiplus@@" fullword ascii
        $s5 = ".?AVImage@Gdiplus@@" fullword ascii
        $s6 = ".?AVBitmap@Gdiplus@@" fullword ascii
        $s7 = ".?AVCAtlException@ATL@@" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_IAmTheKingKingOfHearts {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing King Of Hearts payload"
    strings:
        $s1 = "write info fail!!! GetLastError-->%u" fullword ascii
        $s2 = "LookupAccountSid Error %u" fullword ascii
        $s3 = "CreateServiceErrorID:%d" fullword ascii
        $s4 = "In ControlServiceErrorID:%d" fullword ascii
        $s5 = "In QueryServiceStatus ErrorID:%d" fullword ascii
        $s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii
        $s7 = "hello%s" fullword ascii
        $s8 = "additional header failed..." fullword ascii
        $s9 = "Set Option failed errcode: %ld" fullword ascii
        $s10 = "add cookie failed..." fullword ascii

        $u1 = "Mozilla/4.0 (compatible; )" fullword ascii
        $u2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SE)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($u*) and 4 of ($s*)) or (all of ($u*) and 3 of ($s*)) or (5 of them))
}

rule MALWARE_Win_CobaltStrike {
    meta:
        author = "ditekSHen"
        description = "CobaltStrike payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii

        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)) 
}

rule MALWARE_Win_RedLineDropperAHK {
    meta:
        author = "ditekSHen"
        description = "Detects AutoIt/AutoHotKey executables dropping RedLine infostealer"
        clamav_sig = "MALWARE.Win.Trojan.RedLineDropper-AHK"
    strings:
        $s1 = ".SetRequestHeader(\"User-Agent\",\" ( \" OSName \" | \" bit \" | \" CPUNAme \"\"" ascii
        $s2 = ":= \" | Windows Defender\"" ascii
        $s3 = "WindowSpy.ahk" wide
        $s4 = ">AUTOHOTKEY SCRIPT<" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_DLAgent01 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent"
      snort_sid = "920007"
      clamav_sig = "MALWARE.Win.Trojan.DLAgent01"
    strings:
        $s1 = "Mozilla/5.0 Gecko/41.0 Firefox/41.0" fullword wide
        $s2 = "/Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List" fullword wide
        $s3 = "GUID.log" fullword wide
        $s4 = "NO AV" fullword wide
        $s5 = "%d:%I64d:%I64d:%I64d" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Linux_PLEAD {
    meta:
        author = "ditekSHen"
        description = "PLEAD Linux payload"
        clamav_sig = "MALWARE.Linux.Trojan.PLEAD"
    strings:
        $x1 = "CFileTransfer" ascii
        $x2 = "CFileManager" ascii
        $x3 = "CPortForward" ascii
        $x4 = "CPortForwardManager" ascii
        $x5 = "CRemoteShell" ascii
        $x6 = "CSockClient" ascii

        $s1 = "/proc/self/exe" fullword ascii
        $s2 = "/bin/sh" fullword ascii
        $s3 = "echo -e '" ascii
        $s4 = "%s    <DIR>    %s" ascii
        $s5 = "%s    %lld    %s" ascii
        $s6 = "Files: %d        Size: %lld" ascii
        $s7 = "Dirs: %d" ascii
        $s8 = "%s(%s)/" ascii
        $s9 = "%s %s %s %s" ascii
    condition:
    uint16(0) == 0x457f and (all of ($x*) or all of ($s*) or 12 of them)
}

rule MALWARE_Win_CRAT {
    meta:
        author = "ditekSHen"
        description = "Detects CRAT main DLL"
    strings:
        $s1 = "cmd /c \"dir %s /s >> %s\"" wide
        $s2 = "Set-Cookie:\\b*{.+?}\\n" wide
        $s3 = "Location: {[0-9]+}" wide
        $s4 = "Content-Disposition: form-data; name=\"%s\"; filename=\"" ascii
        $s6 = "%serror.log" wide
        $v2x_1 = "?timestamp=%u" wide
        $v2x_2 = "config.txt" wide
        $v2x_3 = "entdll.dll" wide
        $v2x_4 = "\\cmd.exe" wide
        $v2x_5 = "[MyDocuments]" wide
        $v2x_6 = "@SetWindowTextW FindFileExA" wide
        $v2x_7 = "Microsoft\\Windows\\WinX\\Group1\\*.exe" wide
        $v2s_1 = "Installed Anti Virus Programs" ascii
        $v2s_2 = "Running Processes" ascii
        $v2s_3 = "id=%u&content=" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 6 of ($v2x*) or all of ($v2s*) or (2 of ($v2s*) and 4 of ($v2x*)))
}

rule MALWARE_Win_CRATPluginKeylogger {
    meta:
        author = "ditekSHen"
        description = "Detects CRAT keylogger plugin DLL"
        clamav_sig = "MALWARE.Win.Trojan.CRAT"
    strings:
        $ai1 = "VM detected!" fullword wide
        $ai2 = "Sandbox detected!" fullword wide
        $ai3 = "Debug detected!" fullword wide
        $ai4 = "Analysis process detected!" fullword wide
        $s1 = "Create KeyLogMutex %s failure %d" wide
        $s2 = "Key Log Mutex already created! %s" wide
        $s3 = /KeyLogThread\s(started|finished|terminated)!/ wide
        $s4 = /KeyLog_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 5 of them)
}

rule MALWARE_Win_CRATPluginClipboardMonitor {
    meta:
        author = "ditekSHen"
        description = "Detects CRAT Clipboad Monitor plugin DLL"
    strings:
        $ai1 = "VM detected!" fullword wide
        $ai2 = "Sandbox detected!" fullword wide
        $ai3 = "Debug detected!" fullword wide
        $ai4 = "Analysis process detected!" fullword wide
        $s1 = "Clipboard Monitor Mutex [%s] already created!" wide
        $s2 = "ClipboardMonitorThread started!" fullword wide
        $s3 = /MonitorClipboardThread\s(finished|terminated)!/ wide
        $s4 = /ClipboardMonitor_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 5 of them)
}

rule MALWARE_Win_CRATPluginScreenCapture {
    meta:
        author = "ditekSHen"
        description = "Detects CRAT Screen Capture plugin DLL"
    strings:
        $ai1 = "VM detected!" fullword wide
        $ai2 = "Sandbox detected!" fullword wide
        $ai3 = "Debug detected!" fullword wide
        $ai4 = "Analysis process detected!" fullword wide
        $s1 = "User is inactive!, give up capture" wide
        $s2 = "Capturing screen..." wide
        $s3 = "%s\\P%02d%lu.tmp" fullword wide
        $s4 = "CloseHandle ScreenCaptureMutex failure! %d" fullword wide
        $s5 = "ScreenCaptureMutex already created! %s" fullword wide
        $s6 = "Create ScreenCaptureMutex %s failure %d" fullword wide
        $s7 = /ScreenCaptureThread\s(finished|terminated)!/ wide
        $s8 = /ScreenCapture_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 6 of them)
}

rule MALWARE_Win_CRATPluginRansomHansom {
    meta:
        author = "ditekSHen"
        description = "Detects CRAT Hansom Ransomware plugin DLL"
    strings:
        $cmd1 = "/f /im \"%s\"" wide
        $cmd2 = "add HKLM\\%s /v %s /t REG_DWORD /d %d /F" wide
        $cmd3 = "add HKCU\\%s /v %s /t REG_DWORD /d %d /F" wide
        $cmd4 = "\"%s\" a -y -ep -k -r -s -ibck -df -m0 -hp%s -ri1:%d \"%s\" \"%s\"" wide
        $s1 = "\\hansom.jpg" wide
        $s2 = "HansomMain" fullword ascii wide
        $s3 = "ExtractHansom" fullword ascii wide
        $s4 = "Hansom2008" fullword ascii
        $s5 = ".hansomkey" fullword wide
        $s6 = ".hansom" fullword wide
        $s7 = /Ransom_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($cmd*) and 2 of ($s*)) or (4 of ($s*) and 1 of ($cmd*)) or 6 of them)
}

rule MALWARE_Win_AlienCrypter {
    meta:
        author = "ditekSHen"
        description = "Detects AlienCrypter injector/downloader/obfuscator"
    strings:
        $s1 = ".AlienRunPE." ascii wide
        $s2 = "RunAsNewUser_RunDLL" fullword wide
        $s3 = { 00 50 52 4f 43 45 53 53 5f 53 55 53 50 45 4e 44 5f 52 45 53 55 4d 45 00 64 6e 6c 69 62 2e 50 45 00 }
        $s4 = { 2e 41 6c 69 65 6e 52 75 6e 50 45 00 50 52 4f 43 45 53 53 5f 54 45 52 4d 49 4e 41 54 45 00 }
        $s5 = "@@@http" wide
        $resp1 = "</p><p>@@@77,90," ascii wide
        $resp2 = "</p><p>@@@HH,JA," ascii wide
    condition:
        (uint16(0) == 0x5a4d and 3 of them) or (1 of ($resp*) and 2 of ($s*))
}

rule MALWARE_Win_Ficker {
    meta:
        author = "ditekSHen"
        description = "Detects Ficker infostealer"
        clamav_sig = "MALWARE.Win.Trojan.Ficker"
    strings:
        $s1 = "JNOde\\" ascii
        $s2 = "\"SomeNone" fullword ascii
        $s3 = "kindmessage" fullword ascii
        $s4 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writting non-UTF-8 byte sequences" ascii
        $s5 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii
        $s6 = "(os error other os erroroperation interrruptedwrite zerotimed" ascii
        $s7 = "(os error other os erroroperation interruptedwrite zerotimed" ascii
        $s8 = "nPipeAlreadyExistsWouldBlockInvalidInputInvalidDataTimedOutWriteZeroInterruptedOtherN" fullword ascii
        $s9 = "_matherr(): %s in %s(%g, %g)  (retval=%g)" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_Xorist {
     meta:
        author = "ditekSHen"
        description = "Detects Xorist ransomware"
        clamav_sig = "MALWARE.Win.Ransomware.Xorist"
    strings:
        $x1 = { 00 4d 00 41 00 47 00 45 00 0b 00 50 00 55 00 
                53 00 53 00 59 00 4c 00 49 00 43 00 4b 00 45
                00 52 00 }
        $x2 = { 30 70 33 6e 53 4f 75 72 63 33 20 58 30 72 31 35
                37 2c 20 6d 6f 74 68 65 72 66 75 63 6b 65 72 21
                00 70 75 73 73 79 6c 69 63 6b 65 72 00 2e 62 6d
                70 00 2e 00 2e 2e 00 6f 70 65 6e 00 2e 65 78 65 }
        $s1 = "\\shell\\open\\command" fullword ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $s3 = "CRYPTED!" fullword ascii
        $s4 = "Attention!" fullword ascii
        $s5 = "Password:" fullword ascii
        $s6 = { 43 6f 6d 53 70 65 63 00 2f 63 20 64 65 6c 20 22 00 22 20 3e 3e 20 4e 55 4c }
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 5 of ($s*) or (1 of ($x*) and 3 of ($s*)))
}

rule MALWARE_Win_PYSA {
     meta:
        author = "ditekSHen"
        description = "Detects PYSA/Mespinoza ransomware"
        clamav_sig = "MALWARE.Win.Ransomware.PYSA"
    strings:
        $s1 = "%s\\Readme.README" fullword wide
        $s2 = "Every byte on any types of your devices was encrypted" ascii
        $s3 = { 6c 65 67 61 6c 6e 6f 74 69 63 65 74 65 78 74 00 (50|70) (59|79) (53|73) (41|61) }
        $s4 = { 6c 65 67 61 6c 6e 6f 74 69 63 65 63 61 70 74 69 6f 6e 00 00 (50|70) (59|79) (53|73) (41|61) }
        $s5 = { 2e 62 61 74 00 00 6f 70 65 6e 00 00 00 00 53
                4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f
                66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72
                65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69
                63 69 65 73 5c 53 79 73 74 65 6d 00 00 00 }
        $f1 = ".?AVPK_EncryptorFilter@CryptoPP@@" ascii
        $f2 = ".?AV?$TF_EncryptorImpl@" ascii
        $f3 = "@VTF_EncryptorBase@CryptoPP@@" ascii
    condition:
        uint16(0) == 0x5a4d and all of ($f*) and 3 of ($s*)
}

rule MALWARE_Win_Polar {
    meta:
        author = "ditekSHen"
        description = "Detects Polar ransomware"
        clamav_sig = "MALWARE.Win.Ransomware.Polar"
    strings:
        $s1 = "Encrypt Failed ! ErrorMessage :" wide
        $s2 = ".locked" fullword wide
        $s3 = ".cryptd" fullword wide
        $s4 = "$SysReset" fullword wide
        $s5 = "Polar.Properties.Resources" ascii wide
        $s6 = "AES_EnDecryptor.Basement" fullword ascii
        $s7 = "RunCMDCommand" fullword ascii
        $s8 = "killerps_list" fullword ascii
        $s9 = "clearlog" fullword ascii
        $s10 = "encryptFile" fullword ascii
        $s11 = "changeBackPictrue" fullword ascii
        $pdb1 = "\\Ransomware_ALL_encode\\dir_file\\obj\\x86\\Release\\Encode.pdb" ascii
        $pdb2 = "\\Ransomware_ALL_encode\\dir_file\\obj\\x64\\Release\\Encode.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (8 of ($s*) or (1 of ($pdb*) and 2 of ($s*)))
}

rule MALWARE_Win_BitRAT {
    meta:
        author = "ditekSHen"
        description = "Detects BitRAT RAT"
        clamav_sig = "MALWARE.Win.Trojan.BitRAT"
    strings:
        $s1 = "\\plg\\" fullword ascii
        $s2 = "klgoff_del" fullword ascii
        $s3 = "files_delete" ascii
        $s4 = "files_zip_start" fullword ascii
        $s5 = "files_exec" fullword ascii
        $s6 = "drives_get" fullword ascii
        $s7 = "srv_list" fullword ascii
        $s8 = "con_list" fullword ascii
        $s9 = "ddos_stop" fullword ascii
        $s10 = "socks5_srv_start" fullword ascii
        $s11 = "/getUpdates?offset=" fullword ascii
        $s12 = "Action: /dlex" fullword ascii
        $s13 = "Action: /clsbrw" fullword ascii
        $s14 = "Action: /usb" fullword ascii
        $s15 = "/klg" fullword ascii
        $s16 = "klg|" fullword ascii
        $s17 = "Slowloris" fullword ascii
        $s18 = "Bot ID:" ascii
        $t1 = "<sz>N/A</sz>" fullword ascii
        $t2 = "<silent>N/A</silent>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (4 of ($s*) and 1 of ($t*)))
}

rule MALWARE_Win_Poullight {
    meta:
        author = "ditekSHen"
        description = "Detects Poullight infostealer"
        snort2_sid = "920074-920075"
        snort3_sid = "920074-920075"
        clamav_sig = "MALWARE.Win.Trojan.Poullight"
    strings:
        $s1 = "zipx" fullword wide
        $s2 = "{0}Windows Defender.exe" fullword wide
        $s3 = "pll_test" fullword wide
        $s4 = "loginusers.vdf" wide
        $s5 = "Stealer by Nixscare" wide
        $s6 = "path_lad" fullword ascii
        $s7 = "<CheckVM>" ascii
        $s8 = "Poullight.Properties" ascii
        $s9 = "</ulfile>" fullword wide
        $s10 = "{0}processlist.txt" fullword wide
        $s11 = "{0}Browsers\\Passwords.txt" fullword wide
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule MALWARE_Win_SnakeKeylogger {
    meta:
        author = "ditekSHen"
        description = "Detects Snake Keylogger"
        clamav_sig = "MALWARE.Win.Trojan.SnakeKeylogger"
    strings:
        $id1 = "SNAKE-KEYLOGGER" fullword ascii
        $id2 = "----------------S--------N--------A--------K--------E----------------" ascii
        $s1 = "_KPPlogS" fullword ascii
        $s2 = "_Scrlogtimerrr" fullword ascii
        $s3 = "_Clpreptimerr" fullword ascii
        $s4 = "_clprEPs" fullword ascii
        $s5 = "_kLLTIm" fullword ascii
        $s6 = "_TPSSends" fullword ascii
        $s7 = "_ProHfutimer" fullword ascii
        $s8 = "GrabbedClp" fullword ascii
        $s9 = "StartKeylogger" fullword ascii
        // Snake Keylogger Stub New
        $x1 = "$%SMTPDV$" wide
        $x2 = "$#TheHashHere%&" wide
        $x3 = "%FTPDV$" wide
        $x4 = "$%TelegramDv$" wide
        $x5 = "KeyLoggerEventArgs" ascii
        $m1 = "| Snake Keylogger" ascii wide
        $m2 = /(Screenshot|Clipboard|keystroke) Logs ID/ ascii wide
        $m3 = "SnakePW" ascii wide
        $m4 = "\\SnakeKeylogger\\" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (all of ($id*) or 6 of ($s*) or (1 of ($id*) and 3 of ($s*)) or 4 of ($x*))) or (2 of ($m*))
}

rule MALWARE_Linux_XORDDoS {
    meta:
        author = "ditekSHen"
        description = "Detects XORDDoS"
    strings:
        $s1 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done" fullword ascii
        $s2 = "cp /lib/libudev.so /lib/libudev.so.6" fullword ascii
        $s3 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii
        $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii
    condition:
      uint32(0) == 0x464c457f and 3 of them
}

rule MALWARE_Win_BlackNET {
    meta:
        author = "ditekSHen"
        description = "Detects BlackNET RAT"
        snort2_sid = "920079-920082"
        snort3_sid = "920079-920082"
        clamav_sig = "MALWARE.Win.Trojan.BlackNET"
    strings:
        $s1 = "SbieCtrl" fullword wide
        $s2 = "SpyTheSpy" fullword wide
        $s3 = "\\BlackNET.dat" fullword wide
        $s4 = "StartDDOS" fullword wide
        $s5 = "UDPAttack" fullword wide
        $s6 = "ARMEAttack" fullword wide
        $s7 = "TCPAttack" fullword wide
        $s8 = "HTTPGetAttack" fullword wide
        $s9 = "RetriveLogs" fullword wide
        $s10 = "StealPassword" fullword wide
        $s11 = "/create /f /sc ONSTART /RL HIGHEST /tn \"'" fullword wide
        $b1 = "DeleteScript|BN|" fullword wide
        $b2 = "|BN|Online" fullword wide
        $b3 = "NewLog|BN|" fullword wide
        $cnc1 = "/getCommand.php?id=" fullword wide
        $cnc2 = "/upload.php?id=" fullword wide
        $cnc3 = "connection.php?data=" fullword wide
        $cnc4 = "/receive.php?command=" fullword wide
    condition:
        uint16(0) == 0x5a4d and (9 of ($s*) or all of ($cnc*) or all of ($b*) or 12 of them)
}

rule MALWARE_Win_StormKitty {
    meta:
        author = "ditekSHen"
        description = "Detects StormKitty infostealer"
        clamav_sig = "MALWARE.Win.Trojan.StormKitty"
    strings:
        $x1 = "\\ARTIKA\\Videos\\Chrome-Password-Recovery" ascii
        $x2 = "https://github.com/LimerBoy/StormKitty" fullword ascii
        $x3 = "StormKitty" fullword ascii
        $s1 = "GetBSSID" fullword ascii
        $s2 = "GetAntivirus" fullword ascii
        $s3 = "C:\\Users\\Public\\credentials.txt" fullword wide
        $s4 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" fullword wide
        $s5 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide
        $s6 = "\"encrypted_key\":\"(.*?)\"" fullword wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 5 of ($s*) or (3 of ($s*) and 1 of ($x*)))
}

rule MALWARE_Win_Bulz01 {
    meta:
        author = "ditekSHen"
        description = "Detects trojan loader"
    strings:
        $s1 = "DisableTrivet.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and all of ($s*) and (
            pe.exports("Ordinal") or pe.exports("Chechako") or pe.exports("Originator") or pe.exports("Repressions")
        )
}

rule MALWARE_Win_RevCodeRAT {
    meta:
        author = "ditekSHen"
        description = "Detects RevCode/WebMonitor RAT"
        snort2_sid = "920070"
        snort3_sid = "920070"
        clamav_sig = "MALWARE.Win.Trojan.RevCodeRAT"
    strings:
        $x1 = "rev-novm.dat" fullword wide
        $x2 = "WebMonitor-" fullword wide
        $x3 = "WebMonitor Client" fullword wide
        $x4 = "Launch WebMonitor" fullword wide

        $s1 = "KEYLOG_DEL" fullword ascii
        $s2 = "KEYLOG_STREAM_START" fullword ascii
        $s3 = "send_keylog_del" fullword ascii
        $s4 = "send_keylog_stream_" ascii
        $s5 = "send_shell_exec" fullword ascii
        $s6 = "send_file_download_exec" fullword ascii
        $s7 = "send_pdg_exec" fullword ascii
        $s8 = "send_app_cmd_upd" fullword ascii
        $s9 = "send_webcamstream_start" fullword ascii
        $s10 = "send_screenstream_start" fullword ascii
        $s11 = "send_clipboard_get" fullword ascii
        $s12 = "send_pdg_rev_proxy_stop" fullword ascii
        $s13 = "send_shell_stop" fullword ascii
        $s14 = "send_wnd_cmd" fullword ascii
        $s15 = "SCREEN_STREAM_LEGACY(): Started..." fullword ascii
        $s16 = "SYSTEM_INFORMATION(): Failed! (Error:" fullword ascii
        $s17 = "TARGET_HOST_UPDATE(): Sync successful!" fullword ascii
        $s18 = "PLUGIN_PROCESS_REVERSE_PROXY: Plugin" ascii
        $s19 = "PLUGIN_PROCESS: Plugin" ascii
        $s20 = "PLUGIN_EXEC: Plugin" ascii
        $s21 = "PLUGIN_PROCESS_SCREEN_STREAM: Plugin" ascii

        $cnc1 = "?task_id=" fullword ascii
        $cnc2 = "&operation=" fullword ascii
        $cnc3 = "&filesize=" fullword ascii
        $cnc4 = "pos=" fullword ascii
        $cnc5 = "&mode=" fullword ascii
        $cnc6 = "&cmp=1" fullword ascii
        $cnc7 = "&cmp=0" fullword ascii
        $cnc8 = "&enc=1" fullword ascii
        $cnc9 = "&enc=0" fullword ascii
        $cnc10 = "&user=" fullword ascii
        $cnc11 = "&uid=" fullword ascii
        $cnc12 = "&key=" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or all of ($cnc*) or 8 of ($s*) or (1 of ($x*) and 6 of ($s*)) or (6 of ($cnc*) and 6 of ($s*)))
}

rule MALWARE_Win_PowerPool_STG1 {
    meta:
        author = "ditekSHen"
        description = "Detects first stage PowerPool backdoor"
        snort2_sid = "920088"
        snort3_sid = "920086"
        clamav_sig = "MALWARE.Win.Trojan.PowerPool-STG-1"
    strings:
        $s1 = "cmd /c powershell.exe $PSVersionTable.PSVersion > \"%s\"" fullword wide
        $s2 = "cmd /c powershell.exe \"%s\" > \"%s\"" fullword wide
        $s3 = "rar.exe a -r %s.rar -ta%04d%02d%02d%02d%02d%02d -tb%04d%02d%02d%02d%02d%02d" fullword wide
        $s4 = "MyDemonMutex%d" fullword wide
        $s5 = "MyScreen.jpg" fullword wide
        $s6 = "proxy.log" fullword wide
        $s7 = "myjt.exe" fullword wide
        $s8 = "/?id=%s&info=%s" fullword wide
        $s9 = "auto.cfg" fullword ascii
        $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64)" fullword wide
        $s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)" fullword wide
        $s12 = "CMD COMMAND EXCUTE ERROR!" fullword ascii
        $c1 = "run.afishaonline.eu" fullword wide
        $c2 = "home.Sports-Collectors.com" fullword wide
        $c3 = "about.Sports-Collectors.com" fullword
        $c4 = "179.43.158.15" fullword wide
        $c5 = "185.227.82.35" fullword wide        
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($c*) and 5 of ($s*)))
}

rule MALWARE_Win_PowerPool_STG2 {
    meta:
        author = "ditekSHen"
        description = "Detects second stage PowerPool backdoor"
        snort2_sid = "920089-920091"
        snort3_sid = "920087-920089"
        clamav_sig = "MALWARE.Win.Trojan.PowerPool-STG-2"
    strings:
        $s1 = "write info fail!!! GetLastError-->%u" fullword ascii
        $s2 = "LookupAccountSid Error %u" fullword ascii
        $s3 = "Mozilla/4.0 (compatible; )" fullword ascii
        $s4 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SE)" fullword ascii
        $s5 = "Content-Disposition: form-data; name=\"%s\"" fullword ascii
        $s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii
        $s7 = "Content-Type: multipart/form-data; boundary=--MULTI-PARTS-FORM-DATA-BOUNDARY" fullword ascii
        $s8 = "in Json::Value::find" fullword ascii
        $s9 = "in Json::Value::resolveReference" fullword ascii
        $s10 = "in Json::Value::duplicateAndPrefixStringValue" fullword ascii
        $s11 = ".?AVLogicError@Json@@" fullword ascii
        $s12 = ".?AVRuntimeError@Json@@" fullword ascii
        $s13 = "http:\\\\82.221.101.157:80" ascii
        $s14 = "http://172.223.112.130:80" ascii
        $s15 = "http://172.223.112.130:443" ascii
        $s16 = "http://info.newsrental.net:80" ascii
        $s17 = "%s|%I64d" ascii
        $s18 = "open internet failed..." ascii
        $s19 = "connect failed..." ascii
        $s20 = "handle not opened..." ascii
        $s21 = "corrupted regex pattern" fullword ascii
        $s22 = "add cookie failed..." ascii
    condition:
        uint16(0) == 0x5a4d and 14 of them
}

rule MALWARE_Win_Egregor {
    meta:
        author = "ditekSHen"
        description = "Detects Egregor ransomware variants"
        clamav_sig = "MALWARE.Win.Ransomware.Egregor"
    strings:
        $s1 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" fullword wide
        $p1 = "--deinstall" fullword wide
        $p2 = "--del" fullword wide
        $p3 = "--exit" fullword wide
        $p4 = "--kill" fullword wide
        $p5 = "--loud" fullword wide
        $p6 = "--nooperation" fullword wide
        $p7 = "--nop" fullword wide
        $p8 = "--skip" fullword wide
        $p9 = "--useless" fullword wide
        $p10 = "--yourmommy" fullword wide
        $p11 = "-passegregor" ascii wide
        $p12 = "-peguard" ascii wide
        $p13 = "--nomimikatz" ascii wide
        $p14 = "--multiproc" ascii wide
        $p15 = "--killrdp" ascii wide
        $p16 = "--nonet" ascii wide
        $p17 = "--norename" ascii wide
        $p18 = "--greetings" ascii wide
    condition:
        (uint16(0) == 0x5a4d and pe.is_dll() and ((all of ($s*) and 1 of ($p*)) or
                (
                    2 of them and filesize < 1000KB and 
                    for any i in (0 .. pe.number_of_sections) : (
                        (
                            pe.sections[i].name == ".00cfg"
                        )
                    )
                )
            )
        ) or 8 of ($p*)
}

rule MALWARE_Win_DLAgent02 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches from paste-like websites, most notably hastebin"
      clamav_sig = "MALWARE.Win.Trojan.DLAgent02"
    strings:
        $x1 = "/c timeout {0}" fullword wide
        $x2 = "^(https?|ftp):\\/\\/" fullword wide
        $x3 = "{0}{1}{2}{3}" wide
        $x4 = "timeout {0}" fullword wide
        $s1 = "HttpWebRequest" fullword ascii
        $s2 = "GetResponseStream" fullword ascii
        $s3 = "set_FileName" fullword ascii
        $s4 = "set_UseShellExecute" fullword ascii
        $s5 = "WebClient" fullword ascii
        $s6 = "set_CreateNoWindow" fullword ascii
        $s7 = "DownloadString" fullword ascii
        $s8 = "WriteByte" fullword ascii
        $s9 = "CreateUrlCacheEntryW" fullword ascii
        $s10 = "HttpStatusCode" fullword ascii
        $s11 = "FILETIME" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and ((2 of ($x*) and 2 of ($s*)) or (#x3 > 2 and 4 of ($s*)))
}

rule MALWARE_Win_RedLineDropperEXE {
    meta:
      author = "ditekSHen"
      description = "Detects executables dropping RedLine infostealer"
      clamav_sig = "MALWARE.Win.Trojan.RedLineDropper-EXE"
    strings:
        $s1 = "Wizutezinod togeto0Rowadufevomuki futenujilazem jic lefogatenezinor" fullword wide
        $s2 = "6Tatafamobevofaj bizafoju peyovavacoco lizine kezakajuj" fullword wide
        $s3 = "Lawuherusozeru kucu zam0Zorizeyuk lepaposupu gala kinarusot ruvasaxehuwo" fullword wide
        $s4 = "ClearEventLogW" fullword ascii
        $s5 = "ProductionVersion" fullword wide
        $s6 = "Vasuko)Yugenizugilobo toxocivoriye yexozoyohuzeb" wide
        $s7 = "Yikezevavuzus gucajanesan#Rolapucededoxu xewulep fuwehofiwifi" wide
    condition:
        uint16(0) == 0x5a4d and (pe.exports("_fgeek@8") and 2 of them) or 
        (
            2 of them and 
            for any i in (0 .. pe.number_of_sections) : (
                (
                    pe.sections[i].name == ".rig"
                )
            )
        )
}

rule MALWARE_Win_Nibiru {
    meta:
      author = "ditekSHen"
      description = "Detects Nibiru ransomware"
      clamav_sig = "MALWARE.Win.Ransomware.Nibiru"
    strings:
        $s1 = ".encrypt" fullword wide
        $s2 = "crypted" fullword wide
        $s3 = ".Nibiru" fullword wide
        $s4 = "Encryption Complete" fullword wide
        $s5 = "All your files,documents,important datas,mp4,mp3 and anything valuable" ascii
        $s6 = "EncryptOrDecryptFile" fullword ascii
        $s7 = "get_hacker" ascii
        $s8 = "/C choice /C Y /N /D Y /T 3 & Del \"" fullword wide
        $s9 = "Once You pay,you get the KEY to decrypt files" ascii
        $pdb = "\\Projects\\Nibiru\\Nibiru\\obj\\x86\\Release\\Nibiru.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of them or ($pdb and 2 of ($s*)))
}

rule MALWARE_Win_MedusaLocker {
    meta:
        author = "ditekshen"
        description = "Detects MedusaLocker ransomware"
        clamav_sig = "MALWARE.Win.Ransomware.MedusaLocker"
    strings:
        $x1 = "\\MedusaLockerInfo\\MedusaLockerProject\\MedusaLocker\\Release\\MedusaLocker.pdb" ascii
        $x2 = "SOFTWARE\\Medusa" wide
        $x3 = "=?utf-8?B?0RFQctTF0YDQcNC60IXQvdC+IEludGVybmV0IED4cGxvseVyIDEz?=" ascii
        $s1 = "Recovery_Instructions.mht" fullword wide
        $s2 = "README_LOCK.TXT" fullword wide
        $s3 = "C:\\Users\\Public\\Desktop" wide
        $s4 = "[LOCKER] " wide
        $s5 = "TmV3LUl0ZW0gJ2" ascii
        $s6 = "<HEAD>=20" ascii
        $s7 = "LIST OF ENCRYPTED FILES" ascii
        $s8 = "KEY.FILE" ascii
        $cmd1 = { 2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 00 00 20 00 3e 00 3e 00 20 00 4e 00 55 00 4c 00 }
        $cmd2 = "vssadmin.exe delete" wide nocase
        $cmd3 = "bcdedit.exe /set {default}" wide
        $cmd4 = "wbadmin delete systemstatebackup" wide nocase
        $mut1 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" fullword wide
        $mut2 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" fullword wide
        $mut3 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" fullword wide
        $ext1 = { 2e 00 52 00 65 00 61 00 64 00 49 00 6e 00 73 00 
                  74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00
                  73 00 00 00 00 00 00 00 2e 00 6b 00 65 00 76 00
                  65 00 72 00 73 00 65 00 6e }
        $ext2 = ".exe,.dll,.sys,.ini,.lnk,.rdp,.encrypted" fullword ascii
    condition:
      uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and (4 of ($s*) or 1 of ($mut*))) or 6 of ($s*) or (1 of ($mut*) and 2 of ($cmd*)) or (1 of ($ext*) and 5 of them))
}

rule MALWARE_Win_RansomEXX {
    meta:
        author = "ditekshen"
        description = "Detects RansomEXX ransomware"
        clamav_sig = "MALWARE.Win.Ransomware.RansomEXX"
    strings:
        $id = "ransom.exx" ascii
        $s1 = "!TXDOT_READ_ME!.txt" fullword wide
        $s2 = "debug.txt" fullword wide
        $s3 = ".txd0t" fullword wide
        $s4 = "crypt_detect" fullword wide
        $s5 = "powershell.exe" fullword wide
        $s6 = "cipher.exe" fullword ascii wide
        $s7 = "?ReflectiveLoader@@" ascii
    condition:
      uint16(0) == 0x5a4d and (($id and 3 of ($s*)) or all of ($*))
}

rule MALWARE_Win_QuasarStealer {
    meta:
        author = "ditekshen"
        description = "Detects Quasar infostealer"
        clamav_sig = "MALWARE.Win.Trojan.QuasarStealer"
    strings:
        $s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii
        $s2 = "DQuasar.Common, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
        $s3 = "Process already elevated." fullword wide
        $s4 = "get_PotentiallyVulnerablePasswords" fullword ascii
        $s5 = "GetKeyloggerLogsDirectory" ascii
        $s6 = "set_PotentiallyVulnerablePasswords" fullword ascii
        $s7 = "BQuasar.Client.Extensions.RegistryKeyExtensions+<GetKeyValues>" ascii
    condition:
      uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_RedLine {
    meta:
        author = "ditekSHen"
        description = "Detects RedLine infostealer"
        snort2_sid = "920072-920073"
        snort3_sid = "920072-920073"
        clamav_sig = "MALWARE.Win.Trojan.RedLine-1, MALWARE.Win.Trojan.RedLine-2"
    strings:
        $s1 = { 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 }
        $s2 = { 68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e
                32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e
                2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e
                32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e }
        $s3 = { 83 ec 38 53 b0 ?? 88 44 24 2b 88 44 24 2f b0 ??
                88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1
                b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff
                2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24
                18 b3 32 b8 0e 00 fe ff 2b c6 88 5c 24 32 88 5c
                24 41 89 44 24 28 57 b1 ?? bb 0b 00 fe ff b8 03
                00 fe ff 2b de 2b c6 bf 00 00 fe ff b2 ?? 2b fe
                88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34
                78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6
                44 24 41 33 c6 44 24 43 ?? c6 44 24 44 74 88 54
                24 46 c6 44 24 40 ?? c6 44 24 39 62 c7 44 24 10 }
        $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
        $s5 = " delete[]" fullword ascii
        $s6 = "constructor or from DllMain." ascii

        $x1 = "RedLine.Reburn" ascii
        $x2 = "RedLine.Client." ascii
        $x3 = "hostIRemotePanel, CommandLine: " fullword wide
        $u1 = "<ParseCoinomi>" ascii
        $u2 = "<ParseBrowsers>" ascii
        $u3 = "<GrabScreenshot>" ascii
        $u4 = "UserLog" ascii nocase
        $u5 = "FingerPrintT" fullword ascii
        $u6 = "InstalledBrowserInfoT" fullword ascii
        $u7 = "RunPE" fullword ascii
        $u8 = "DownloadAndEx" fullword ascii
        $u9 = ".Data.Applications.Wallets" ascii
        $u10 = ".Data.Browsers" ascii
        $u11 = ".Models.WMI" ascii
        $u12 = "DefenderSucks" wide

        $pat1 = "(((([0-9.])\\d)+){1})" fullword wide
        $pat2 = "^(?:2131|1800|35\\\\d{3})\\\\d{11}$" fullword wide
        $pat3 = "6(?:011|5[0-9]{2})[0-9]{12}$/C" fullword wide
        $pat4 = "Telegramprofiles^(6304|6706|6709|6771)[0-9]{12,15}$" fullword wide
        $pat5 = "host_key^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" fullword wide
        $pat6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" wide
        $pat7 = "settingsprotocol^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" wide
        $pat8 = "Opera GX4[0-9]{12}(?:[0-9]{3})?$cookies" wide
        $pat9 = "^9[0-9]{15}$Coinomi" wide
        $pat10 = "wallets^(62[0-9]{14,17})$" wide
        $pat11 = "hostpasswordUsername_value" wide
        $pat12 = "credit_cards^389[0-9]{11}$" wide
        $pat13 = "NWinordVWinpn.eWinxe*WinhostUsername_value" wide
        $pat14 = /(\/|,\s)CommandLine:/ wide
        // another variant
        $v2_1 = "ListOfProcesses" fullword ascii
        $v2_2 = /get_Scan(ned)?(Browsers|ChromeBrowsersPaths|Discord|FTP|GeckoBrowsersPaths|Screen|Steam|Telegram|VPN|Wallets)/ fullword ascii
        $v2_3 = "GetArguments" fullword ascii
        $v2_4 = "VerifyUpdate" fullword ascii
        $v2_5 = "VerifyScanRequest" fullword ascii
        $v2_6 = "GetUpdates" fullword ascii
        // yet another variant
        $v3_1 = "localhost.IUserServiceu" fullword ascii
        $v3_2 = "ParseNetworkInterfaces" fullword ascii
        $v3_3 = "ReplyAction0http://tempuri.org/IUserService/GetUsersResponse" fullword ascii
        $v3_4 = "Action(http://tempuri.org/IUserService/GetUsersT" fullword ascii
        $v3_5 = "basicCfg" fullword wide
        // more variants
        $vx4_1 = "C:\\\\Windows\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319\\\\AddInProcess32.exe" fullword wide
        $v4_2 = "isWow64" fullword ascii
        $v4_3 = "base64str" fullword ascii
        $v4_4 = "stringKey" fullword ascii
        $v4_5 = "BytesToStringConverted" fullword ascii
        $v4_6 = "FromBase64" fullword ascii
        $v4_7 = "xoredString" fullword ascii
        $v4_8 = "procName" fullword ascii
        $v4_9 = "base64EncodedData" fullword ascii
        // another variant 2021-10-23
        $v5_1 = "DownloadAndExecuteUpdate" fullword ascii
        $v5_2 = "ITaskProcessor" fullword ascii
        $v5_3 = "CommandLineUpdate" fullword ascii
        $v5_4 = "DownloadUpdate" fullword ascii
        $v5_5 = "FileScanning" fullword ascii
        $v5_6 = "GetLenToPosState" fullword ascii
        $v5_7 = "RecordHeaderField" fullword ascii
        $v5_8 = "EndpointConnection" fullword ascii
        $v5_9 = "BCRYPT_KEY_LENGTHS_STRUCT" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or 2 of ($x*) or 7 of ($u*) or 7 of ($pat*) or (1 of ($x*) and (5 of ($u*) or 2 of ($pat*))) or 5 of ($v2*) or 4 of ($v3*) or (3 of ($v2*) and (2 of ($pat*) or 2 of ($u*)) or (1 of ($vx4*) and 5 of ($v4*)) or 5 of ($v4*) or 6 of ($v5*)))) or (all of ($x*) and 4 of ($s*))
}

rule MALWARE_Win_Bandook {
    meta:
        author = "ditekshen"
        description = "Detects Bandook backdoor"
        clamav_sig = "MALWARE.Win.Trojan.Bandook"
    strings:
        $s1 = "\"%sLib\\dpx.pyc\" \"%ws\" \"%ws\" \"%ws\" \"%ws\" \"%ws\"" fullword wide
        $s2 = "%s\\usd\\dv-%s.dat" fullword ascii
        $s3 = "%sprd.dat" fullword ascii
        $s4 = "%sfile\\shell\\open\\command" fullword ascii
        $s5 = "explorer.exe , %s" fullword ascii

        $f1 = "CaptureScreen" fullword ascii
        $f2 = "StartShell" fullword ascii
        $f3 = "ClearCred" fullword ascii
        $f4 = "GrabFileFromDevice" fullword ascii
        $f5 = "PutFileOnDevice" fullword ascii
        $f6 = "ChromeInject" fullword ascii
        $f7 = "StartFileMonitor" fullword ascii
        $f8 = "DisableMouseCapture" fullword ascii
        $f9 = "StealUSB" fullword ascii
        $f10 = "DDOSON" fullword ascii
        $f11 = "InstallMac" fullword ascii
        $f12 = "SendCam" fullword ascii

        $x1 = "RTC-TGUBP" fullword ascii
        $x2 = "AVE_MARIA" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 6 of ($f*) or (2 of ($s*) and 3 of ($f*)) or (all of ($x*) and (2 of ($f*) or 3 of ($s*))))
}

rule MALWARE_Win_Kimsuky {
    meta:
        author = "ditekshen"
        description = "Detects Kimsuky backdoor"
        clamav_sig = "MALWARE.Win.Trojan.Kimsuky"
    strings:
        $s1 = "Win%d.%d.%dx64" fullword ascii
        $s2 = ".zip" fullword ascii
        $s3 = ".enc" fullword ascii
        $s4 = "&p2=a" fullword ascii
        $s5 = "Content-Disposition: form-data; name=\"binary\"; filename=\"" fullword ascii
        $s6 = "%s/?m=a&p1=%s&p2=%s-%s-v%d" fullword ascii
        $s7 = "/?m=b&p1=" fullword ascii
        $s8 = "/?m=c&p1=" fullword ascii
        $s9 = "/?m=d&p1=" fullword ascii
        $s10 = "http://%s/%s/?m=e&p1=%s&p2=%s&p3=%s" fullword ascii
        $s11 = "taskkill.exe /im iexplore.exe /f" fullword ascii
        $s12 = "GetParent" fullword ascii
        $s13 = "DllRegisterServer" fullword ascii
        $dll1 = "AutoUpdate.dll" fullword ascii
        $dll2 = "dropper-ie64.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($dll*) and 7 of ($s*)) or (11 of ($*)))
}

rule MALWARE_Win_DLAgent03 {
    meta:
      author = "ditekSHen"
      description = "Detects known Delphi downloader agent downloading second stage payload, notably from discord"
      clamav_sig = "MALWARE.Win.Trojan.DLAgent03"
    strings:
        $delph1 = "FastMM Borland Edition" fullword ascii
        $delph2 = "SOFTWARE\\Borland\\Delphi" ascii
        $v1_1 = "InternetOpenUrlA" fullword ascii
        $v1_2 = "CreateFileA" fullword ascii
        $v1_3 = "WriteFile" fullword ascii
        $v2_1 = "WinHttp.WinHttpRequest.5.1" fullword ascii
        $v2_2 = { 6f 70 65 6e ?? ?? ?? ?? ?? 73 65 6e 64 ?? ?? ?? ?? 72 65 73 70 6f 6e 73 65 74 65 78 74 }
        // $pat is slowing down scanning
        //$pat = /[a-f0-9]{168}/ fullword ascii
        $url1 = "https://discord.com/" fullword ascii
        $url2 = "http://www.superutils.com" fullword ascii
        $url3 = "http://www.xboxharddrive.com" fullword ascii
    condition:
        //uint16(0) == 0x5a4d and 1 of ($delph*) and $discord and ((all of ($v1*) or all of ($v2*)) or $pat)
        uint16(0) == 0x5a4d and 1 of ($delph*) and 1 of ($url*) and (all of ($v1*) or 1 of ($v2*))
}

rule MALWARE_Win_Salfram {
    meta:
        author = "ditekSHen"
        description = "Detects Salfram executables"
        snort2_sid = "920085-920087"
        snort3_sid = "920085"
        clamav_sig = "MALWARE.Win.Trojan.Salfram"
    strings:
        $s1 = "!This Salfram cannot be run in DOS mode." fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_HawkEyeV9 {
    meta:
        author = "ditekshen"
        description = "Detects HawkEyeV9 payload"
        clamav_sig = "MALWARE.Win.Trojan.HawkEyeV9"
    strings:
        $id1 = "HawkEye Keylogger - Reborn v9 - {0} Logs - {1} \\ {2}" wide
        $id2 = "HawkEye Keylogger - Reborn v9{0}{1} Logs{0}{2} \\ {3}{0}{0}{4}" wide
        $str1 = "_PasswordStealer" ascii
        $str2 = "_KeyStrokeLogger" ascii
        $str3 = "_ScreenshotLogger" ascii
        $str4 = "_ClipboardLogger" ascii
        $str5 = "_WebCamLogger" ascii
        $str6 = "_AntiVirusKiller" ascii
        $str7 = "_ProcessElevation" ascii
        $str8 = "_DisableCommandPrompt" ascii
        $str9 = "_WebsiteBlocker" ascii
        $str10 = "_DisableTaskManager" ascii
        $str11 = "_AntiDebugger" ascii
        $str12 = "_WebsiteVisitorSites" ascii
        $str13 = "_DisableRegEdit" ascii
        $str14 = "_ExecutionDelay" ascii
        $str15 = "_InstallStartupPersistance" ascii
    condition:
        int16(0) == 0x5a4d and (1 of ($id*) or 5 of ($str*))
}

rule MALWARE_Win_HyperBro {
    meta:
        author = "ditekSHen"
        description = "Detects HyperBro (class names) payload"
        clamav_sig = "MALWARE.Win.Trojan.HyperBro"
    strings:
        $s1 = "VTClipboardInfo" ascii wide
        $s2 = "VTClipboardMgr" ascii wide
        $s3 = "VTFileRename" ascii wide
        $s4 = "VTFileRetime" ascii wide
        $s5 = "VTKeyboardInfo" ascii wide
        $s6 = "VTKeyboardMgr" ascii wide
        $s7 = "VTRegeditKeyInfo" ascii wide
        $s8 = "VTRegeditMgr" ascii wide
        $s9 = "VTRegeditValueInfo" ascii wide
        $s10 = "VTFileDataRes" ascii wide
    condition:
        uint16(0) == 0x5a4d and 9 of them
}

rule MALWARE_Linux_UNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown/unidentified Linux malware"
    strings:
        $f1 = "%sresponse.php?status" ascii
        $f2 = "%supstream.php?mid=%s&os=%s" ascii fullword
        $f3 = "%supstream.php?tid=%" ascii
        $f4 = "%sindex.php?token=%.32s&flag=%d&name=%s" ascii fullword
        $f5 = "%sactive_off.php?id=%d&uniqu=%d" ascii fullword
        $s1 = "lock:%i usable num:%i n:%i" fullword ascii
        $s2 = "tid:%.*s tNumber:%i" fullword ascii
        $s3 = "init.php" fullword ascii
        $s4 = "mod_drone" fullword ascii
        $s5 = "new_mid" fullword ascii
        $s6 = "&exists[]=" fullword ascii
        $s7 = "&mod[]=" fullword ascii
        $s8 = "shutdown" fullword ascii
        $s9 = "&mac[]=%02X%02X%02X%02X%02X%02X" fullword ascii
    condition:
        uint16(0) == 0x457f and (3 of ($f*) or 6 of ($s*))
}

rule MALWARE_Linux_UNK02 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown/unidentified Linux malware"
    strings:
        $rf1 = "[]A\\A]A^A_" ascii
        $rf2 = "[A\\A]A^A_]" ascii
        $f1 = "/bin/basH" ascii fullword
        $f2 = "/proc/seH" ascii fullword
        $f3 = "/dev/ptsH" ascii fullword
        $f4 = "pqrstuvwxyzabcde" ascii fullword
        $f5 = "libnss_%s.so.%d.%d" ascii fullword
    condition:
        uint16(0) == 0x457f and (all of ($f*) and #rf1 > 3 and #rf2 > 3)
}

rule MALWARE_Win_iTranslatorEXE {
    meta:
        author = "ditekSHen"
        description = "Detects iTranslator EXE payload"
        clamav_sig = "MALWARE.Win.Trojan.iTranslator_EXE"
    strings:
        $s1 = "\\itranslator\\wintrans.exe" fullword wide
        $s2 = "\\SuperX\\SuperX\\Obj\\Release\\SharpX.pdb" fullword ascii
        $s3 = "\\itranslator\\itranslator.dll" fullword ascii
        $s4 = ":Intoskrnl.exe" fullword ascii
        $s5 = "InjectDrv.sys" fullword ascii
        $s6 = "SharpX.dll" fullword wide
        $s7 = "GetMicrosoftEdgeProcessId" ascii
        $s8 = ".php?type=is&ch=" ascii
        $s9 = ".php?uid=" ascii
        $s10 = "&mc=" fullword ascii
        $s11 = "&os=" fullword ascii
        $s12 = "&x=32" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of ($s*)
}

rule MALWARE_Win_iTranslatorDLL {
    meta:
        author = "ditekSHen"
        description = "Detects iTranslator DLL payload"
        clamav_sig = "MALWARE.Win.Trojan.iTranslator_DLL"
    strings:
        $d1 = "system32\\drivers\\%S.sys" fullword wide
        $d2 = "\\windows\\system32\\winlogon.exe" fullword ascii
        $d3 = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\%s" fullword wide
        $d4 = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\webssx" fullword wide
        $d5 = "\\Device\\CtrlSM" fullword wide
        $d6 = "\\DosDevices\\CtrlSM" fullword wide
        $d7 = "\\driver_wfp\\CbFlt\\Bin\\CbFlt.pdb" ascii
        $d8 = ".php" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWWARE_Win_Octopus {
    meta:
        author = "ditekSHen"
        description = "Detects Octopus trojan payload"
        clamav_sig = "MALWARE.Win.Trojan.Octopus"
    strings:
        $s1 = "\\Mozilla\\Firefox\\Profiles\\" fullword wide
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s3 = "\\wbem\\WMIC.exe" fullword wide
        $s4 = ".profiles.ini" fullword wide
        $s5 = "PushEBP_" ascii
        $s6 = "MovEBP_ESP_" ascii
        $s7 = "Embarcadero Delphi for Win32 compiler" ascii
        $s8 = "TempWmicBatchFile.bat" fullword wide
        $wq1 = "computersystem get Name /format:list" wide
        $wq2 = "os get installdate /format:list" wide
        $wq3= "get serialnumber /format:list" wide
        $wq4 = "\\\\\\\\.\\\\PHYSICALDRIVE" wide
        $wq5= "path CIM_LogicalDiskBasedOnPartition" wide
        $wq6 = "get Antecedent,Dependent" wide
        $wq7 = "path win32_physicalmedia" wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) and 5 of ($wq*))
}

rule MALWARE_Win_CasperTroy {
    meta:
        author = "ditekSHen"
        description = "Detects CasperTroy payload"
    strings:
        $s1 = "DllTroy.dll" fullword ascii
        $s2 = "Content-Disposition: form-data; name=\"image\"; filename=\"title.gif\"" fullword ascii
        $s3 = "Content-Disposition: form-data; name=\"COOKIE_ID\"" fullword ascii
        $s4 = "Content-Disposition: form-data; name=\"PHP_SESS_ID\"" fullword ascii
        $s5 = "Content-Disposition: form-data; name=\"SESS_ID\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_Rasftuby {
    meta:
        author = "ditekSHen"
        description = "Detects Rasftuby/DarkCrystal"
        clamav_sig = "MALWARE.Win.Trojan.DarkCrystal.RAT-Rasftuby"
    strings:
        $s1 = "/DCRS/main.php?data=active" fullword ascii wide
        $s2 = "/socket.php?type=__ds_" ascii wide
        $s3 = "/uploader.php" fullword ascii wide
        $s4 = "del \\\"%USERPROFILE%\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\System.lnk\\\"" fullword ascii wide
        $s5 = "Host:{0},Port:{1},User:{2},Pass:{3}<STR>" fullword ascii wide
        $s6 = "keyloggerstart_status" fullword ascii wide
        $s7 = "keyloggerstop_status" fullword ascii wide
        $s8 = "[PRINT SCREEN]" fullword ascii wide
        $s9 = "DCS.Internal" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of ($s*)
}

rule MALWARE_Win_ProtonBot {
    meta:
        author = "ditekSHen"
        description = "Detects ProtonBot loader"
        clamav_sig = "MALWARE.Win.Trojan.ProtonBot"
    strings:
        $x1 = "\\PROTON\\Release\\build.pdb" ascii
        $x2 = "\\proton\\proton bot\\json.hpp" wide
        $x3 = "proton bot" ascii wide
        $s1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s2 = "ranges.size() == 2 or ranges.size() == 4 or ranges.size() == 6" fullword wide
        $s3 = "ref_stack.back()->is_array() or ref_stack.back()->is_object()" fullword wide
        $s4 = "ktmw32.dll" fullword ascii
        $s5 = "@detail@nlohmann@@" ascii
        $s6 = "urlmon.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (all of ($s*) and 1 of ($x*)))
}

rule MALWARE_Win_ImminentRAT {
    meta:
        author = "ditekSHen"
        description = "Detects ImminentRAT"
    strings:
        $x1 = "abuse@imminentmethods.net" ascii
        $x2 = "Imminent-Monitor-" ascii
        $x3 = "AddressChangeListener" fullword ascii
        $x4 = "SevenZipHelper" fullword ascii
        $x5 = "WrapNonExceptionThrows" fullword ascii
        $s1 = "_ENABLE_PROFILING" wide
        $s2 = "Anti-Virus: {0}" wide
        $s3 = "File downloaded & executed" wide
        $s4 = "Chat - You are speaking with" wide
        $s5 = "\\Imminent\\Plugins" wide
        $s6 = "\\Imminent\\Path.dat" wide
        $s7 = "\\Imminent\\Geo.dat" wide
        $s8 = "DisableTaskManager = {0}" wide
        $s9 = "This client is already mining" wide
        $s10 = "Couldn't get AV!" wide
        $s11 = "Couldn't get FW!" wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or 5 of ($s*))
}

rule MALWARE_Win_WarzoneRAT {
    meta:
        author = "ditekSHen"
        description = "Detects AveMaria/WarzoneRAT"
    strings:
        $s1 = "RDPClip" fullword wide
        $s2 = "Grabber" fullword wide
        $s3 = "Ave_Maria Stealer OpenSource" wide
        $s4 = "\\MidgetPorn\\workspace\\MsgBox.exe" wide
        $s5 = "@\\cmd.exe" wide
        $s6 = "/n:%temp%\\ellocnak.xml" wide
        $s7 = "Hey I'm Admin" wide
        $s8 = "warzone160" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of ($s*)
}

rule MALWARE_Win_KaraganyCore {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost core plugin"
    strings:
        $s1 = "127.0.0.1" fullword ascii
        $s2 = "port" fullword ascii
        $s3 = "C:\\Windows\\System32\\Kernel32.dll" fullword ascii
        $s4 = "kernel32.dll" fullword ascii
        $s5 = "http" ascii
        $s6 = "Move" fullword ascii
        $s7 = "<supportedOS Id=\"{" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_KaraganyKeylogger {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost keylogger plugin"
    strings:
        $s1 = "__klg__" fullword wide
        $s2 = "__klgkillsoft__" fullword wide
        $s3 = "CLIPBOARD_PASTE" wide
        $s4 = "%s\\k%d.txt" wide
        $s5 = "\\Update\\Tmp" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_KaraganyScreenUtil {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost ScreenUtil module"
    strings:
        $s1 = "__pic__" ascii wide
        $s2 = "__pickill__" ascii wide
        $s3 = "\\picture.png" fullword wide
        $s4 = "%d.jpg" wide
        $s5 = "\\Update\\Tmp" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_KaraganyListrix {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost Listrix module"
    strings:
        $s1 = "\\Update\\Tmp\\" wide
        $s2 = "*pass*.*" fullword wide
        $s3 = ">> NUL" wide
        $s4 = "%02d.%02d.%04d %02d:%02d" wide
        $s5 = "/c del" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Osx_MacSearch {
    meta:
        author = "ditekSHen"
        description = "Detects MacSearch adware"
    strings:
        $s1 = "open -a safari" ascii
        $s2 = "/INDownloader" ascii
        $s3 = "/safefinder" ascii
        $s4 = "/INEncryptor" ascii
        $s5 = "/INInstallerFlow" ascii
        $s6 = "/INConfiguration" ascii
        $s7 = "/INChromeAndFFSetter" ascii
        $s8 = "/INSafariSetter" ascii
        $s9 = "/bin/launchctl" fullword ascii
        $s10 = "/usr/bin/csrutil" fullword ascii
        $s11 = "_Tt%cSs%zu%.*s%s" fullword ascii
        $s12 = "_Tt%c%zu%.*s%zu%.*s%s" fullword ascii
        $s13 = "/macap/safefinder_Obf/safefinder/" ascii
        $s14 = "/safefinder.build/Release/macsearch.build/" ascii
    condition:
        uint16(0) == 0xfacf and 10 of them
}

rule MALWARE_Osx_Genieo {
    meta:
        author = "ditekSHen"
        description = "Detects LinqurySearch/Genieo adware"
        clamav_sig = "MALWARE.Osx.Trojan.Genieo"
    strings:
        $s1 = "<key>com.apple.security.get-task-allow</key>" fullword ascii
        $s2 = "U1QQFXAfCxAfRUNCH1JZXh9" ascii
        $s3 = "XVFTQ1VRQlNYH" ascii
        $s4 = "dF9HXlxfUVQQVUJCX0IQHRB" ascii
        $s5 = "Value:forHTTPHeaderField:" ascii
        $s6 = "postContent:::" fullword ascii
        $s7 = "postLog:" fullword ascii
        $s8 = "initWithBase64EncodedString:options:" fullword ascii
        $s9 = "do shell script \"%@\" with administrator privileges" fullword ascii
        $s10 = /LinqurySearch-[a-f0-9]{40,}/
    condition:
        uint16(0) == 0xfacf and 6 of them
}

rule MALWARE_Osx_AMCPCVARK {
    meta:
        author = "ditekSHen"
        description = "Detects OSX TechyUtils/PCVARK adware"
        clamav_sig = "MALWARE.Osx.Adware.AMC-PCVARK-TechyUtils"
    strings:
        $s1 = "Mac Auto Fixer.app" fullword ascii
        $s2 = "com.techyutil.macautofixer" fullword ascii
        $s3 = "com.findApp.findApp" ascii
        $s4 = "Library/Preferences/%@.plist" fullword ascii
        $s5 = "Library/%@/%@" fullword ascii
        $s6 = "Library/Application Support/%@/%@" fullword ascii
        $s7 = "sleep 3; rm -rf \"%@\"" fullword ascii
        $s8 = "Silently calling url: %@" ascii

        $cnc1 = "cloudfront.net/getdetails" ascii
        $cnc2 = "trk.entiretrack.com/trackerwcfsrv/tracker.svc/trackOffersAccepted/?" ascii
        $cnc3 = "pxl=%@&x-count=1&utm_source=%@&lpid=0&utm_content=&utm_term=&x-base=&utm_medium=%@&utm_publisher=%@&offerpxl=&x-fetch=1&utm_campaign=@&affiliateid=&x-at=&btnid=" ascii

        $x1 = "mafsysinfo" fullword ascii
        $x2 = "MAF4497_MAF4399_MAF2204" ascii

        $developerid = "Developer ID Application: Rahul Gahlot (RZ74UYT742)" ascii
    condition:
        uint16(0) == 0xfacf and (6 of ($s*) or 2 of ($cnc*) or all of ($x*) or $developerid)
}

rule MALWARE_Osx_RealtimeSpy {
    meta:
        author = "ditekSHen"
        description = "Detects macOS RealtimeSpy monitoring app"
        clamav_sig = "MALWARE.Osx.Trojan.RealtimeSpy"
    strings:
        $x1 = "SPYAGENT4HASHCIPHER" fullword ascii
        $x2 = ":username:password:acctid:compUser:compName:" ascii
        $x3 = ":username:password:acctid:compName:" ascii
        $x4 = "://www.realtime-spy-mac.com/" ascii
        $x5 = "/Users/spytech/" ascii
        $x6 = "shell script \"touch /private/var/db/.AccessibilityAPIEnabled\" password \"pwd\" with administrator privileges" ascii
        $x7 = "Content-Disposition: form-data; name=\"raptor_" ascii

        $c1 = "_OBJC_CLASS_$_LocationLogger" fullword ascii
        $c2 = "_OBJC_CLASS_$_MonitoringFunctions" fullword ascii
        $c3 = "_OBJC_CLASS_$_ProcessLogger" fullword ascii
        $c4 = "_OBJC_CLASS_$_RealtimeLoggingFunctions" fullword ascii
        $c5 = "_OBJC_CLASS_$_Realtime_SpyAppDelegate" fullword ascii
        $c6 = "_OBJC_CLASS_$_ScreenshotLogger" fullword ascii
        $c7 = "_OBJC_CLASS_$_Uploader" fullword ascii
        $c8 = "_OBJC_CLASS_$_UsageLogger" fullword ascii
        $c9 = "_OBJC_CLASS_$_WebsiteLogger" fullword ascii
    condition:
        uint16(0) == 0xfacf and (2 of ($x*) or 2 of ($c*))
}

rule MALWARE_Osx_MaxOfferDeal {
    meta:
        author = "ditekSHen"
        description = "Detects macOS MaxOfferDeal adware"
        clamav_sig = "MALWARE.Osx.Adware.MaxOfferDeal"
    strings:
        $s1 = "clEvE15obfuscated_data" ascii
        $s2 = "%.*s.%.*s" fullword ascii
        $s3 = "_Tt%cSs%zu%.*s%s" fullword ascii
        $s4 = "_Tt%c%zu%.*s%zu%.*s%s" fullword ascii
        $s5 = "__ZL20tFirefoxProfilesPath" ascii
        $s6 = "__ZL22tFirefoxSearchFileName" ascii
        $s7 = "__ZL37tFirefoxDefaultProfileFolderExtension" ascii
        $s8 = "__ZL21tFirefoxPrefsFileName" ascii
        $s9 = "__GLOBAL__sub_I_Firefox.mm" ascii
        $s10 = "add_image_hook_" ascii
        $s11 = "/Library/Caches/com.apple.xbs/Sources/arclite/arclite-66/source/" fullword ascii
    condition:
        uint16(0) == 0xfacf and all of them
}

rule MALWARE_Osx_WindTrail {
    meta:
        author = "ditekSHen"
        description = "Detects WindTrail OSX trojan"
        clamav_sig = "MALWARE.Osx.Trojan.WindTrail"
    strings:
        $s1 = "m_ComputerName_UserName" fullword ascii
        $s2 = "m_uploadURL" fullword ascii
        $s3 = "m_logString" fullword ascii
        $s4 = "GenrateDeviceName" fullword ascii
        $s5 = "open -a" fullword ascii
        $s6 = "AESEncryptFile:toFile:usingPassphrase:error:" fullword ascii
        $s7 = "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
        $s8 = "_kLSSharedFileListSessionLoginItems" fullword ascii
        $developerid = "Developer ID Application: warren portman (95RKE2AA8F)" ascii
    condition:
        uint16(0) == 0xfacf and (all of ($s*) or $developerid)
}

rule MALWARE_Osx_TechyUtils {
    meta:
        author = "ditekSHen"
        description = "Detects TechyUtils OSX packages"
        clamav_sig = "MALWARE.Osx.Trojan.TechyUtils"
    strings:
        $s1 = "__ZL58__arclite_NSMutableDictionary__" ascii
        $s2 = "__ZL46__arclite_NSDictionary_" ascii
        $s3 = "<key>com.apple.security.get-task-allow</key>" fullword ascii
        $s4 = "/productprice.svc/GetCountryCode" ascii
        $s5 = "@_pthread_mutex_lock" fullword ascii
        $s6 = "_mh_execute_header" fullword ascii
        $s7 = "/Users/prasoon/Documents/" ascii
        $developerid = "Developer ID Application: Techyutils Software Private Limited (VS9Q8BRRRJ)" ascii
    condition:
        uint16(0) == 0xfacf and (all of ($s*) or $developerid)
}

rule MALWARE_Osx_LamePyre {
    meta:
        description = "Detects LamePyre"
    strings:
        // wFlow
        $s1 = "/Automator/Run Shell" ascii
        $s2 = "curl " ascii
        $s3 = "base64" ascii
        $s4 = "screencapture" ascii
        $s5 = "handler.php"
        $s6 = "zip" ascii
        // Persistence scripts
        $ps1 = "base64.b64decode" ascii
        $ps2 = "dXJsbGliM" ascii         // urllib2
        $ps3 = "c3VicHJvY2Vz" ascii      // subprocess
        $ps4 = "aW5kZXguYXN" ascii       // index.asp
        $sp5 = "YWRkaGVhZGVy" ascii      // addheader
    condition:
        all of ($ps*) or 5 of ($s*)
}

rule MALWARE_Win_DLAgent04 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches from paste-like websites, most notably hastebin"
      clamav_sig = "MALWARE.Win.Trojan.DLAgent04"
    strings:
        $x1 = "@@@http" ascii wide
        $s1 = "HttpWebRequest" fullword ascii
        $s2 = "GetResponseStream" fullword ascii
        $s3 = "set_FileName" fullword ascii
        $s4 = "set_UseShellExecute" fullword ascii
        $s5 = "WebClient" fullword ascii
        $s6 = "set_CreateNoWindow" fullword ascii
        $s7 = "DownloadString" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and #x1 > 1 and 4 of ($s*)
}

rule MALWARE_Win_GDriveRAT {
    meta:
        author = "ditekSHen"
        description = "Detects GDriveRAT"
        clamav_sig = "MALWARE.Win.Trojan.GDriveRAT"
    strings:
        $h1 = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart" fullword wide
        $h2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36" fullword wide
        $h3 = "multipart/related; boundary=\"boundary_tag\"" fullword wide
        $h4 = "https://www.googleapis.com/drive/v3/files" fullword wide
        $s1 = "move gdrive.exe \"C:\\Users\\" fullword wide
        $s2 = "file_data" fullword ascii
        $s3 = "comp_id" fullword ascii
        $s4 = "file_name" fullword ascii
        $s5 = "refresh_token" fullword ascii
        $s6 = "commands" fullword ascii
        $s7 = "execute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($h*) and 5 of ($s*)
}

rule MALWARE_Win_STOP {
    meta:
        author = "ditekSHen"
        description = "Detects STOP ransomware"
        snort2_sid = "920113"
        snort3_sid = "920111"
        clamav_sig = "MALWARE.Win.Ransomware.STOP"
    strings:
        $x1 = "C:\\SystemID\\PersonalID.txt" fullword wide
        $x2 = "/deny *S-1-1-0:(OI)(CI)(DE,DC)" wide
        $x3 = "e:\\doc\\my work (c++)\\_git\\encryption\\" ascii wide nocase
        $s1 = "\" --AutoStart" fullword ascii wide
        $s2 = "--ForNetRes" fullword wide
        $s3 = "--Admin" fullword wide
        $s4 = "%username%" fullword wide
        $s5 = "?pid=" fullword wide
        $s6 = /&first=(true|false)/ fullword wide
        $s7 = "delself.bat" ascii
        $mutex1 = "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}" fullword ascii
        $mutex2 = "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}" fullword ascii
        $mutex3 = "{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($x*) and 1 of ($mutex*)) or (all of ($x*)) or (6 of ($s*) and (1 of ($x*) or 1 of ($mutex*))) or (9 of them))
}

rule MALWARE_Win_ParallaxRAT {
    meta:
        author = "ditekSHen"
        description = "Detects ParallaxRAT"
        clamav_sig = "MALWARE.Win.Trojan.ParallaxRAT"
    strings:
       $s1 = "[Clipboard End]" fullword wide
       $s2 = "[Ctrl +" fullword wide
       $s3 = "[Alt +" fullword wide
       $s4 = "Clipboard Start" wide
       $s5 = "(Wscript.ScriptFullName)" wide
       $s6 = "CSDVersion" fullword ascii
       $s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword ascii
       $x1 = { 2e 65 78 65 00 00 84 00 00 4d 5a 90 00 }
       $x2 = "This program cannot be run in DOS mode" ascii
    condition:
        ((uint16(0) == 0x5a4d and all of ($s*)) or all of them)
}

rule MALWARE_Win_Meterpreter {
    meta:
        author = "ditekSHen"
        description = "Detects Meterpreter payload"
    strings:
        $s1 = "PACKET TRANSMIT" fullword ascii
        $s2 = "PACKET RECEIVE" fullword ascii
        $s3 = "\\\\%s\\pipe\\%s" fullword ascii wide
        $s4 = "%04x-%04x:%s" fullword wide
        $s5 = "server.dll" fullword ascii
        //$s6 = "tcp://" wide
    condition:
        (uint16(0) == 0x5a4d and all of them) or (filesize < 300KB and all of them)
}

/*
rule MALWARE_Win_Raccoon {
    meta:
        author = "ditekSHen"
        description = "Detects Raccoon/Racealer infostealer"
        clamav_sig = "MALWARE.Win.Trojan.Raccoon"
    strings:
        $s1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s2 = "inetcomm server passwords" fullword wide
        $s3 = "\\json.hpp" wide
        $s4 = "CredEnumerateW" fullword ascii
        $s5 = "Microsoft_WinInet_" fullword wide
        $s6 = "already connected" fullword ascii
        $s7 = "copy_file" fullword ascii
        $s8 = "\"; filename=\"" fullword ascii
        $s9 = "%[^:]://%[^/]%[^" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
*/

rule MALWARE_Win_Trojan_ExpressCMS {
    meta:
        author = "ditekSHen"
        description = "Detects ExpressCMS"
        clamav_sig = "MALWARE.Win.Trojan.ExpressCMS"
    strings:
        $s1 = "/click.php?cnv_id=" fullword wide
        $s2 = "/click.php?key=" wide
        $s3 = "jdlnb" fullword wide
        $s4 = "Gkjfdshfkjjd: dsdjdsjdhv" fullword wide
        $s5 = "--elevated" fullword wide
        $s6 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%d" wide
        $s7 = "\\Microsoft\\Manager.exe" fullword wide
        $s8 = "\\Microsoft\\svchost.exe" fullword wide
    condition:
       uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_MeterpreterStager {
    meta:
        author = "ditekSHen"
        description = "Detects Meterpreter stager payload"
    strings:
        $s1 = "PAYLOAD:" fullword ascii
        $s2 = "AQAPRQVH1" fullword ascii
        $s3 = "ws2_32" fullword ascii
        $s4 = "KERNEL32.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them and filesize < 100KB
}

rule MALWARE_Win_Ziggy {
    meta:
        author = "ditekSHen"
        description = "Detects Ziggy ransomware"
        snort2_sid = "920098"
        snort3_sid = "920096"
        clamav_sig = "MALWARE.Win.Ransomware.Ziggy"
    strings:
        $id1 = "/Ziggy Info;component/mainwindow.xaml" fullword wide
        $id2 = "AZiggy Info, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
        $id3 = "Ziggy Ransomware" fullword wide
        $id4 = "clr-namespace:Zeggy" fullword ascii
        $s1 = "GetCooldown" fullword ascii
        $s2 = "checkCommandMappings" fullword ascii
        $s3 =  "add_OnExecuteCommand" fullword ascii
        $s4 = "MindLated.jpg" fullword wide
        $s5 = "http://fixfiles.xyz/ziggy/api/info.php?id=" fullword wide
        $s6 = "Reamaining time:" fullword wide
        $msg1 = "<:In case of no answer in 12 hours write us to this e-mail" ascii
        $msg2 = "Free decryption as guarantee" fullword ascii
        $msg3 = "# Do not try to decrypt your data using third party software, it may cause permanent data loss" ascii
        $msg4 = "# Decryption of your files with the help of third parties may cause increased price (they add their fee to our) or you can becom" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($id*) or 4 of ($s*) or 3 of ($msg*))
}

rule MALWARE_Win_NWorm {
    meta:
        author = "ditekSHen"
        description = "Detects NWorm/N-W0rm payload"
        clamav_sig = "MALWARE.Win.Trojan.NWorm"
    strings:
        $id1 = "N-W0rm" ascii
        $id2 = "N_W0rm" ascii
        $x1 = "pongPing" fullword wide
        $x2 = "|NW|" fullword wide
        $s1 = "runFile" fullword wide
        $s2 = "runUrl" fullword wide
        $s3 = "killer" fullword wide
        $s4 = "powershell" fullword wide
        $s5 = "wscript.exe" fullword wide
        $s6 = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File \"" fullword wide
        $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36" fullword wide
        $s8 = "Start-Sleep -Seconds 1.5; Remove-Item -Path '" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($id*) and (1 of ($x*) or 3 of ($s*))) or (all of ($x*) and 2 of ($s*)) or 7 of ($s*) or 10 of them)
}

rule MALWARE_Win_QakBot {
    meta:
        author = "ditekSHen"
        description = "Detects variants of QakBot payload"
    strings:
        $s1 = "stager_1.dll" fullword ascii
        $s2 = "_vsnwprintf" fullword ascii
        $s3 = "DllRegisterServer" fullword ascii
        $s4 = "Win32_PnPEntity" fullword wide
        $s5 = "0>user32.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Fonix {
    meta:
        author = "ditekSHen"
        description = "Detects Fonix ransomware"
        clamav_sig = "MALWARE.Win.Ransomware.Fonix"
    strings:
        $s1 = "dontcryptanyway" fullword wide
        $s2 = "Cpriv.key" ascii wide
        $s3 = "Cpub.key" ascii wide
        $s4 = "NetShareEnum() failed!Error: % ld" fullword wide
        $s5 = "<div class='title'> Attention!</div><ul><li><u><b>DO NOT</b> pay" wide
        $s6 = "Encryption Completed !!!" fullword wide
        $s7 = "kill process" fullword ascii
        $s8 = "Copy SystemID C:\\ProgramData\\SystemID" ascii
        $id1 = "].FONIX" fullword wide
        $id2 = "xinofconfig.txt" fullword ascii wide
        $id3 = "XINOF4MUTEX" wide
        $id4 = ":\\Fonix\\cryptoPP\\" ascii
        $id5 = "schtasks /CREATE /SC ONLOGON /TN fonix" ascii
        $id6 = "Ransomware\\Fonix" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or 3 of ($id*) or (1 of ($id*) and 3 of ($s*)))
}

rule MALWARE_Win_Bobik {
    meta:
        author = "ditekSHen"
        description = "Detects Bobik infostealer"
        clamav_sig = "MALWARE.Win.Trojan.Bobik"
    strings:
        $s1 = "@Default\\Login Data" fullword ascii
        $s2 = "@Default\\Cookies" fullword ascii
        $s3 = "@logins.json" fullword ascii
        $s4 = "@[EXECUTE]" fullword ascii
        $s5 = "@C:\\Windows\\System32\\cmd.exe" fullword ascii
        $s6 = /(CHROME|OPERA|FIREFOX)_BASED/ fullword ascii
        $s7 = "threads.nim" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_RunningRAT {
    meta:
        author = "ditekSHen"
        description = "Detects RunningRAT"
        clamav_sig = "MALWARE.Win.Trojan.RunningRAT"
    strings:
        $s1 = "%s%d.dll" fullword ascii
        $s2 = "/c ping 127.0.0.1 -n" ascii
        $s3 = "del /f/q \"%s\"" ascii
        $s4 = "GUpdate" fullword ascii
        $s5 = "%s\\%d.bak" fullword ascii
        $s6 = "\"%s\",MainThread" ascii
        $s7 = "rundll32.exe" fullword ascii
        $rev1 = "emankcosteg" fullword ascii
        $rev2 = "ini.revreS\\" fullword ascii
        $rev3 = "daerhTniaM,\"s%\" s%" ascii
        $rev4 = "s% etadpUllD,\"s%\" 23lldnuR" ascii
        $rev5 = "---DNE yromeMmorFdaoL" fullword ascii
        $rev6 = "eMnigulP" fullword ascii
        $rev7 = "exe.23lldnuR\\" fullword ascii
        $rev8 = "dnammoc\\nepo\\llehs\\" ascii
        $rev9 = "\"s%\" k- exe.tsohcvs\\23metsyS\\%%tooRmetsyS%" ascii
        $rev10 = "emanybtsohteg" fullword ascii
        $rev11 = "tekcosesolc" fullword ascii
        $rev12 = "tpokcostes" fullword ascii
        $rev13 = "emantsohteg" fullword ascii
        // variant
        $v2_1 = "%%SystemRoot%%\\System32\\svchost.exe -k \"%s\"" fullword ascii
        $v2_2 = "LoadFromMemory END---" fullword ascii
        $v2_3 = "hmProxy!= NULL" fullword ascii
        $v2_4 = "Rundll32 \"%s\",DllUpdate %s" fullword ascii
        $v2_5 = "ipip.website" fullword ascii
        $v2_6 = "%d*%sMHz" fullword ascii
        $v2_7 = "\\Server.ini" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($rev*) or 6 of ($v*) or 8 of them)
}

rule MALWARE_Win_DLAgent05 {
    meta:
        author = "ditekSHen"
        description = "Detects an unknown dropper. Typically exisys as a DLL in base64-encoded gzip-compressed file embedded within another executable"
        clamav_sig = "MALWARE.Win.Trojan.DLAgent05"
    strings:
        $s1 = "MARCUS.dll" fullword ascii wide
        $s2 = "GZipStream" fullword ascii
        $s3 = "MemoryStream" fullword ascii
        $s4 = "proj_name" fullword ascii
        $s5 = "res_name" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Nemty {
    meta:
        author = "ditekSHen"
        description = "Detects Nemty/Nefilim ransomware"
    strings:
        $s1 = "Go build ID:" ascii
        $s2 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticKharoshthiManichaeanOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianSaurasht" ascii
        $s3 = "crypto/x509.ExtKeyUsage" ascii
        $s4 = "crypto/x509.KeyUsageContentCommitment" ascii
        $s5 = "DEK-Info header" ascii
        $s6 = "GetUserProfileDirectoryWMagallanes Standard TimeMontevideo Standard TimeNorth Asia Standard TimePacific SA Standard TimeQueryPerformanceCounter" fullword ascii
        $s7 = "*( -  <  =  >  k= m=%: +00+03+04+05+06+07+08+09+10+11+12+13+14-01-02-03-04-05-06-08-09-11-12..." ascii
        $s8 = "Go cmd/compile go1.10" fullword ascii
        $s9 = ".dllprogramdatarecycle.bin" ascii
        $s10 = ".dll.exe.lnk.sys.url" ascii
        $vx1_1 = "Fa1led to os.OpenFile()" ascii
        $vx1_2 = "-HELP.txt" ascii
        $vf1_1 = "main.CTREncrypt" fullword ascii
        $vf1_2 = "main.FileSearch" fullword ascii
        $vf1_3 = "main.getdrives" fullword ascii
        $vf1_4 = "main.RSAEncrypt" fullword ascii
        $vf1_5 = "main.SaveNote" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (9 of ($s*) or (all of ($vx*) and 2 of ($s*)) or all of ($vf*))
}

rule MALWARE_Win_QnapCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects QnapCrypt/Lockedv1/Cryptfile2 ransomware"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "Encrypting %s..." ascii
        $s2 = "\\Start Menu\\Programs\\StartUp\\READMEV" ascii
        $s3 = "main.deleteRecycleBin" ascii
        $s4 = "main.encryptFiles" ascii
        $s5 = "main.antiVirtualBox" ascii
        $s6 = "main.antiVmware" ascii
        $s7 = "main.deleteShadows" ascii
        $s8 = "main.delUAC" ascii
        $s9 = "main.KillProcess" ascii
        $s10 = "main.delExploit" ascii
        $s11 = "main.encrypt" ascii
        $s12 = "main.ClearLogDownload" ascii
        $s13 = "main.ClearLog" ascii
        $s14 = "main.EndEncrypt" ascii
        $s15 = "main.RunFuckLogAndSoft" ascii
        $s16 = "main.ClearUsercache" ascii
        $s17 = "main.FirstDuty" ascii
        $s18 = ".lockedv1" ascii
        $s19 = "WSAStartup\\clear.bat\\ngrok.exe\\video.mp4" ascii
        $s20 = "net stop " ascii
    condition:
        uint16(0) == 0x5a4d and $go and 6 of ($s*)
}

rule MALWARE_Win_Alfonoso {
    meta:
        author = "ditekSHen"
        description = "Detects Alfonoso / Shurk / HunterStealer infostealer"
        snort2_sid = "920102"
        snort3_sid = "920100"
        clamav_sig = "MALWARE.Win.Trojan.Alfonso"
    strings:
        $s1 = "%s\\etilqs_" fullword ascii
        $s2 = "SELECT name, rootpage, sql FROM '%q'.%s" fullword ascii
        $s3 = "%s-mj%08X" fullword ascii
        $s4 = "| Site:" ascii
        $s5 = "| Login:" ascii
        $s6 = "| Password:" ascii
        $s7 = "| BUILD NAME:" ascii
        $s8 = "recursive_directory_iterator" ascii
        $s9 = { 2e 7a 69 70 00 00 00 00 2e 7a 6f 6f 00 00 00 00
                2e 61 72 63 00 00 00 00 2e 6c 7a 68 00 00 00 00
                2e 61 72 6a 00 00 00 00 2e 67 7a 00 2e 74 67 7a
                00 00 00 00 }
        $s10 = "Shurk Steal" fullword ascii
        $s11 = ":memory:" fullword ascii
        $s12 = "current_path()" fullword ascii
        $s13 = "vtab:%p:%p" fullword ascii
        $f1 = "chatlog.txt" ascii
        $f2 = "servers.fav" ascii
        $f3 = "\\USERDATA.DAT" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($s*) and 2 of ($f*)) or (all of ($f*) and 5 of ($s*)))
}

rule MALWARE_Win_Vidar {
    meta:
        author = "ditekSHen"
        description = "Detects Vidar / ArkeiStealer"
    strings:
        $s1 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii
        $s2 = "screenshot.jpg" fullword wide
        $s3 = "Content-Disposition: form-data; name=\"" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Babuk {
    meta:
        author = "ditekSHen"
        description = "Detects Babuk ransomware"
    strings:
        $s1 = "ecdh_pub_k.bin" wide
        $s2 = "How To Restore Your Files.txt" wide
        $s3 = /(babuk|babyk)\s(ransomware|locker)/ ascii nocase
        $s4 = "/login.php?id=" ascii
        $s5 = "http://babuk" ascii
        $s6 = "bootsect.bak" fullword wide
        $s7 = "Can't open file after killHolder" ascii
        $s8 = "Can't OpenProcess" ascii
        $s9 = "DoYouWantToHaveSexWithCuongDong" ascii
        $arg1 = "-lanfirst" fullword ascii
        $arg2 = "-lansecond" fullword ascii
        $arg3 = "-nolan" fullword ascii
        $arg4 = "shares" fullword wide
        $arg5 = "paths" fullword wide
        $arg6 = "gdebug" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or (3 of ($arg*) and 2 of ($s*)))
}

rule MALWARE_Win_Nitol {
    meta:
        author = "ditekSHen"
        description = "Detects Nitol backdoor"
    strings:
        $s1 = "%$#@!.aspGET ^&*().htmlGET" ascii
        $s2 = "Applications\\iexplore.exe\\shell\\open\\command" fullword ascii
        $s3 = "taskkill /f /im rundll32.exe" fullword ascii
        $s4 = "\\Tencent\\Users\\*.*" fullword ascii
        $s5 = "[Pause Break]" fullword ascii
        $s6 = ":]%d-%d-%d  %d:%d:%d" fullword ascii
        $s7 = "GET %s HTTP/1.1" fullword ascii
        $s8 = "GET %s%s HTTP/1.1" fullword ascii
        $s9 = "Accept-Language: zh-cn" fullword ascii
        $s10 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)" fullword ascii
        $s11 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
        $s12 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
        $w1 = ".aspGET" ascii
        $w2 = ".htmGET" ascii
        $w3 = ".htmlGET" ascii
        $domain = "www.xy999.com" fullword ascii
        $v2_1 = "loglass" fullword ascii
        $v2_2 = "rlehgs" fullword ascii
        $v2_3 = "eherrali" fullword ascii
        $v2_4 = "agesrlu" fullword ascii
        $v2_5 = "lepejagas" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($v2*)) or ($domain and 3 of them) or (#w1 > 2 and #w2 > 2 and #w3 > 2 and 3 of ($s*)))
}

rule MALWARE_Win_StrongPity {
    meta:
        author = "ditekSHen"
        description = "Detects StrongPity"
    strings:
        $s1 = "Boundary%08X" ascii wide
        $s2 = "Content-Disposition: form-data; name=\"file\";" fullword ascii
        $s3 = "%sfilename=\"%ls\"" fullword ascii
        $s4 = "name=%ls&delete=" fullword ascii
        $s5 = "Content-Type: application/octet-stream" fullword ascii
        $s6 = "cmd.exe /C ping" wide
        $s7 = "& rmdir /Q /S \"" wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_JSSLoader {
    meta:
        author = "ditekSHen"
        description = "Detects JSSLoader RAT/backdoor"
    strings:
        $cmd1 = "Cmd_UPDATE" fullword ascii
        $cmd2 = "Cmd_IDLE" fullword ascii
        $cmd3 = "Cmd_EXE" fullword ascii
        $cmd4 = "Cmd_VBS" fullword ascii
        $cmd5 = "Cmd_JS" fullword ascii
        $cmd6 = "Cmd_PWS" fullword ascii
        $cmd7 = "Cmd_RAT" fullword ascii
        $cmd8 = "Cmd_UNINST" fullword ascii
        $cmd9 = "Cmd_RunDll" fullword ascii
        $s1 = "ANSWER_OK" fullword ascii
        $s2 = "GatherDFiles" ascii
        $s3 = "CommandCd" fullword ascii
        $s4 = "URL_GetCmd" fullword ascii
        $s5 = "\"host\": \"{0}\", \"domain\": \"{1}\", \"user\": \"{2}\"" wide
        $s6 = "pc_dns_host_name" wide
        $s7 = "\"adinfo\": { \"adinformation\":" wide
        $e1 = "//e:vbscript" wide
        $e2 = "//e:jscript" wide
        $e3 = "/c rundll32.exe" wide
        $e4 = "/C powershell" wide
        $e5 = "C:\\Windows\\System32\\cmd.exe" wide
        $e6 = "echo del /f" wide
        $e7 = "AT.U() {0}. format" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($cmd*) or 5 of ($s*) or all of ($e*) or 7 of them)
}

rule MALWARE_Win_CHUWI_Seth {
    meta:
        author = "ditekSHen"
        description = "Detects detected unknown RAT. Called CHUWI based on PDB, and promoted to Seth Ransomware."
        snort2_sid = "920103-920105"
        snort3_sid = "920101-920103"
        notes = "First sighting on 2020-01-05 didn't include ransomware artificats. Second sighting on 2020-01-24 with several correlations between the two samples now include ransomware artifacts."
    strings:
        // First sighting on 2020-01-05
        // No ransomware artifcats
        // 80104e0ad490b44a632a15e5875e7626db7f35fa94d7aadf19c45a621d75c7e0
        $cmd1 = "shell_command" fullword ascii
        $cmd2 = "check_command" fullword ascii
        $cmd3 = "down_exec" fullword ascii
        $cmd4 = "open_link" fullword ascii
        $cmd5 = "down_exec" fullword ascii
        $cmd6 = "exe_link" fullword ascii
        $cmd7 = "shellCommand" fullword ascii
        $cmd8 = "R_CMMAND" fullword ascii
        $cnc1 = "/check_command.php?HWID=" ascii
        $cnc2 = "&act=get_command" ascii
        $cnc3 = "/get_command.php?hwid=" ascii
        $cnc4 = "&command=down_exec" ascii
        $cnc5 = "&command=message" ascii
        $cnc6 = "&command=open_link" ascii
        $cnc7 = "&command=down_exec" ascii
        $cnc8 = "&command=shell" ascii
        $pdb = "\\Users\\CHUWI\\Documents\\CPROJ\\Downloader\\svchost" ascii

        // Second sighting on 2020-01-24
        // Includes ransomware artificats
        // 58c852525bf3bea185db34a79c2c5640c02f8291cdbdbe8dd7c0a9d4682f4b2c
        $rcnc1 = "inc/check_command.php" ascii
        $rcnc2 = "inc/get_command.php" ascii
        $rcnc3 = "php?btc" ascii
        $rcnc4 = "php?hwid" ascii
        $x1 = "> %USERPROFILE%\\Desktop\\HOW_DECRYPT_FILES.seth.txt" ascii
        $x2 = "/C dir /b %USERPROFILE%\\Documents > %temp%\\doc.txt" ascii
        $x3 = "/C dir /b %USERPROFILE%\\Desktop > %temp%\\desk.txt" ascii
        $x4 = "/C dir /b %USERPROFILE%\\Downloads > %temp%\\downs.txt" ascii
        $x5 = "/C dir /b %USERPROFILE%\\Pictures > %temp%\\pics.txt" ascii
        $x6 = "for /F \"delims=\" %%a in ('mshta.exe \"%~F0\"') do set \"HTA=%%a\"" ascii
        $x7 = "\\svchost.exe" fullword ascii
        $x8 = ".seth" fullword ascii
        $x9 = "MyAgent" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ($pdb or 5 of ($cmd*) or 4 of ($cnc*) or all of ($rcnc*) or 5 of ($x*) or 8 of them)
}

rule MALWARE_Win_Gulpix {
    meta:
        author = "ditekSHen"
        description = "Detects Gulpix/HyperPlus backddor"
    strings:
        $x1 = "MainServer.dll" fullword ascii
        $x2 = "NvSmartMax.dat" fullword wide
        $x3 = "NvSmartMax.dll" fullword wide
        $x4 = "http://+:80/FD873AC4-CF86-4FED-84EC-4BD59C6F17A7/" fullword wide
        $s1 = "IP retriever" fullword wide
        $s2 = "\\cmd.exe" fullword wide
        $s3 = "\\msnetwork-cache.db" fullword wide
        $s4 = "http://+:" wide
        $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" fullword wide
        // UAC Bypass
        $s6 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii
        $s7 = "Got a unknown request for %ws" wide
        $s8 = "HttpReceiveRequestEntityBody failed with %lu" wide
        $s9 = "FD873AC4-CF86-4FED-84EC-4BD59C6F17A7" wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 6 of ($s*) or (2 of ($x*) and 4 of ($s*)) or
             (
                 2 of them and 
                 pe.exports("daemon") and 
                 pe.exports("run") and 
                 pe.exports("session") and 
                 pe.exports("work")
            )
        )
}

rule MALWARE_Linux_RansomExx {
    meta:
        author = "ditekshen"
        description = "Detects RansomEXX ransomware"
        clamav_sig = "MALWARE.Linux.Ransomware.RansomEXX"
    strings:
        $c1 = "crtstuff.c" fullword ascii
        $c2 = "cryptor.c" fullword ascii
        $c3 = "ransomware.c" fullword ascii
        $c4 = "logic.c" fullword ascii
        $c5 = "enum_files.c" fullword ascii
        $c6 = "readme.c" fullword ascii
        $c7 = "ctr_drbg.c" fullword ascii
        
        $s1 = "regenerate_pre_data" fullword ascii
        $s2 = "g_RansomHeader" fullword ascii
        $s3 = "CryptOneBlock" fullword ascii
        $s4 = "RansomLogic" fullword ascii
        $s5 = "CryptOneFile" fullword ascii
        $s6 = "encrypt_worker" fullword ascii
        $s7 = "list_dir" fullword ascii
        $s8 = "ctr_drbg_update_internal" fullword ascii
    condition:
        uint16(0) == 0x457f and (5 of ($s*) or 6 of ($s*) or (3 of ($c*) and 3 of ($s*)))
}

rule MALWARE_Win_TrickbotModule {
    meta:
        author = "ditekshen"
        description = "Detects Trickbot modules"
    strings:
        $mc = "<moduleconfig>" ascii
        $s1 = "<autostart>" ascii
        $s2 = "<nohead>" ascii
        $s3 = "<needinfo" ascii
        $s4 = "<conf ctl" ascii
        $s5 = "<limit>" ascii
        $w1 = "<sys>yes</sys>" ascii
        $w2 = "<sys>no</sys>" ascii
        $w3 = "<autostart>yes</autostart>" ascii
        $w4 = "<autostart>no</autostart>" ascii
        $w5 = "<nohead>yes</nohead>" ascii
        $w6 = "<nohead>no</nohead>" ascii
        $w7 = /<limit>\d+<\/limit>/ ascii
        $w8 = "<moduleconfig> </moduleconfig" ascii
    condition:
        uint16(0) == 0x5a4d and $mc and (2 of ($s*) or (1 of ($s*) and 1 of ($w*)) or 1 of ($w*))
}

rule MALWARE_Win_Gaudox {
    meta:
        author = "ditekshen"
        description = "Detects Gaudox RAT"
    strings:
        $s1 = "hdr=%s&tid;=%s&cid;=%s&trs;=%i" ascii wide
        $s2 = "\\\\\\\\.\\\\PhysicalDrive%u" ascii wide
        //$s3 = "Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Phobos {
    meta:
        author = "ditekshen"
        description = "Detects Phobos ransomware"
    strings:
        $x1 = "\\\\?\\UNC\\\\\\e-" fullword wide
        $x2 = "\\\\?\\ :" fullword wide
        $x3 = "POST" fullword wide
        $s1 = "ELVL" fullword wide
        $s2 = /SUP\d{3}/ fullword wide
        $s3 = { 41 31 47 ?? 41 2b }
    condition:
        uint16(0) == 0x5a4d and all of ($x*) and 1 of ($s*)
}

rule MALWARE_Win_Ratty {
    meta:
        author = "ditekshen"
        description = "Detects Ratty Java RAT"
    strings:
        $s1 = "/rat/RattyClient.class" ascii
        $s2 = "/rat/ActiveConnection.class" ascii
        $s3 = "/rat/attack/" ascii
        $s4 = "/rat/gui/swing/Ratty" ascii
        $s5 = "/rat/packet/PasswordPacket" ascii
        $s6 = "/rat/packet/" ascii
        $e1 = "/engine/Keyboard.class" ascii
        $e2 = "/engine/IMouseListener.class" ascii
        $e3 = "/engine/Screen$ResizeBehavior.class" ascii
        $e4 = "/engine/fx/ISoundListener.class" ascii
        $e5 = "/engine/net/TCPServer.class"  ascii
        $e6 = "/engine/noise/PerlinNoise.class" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 or uint16(0) == 0x4b50) and (3 of ($s*) or all of ($e*))
}

rule MALWARE_Win_FatDuke {
    meta:
        author = "ditekSHen"
        description = "Detects FatDuke"
    strings:
        $s1 = "\\\\?\\Volume" fullword ascii
        $s2 = "WINHTTP_AUTOPROXY_OPTIONS@@PAUWINHTTP_PROXY_INFO@@" ascii
        $s3 = "WINHTTP_CURRENT_USER_IE_PROXY_CONFIG@@" ascii
        $s4 = "Cannot write a Cannot find the too long string mber of records Log malfunction! Cannot create ain an invalid ra Internal sync iright function iWaitForSingleObjffsets" ascii
        $pattern = "()$^.*+?[]|\\-{},:=!" ascii
        $b64 = "eyJjb25maWdfaWQiOi" wide
        //$decoded = "{\"config_id\"" base64wide
    condition:
        //uint16(0) == 0x5a4d and (3 of ($s*) or (($b64 or $decoded) and 2 of them) or (#pattern > 3 and 2 of them))
        uint16(0) == 0x5a4d and (3 of ($s*) or ($b64 and 2 of them) or (#pattern > 3 and 2 of them))
}

rule MALWARE_Win_MiniDuke {
    meta:
        author = "ditekSHen"
        description = "Detects MiniDuke"
    strings:
        $s1 = "DefPipe" fullword ascii
        $s2 = "term %5d" fullword ascii
        $s3 = "pid %5d" fullword ascii
        $s4 = "uptime %5d.%02dh" fullword ascii
        $s5 = "login: %s\\%s" fullword ascii
        $s6 = "Software\\Microsoft\\ApplicationManager" ascii
        $s7 = { 69 64 6c 65 ?? 00 73 74 6f 70 ?? 00 61 63 63 65 70 74 ?? 00 63 6f 6e 6e 65 63 74 ?? 00 6c 69 73 74 65 6e ?? 00 }

        $net1 = "salesappliances.com" ascii
        $net2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36" fullword ascii
        $net3 = "http://10." ascii
        $net4 = "JiM9t8g7j8KoJkLJlKqka8dbo7q5z4v5u3o4z" ascii
        $net5 = "application/octet-stream" ascii
        $net6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 4 of ($net*) or 7 of them)
}

rule MALWARE_Win_PolyglotDuke {
    meta:
        author = "ditekSHen"
        description = "Detects PolyGlotDuke"
    strings:
        $s1 = { 48 b9 ff ff ff ff ff ff ff ff 51 48 23 8c 24 ?? 00 00 00 48 89 8C 24 00 00 00 00 }
        $s2 = { 56 be ff ff ff ff 56 81 e6 7f }
        $s3 = { 48 8b 05 19 ?4 4b 00 48 05 48 83 00 00 4c 8b 44 24 50 8b 54 24 48 48 8b }
        //$s4 = { 48 8B 84 24 ?? 00 00 00 48 ?? ?? 24 ?? 00 00 00 48 89 84 24 }
    condition:
        uint16(0) == 0x5a4d and (all of ($s*)) or
         (
                 2 of them and 
                 pe.exports("InitSvc")
        )
}

rule MALWARE_Win_Guidlma {
    meta:
        author = "ditekSHen"
        description = "Detects Guildma"
    strings:
        $v1_1 = "marxvxinhhm98.dll" fullword wide
        $v1_2 = "marxvxinhhmxa.gif" fullword wide
        $v1_3 = "marxvxinhhmxb.gif" fullword wide
        $v1_4 = "c:\\programdata" fullword wide
        $v1_5 = "\\tempa\\" fullword wide
        $v2_1 = "C:\\Windows\\System32\\dllhost.exe" fullword ascii
        $v2_2 = "C:\\Windows\\SysWOW64\\dllhost.exe" fullword ascii
        $v2_3 = "C:\\Users\\Public\\go" fullword ascii
        $v2_4 = ":%:*:/:>:C:H:W:\\:a:p:u:z:" fullword ascii
        $v2_5 = ": :%:*:9:>:C:R:W:\\:k:p:u:" fullword ascii
        $v2_6 = ":*:/:4:C:H:M:\\:a:f:u:z:" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($v1*) or 5 of ($v2*)
}

rule MALWARE_Win_CyberGate {
    meta:
        author = "ditekSHen"
        description = "Detects CyberGate/Spyrat/Rebhip RTA"
    strings:
        $s1 = "UnitInjectLibrary" ascii
        $s2 = "TLoader" fullword ascii
        $s3 = "\\\\.\\SyserDbgMsg" fullword ascii
        $s4 = "\\\\.\\SyserBoot" fullword ascii
        $s5 = "\\signons" ascii
        $s6 = "####@####" ascii
        $s7 = "XX-XX-XX-XX" fullword ascii
        $s8 = "EditSvr" ascii
        $s9 = "_x_X_PASSWORDLIST_X_x_" fullword ascii
        $s10 = "L$_RasDefaultCredentials#0" fullword ascii
        $s11 = "password" nocase ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_WSHRATJS {
    meta:
        author = "ditekSHen"
        description = "Detects WSHRAT JS variants"
    strings:
        $charset_full = "us-ascii" nocase ascii
        $charset_begin = "\"us-\"" nocase ascii
        $charset_end = "Array(97,115,99,105,105)" nocase ascii
        $wsc_object1 = "WScript.CreateObject(\"System.Text.UTF8Encoding" nocase ascii
        $wsc_object2 = "WScript.CreateObject(\"Adodb.Stream" nocase ascii
        $wsc_object3 = "WScript.CreateObject(\"Microsoft.XmlDom" nocase ascii
        $s1 = "function(){return" ascii
        $s2 = "}catch(err){" ascii
        $s3 = "{item: \"bin.base64\"}" nocase ascii
        $s4 = "* 1].item =" ascii
    condition:
        filesize < 400KB and ($charset_full or ($charset_begin and $charset_end)) and 2 of ($wsc_object*) and 3 of ($s*)
}

rule MALWARE_Win_AsyncRAT {
    meta:
        author = "ditekSHen"
        description = "Detects AsyncRAT"
    strings:
        $x1 = "AsyncRAT" fullword ascii
        $x2 = "AsyncRAT 0." wide
        $x3 = /AsyncRAT\s[0-9]\.[0-9]\.[0-9][A-Z]/ fullword wide

        $s1 = "/create /sc onlogon /rl highest /tn" fullword wide
        $s2 = "/C choice /C Y /N /D Y /T 1 & Del \"" fullword wide
        $s3 = "{{ ProcessId = {0}, Name = {1}, ExecutablePath = {2} }}" fullword wide
        $s4 = "Stub.exe" fullword ascii wide
        $s5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" ascii wide
        $s6 = "VirtualBox" fullword ascii wide
        $s7 = "/target:winexe /platform:x86 /optimize+" fullword ascii wide
        $s8 = "Win32_ComputerSystem" ascii wide
        $s9 = "Win32_Process Where ParentProcessID=" ascii wide
        $s10 = "etirWgeR.llehShsW" ascii wide
        $s11 = "usbSpread" fullword ascii wide

        $cnc1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword ascii wide
        $cnc2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" fullword ascii wide
        $cnc3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii wide
        $cnc4 = "POST / HTTP/1.1" fullword ascii wide
    condition:
        ((uint16(0) == 0x5a4d and filesize < 4000KB) and (1 of ($x*) or 6 of ($s*) or all of ($cnc*) or (4 of ($s*) and 2 of ($cnc*)))) or (1 of ($x*) or 6 of ($s*) or all of ($cnc*) or (4 of ($s*) and 2 of ($cnc*)))
}

rule MALWARE_Win_QuilClipper {
    meta:
        author = "ditekSHen"
        description = "Detects QuilClipper variants mostly in memory or extracted AutoIt script"
    strings:
        $cnc1 = "QUILCLIPPER by" ascii
        $cnc2 = "/ UserName:" ascii
        $cnc3 = "/ System:" ascii
        $s1 = "DLLCALL ( \"kernel32.dll\" , \"handle\" , \"CreateMutexW\" , \"struct*\"" ascii
        $s2 = "SHELLEXECUTE ( @SCRIPTFULLPATH , \"\" , \"\" , FUNC_" ascii
        $s3 = "CASE BITROTATE" ascii
        $s4 = "CASE BITXOR" ascii
        $s5 = "CLIP( FUNC_" ascii
        $s6 = "CLIPPUT (" ascii
        $s7 = "FUNC _CLIPPUTFILE(" ascii
        $s8 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Schedule" ascii
    condition:
        all of ($cnc*) or all of ($s*)
}

rule MALWARE_Win_SpyEye {
    meta:
        author = "ditekSHen"
        description = "Detects SpyEye"
    strings:
        $x1 = "_CLEANSWEEP_" ascii wide
        $x2 = "config.datUT" fullword ascii
        $x3 = "webinjects.txtUT" fullword ascii
        $s1 = "confirm:processCommand" fullword ascii
        $s2 = "Smth wrong with navigate to REF-PAGE (err code: %d). 0_o" fullword ascii
        $s3 = "(UTC%s%2.2f) %s" fullword wide
        $s4 = "M\\F;u`r" fullword ascii
        $s5 = "]YH0%Yn" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 1 of ($s*)))
}

// requires Yara v4.0.2+
rule MALWARE_Win_Renamer {
    meta:
        author = "ditekSHen"
        description = "Detects Renamer/Tainp variants"
    strings:
        $s1 = "shell\\open\\command=" fullword wide
        $s2 = "icon=%SystemRoot%\\system32\\SHELL32.dll,4" fullword wide
        $s3 = "DropTarget" ascii
        $s4 = "C:\\Windows\\Paint" fullword wide
        $s5 = "hold.inf" fullword wide
        $s6 = "Dropped" ascii
    condition:
        uint16(0) == 0x5a4d and all of ($s*) or 
        (
            4 of ($s*) and
            for any directory in pe.data_directories : 
            (
                directory.virtual_address != 0 and
                directory.size == 0
            )
        )
}

rule MALWARE_Win_Epsilon {
    meta:
        author = "ditekSHen"
        description = "Detects Epsilon ransomware"
    strings:
        $s1 = ".Speak \"" wide
        $s2 = "chkUpdateRegistry" fullword wide
        $s3 = "/C choice /C Y /N /D Y /T 1 & Del \"" fullword wide
        $s4 = "CreateObject(\"sapi.spvoice\")" fullword wide
        $s5 = "READ_ME.hta" wide
        $s6 = "WScript.Sleep(" wide
        $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
        $s8 = "<div class='bold'>Files are encrypted* but not deleted.</div>" ascii
        $e1 = { 72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00
                78 00 65 00 00 09 2e 00 74 00 78 00 74 00 00 09
                2e 00 64 00 6f 00 63 00 00 0b 2e 00 64 00 6f 00
                63 00 78 00 00 09 2e 00 78 00 6c 00 73 00 00 0d
                2e 00 69 00 6e 00 64 00 65 00 78 00 00 09 2e 00
                70 00 64 00 66 00 00 09 2e 00 7a 00 69 00 70 00
                00 09 2e 00 72 00 61 00 72 00 00 09 2e 00 63 00
                73 00 73 00 00 09 2e 00 6c 00 6e 00 6b 00 00 0b
                2e 00 78 00 6c 00 73 00 78 00 00 09 2e 00 70 00
                70 00 74 00 00 0b 2e 00 70 00 70 00 74 00 78 00
                00 09 2e 00 6f 00 64 00 }
        $e2 = { 68 00 74 00 6d 00 00 07 2e 00 6d 00 6c 00 00 07
                43 00 3a 00 5c 00 00 07 44 00 3a 00 5c 00 00 07
                45 00 3a 00 5c 00 00 07 46 00 3a 00 5c 00 00 07
                47 00 3a 00 5c 00 00 07 5a 00 3a 00 5c 00 00 07
                41 00 3a 00 5c 00 00 0f 63 00 6d 00 64 00 2e 00
                65 00 78 00 65 }
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (all of ($e*) and 4 of ($s*)))
}

rule MALWARE_Win_CoreBot {
    meta:
        author = "ditekSHen"
        description = "Detects CoreBot"
        snort_sid = "920211-920212"
    strings:
        $f1 = "core.cert_fp" fullword ascii
        $f2 = "core.crash_handler" fullword ascii
        $f3 = "core.delay" fullword ascii
        $f4 = "core.guid" fullword ascii
        $f5 = "core.inject" fullword ascii
        $f6 = "core.installed_file" fullword ascii
        $f7 = "core.plugins_dir" fullword ascii
        $f8 = "core.plugins_key" fullword ascii
        $f9 = "core.safe_mode" fullword ascii
        $f10 = "core.server" fullword ascii
        $f11 = "core.servers" fullword ascii
        $f12 = "core.test_env" fullword ascii
        $f13 = "core.vm_detect" fullword ascii
        $f14 = "core.vm_detect_skip" fullword ascii
        $s1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko" fullword wide
        $s2 = "\\Microsoft\\Windows\\AppCache" wide
        $s3 = "crash_flag" fullword wide
        $s4 = "container.dat" fullword wide
        $s5 = "INJECTED" fullword ascii
        $s6 = "tmp.delete_file" fullword ascii
        // variant
        $x1 = "CoreBot v" wide
        $x2 = "BotName" fullword ascii
        $x3 = "RunBotKiller" fullword ascii
        $x4 = "botv" fullword ascii
        $x5 = "\\CoreBot\\CoreBot\\obj\\" ascii
        $v1_1 = "newtask" fullword wide
        $v1_2 = "drivers\\etc\\hosts" fullword wide
        $v1_3 = "/C schtasks /create /tn \\" wide
        $v1_4 = "/st 00:00 /du 9999:59 /sc once /ri 1 /f" wide
        $v1_5 = "AntivirusInstalled" fullword ascii
        $v1_6 = "payload" fullword ascii
        $v1_7 = "DownloadFile" fullword ascii
        $v1_8 = "RemoveFile" fullword ascii
        $v1_9 = "AutoRunName" fullword ascii
        $v1_10 = "EditHosts" fullword ascii
        $v1_11 = /127\.0\.0\.1 (avast|mcafee|eset|avira|bitdefender|bullguard|safebrowse)\.com/ fullword wide
        $cnc1 = "&os=" fullword wide
        $cnc2 = "&pv=" fullword wide
        $cnc3 = "&ip=" fullword wide
        $cnc4 = "&cn=" fullword wide
        $cnc5 = "&lr=" fullword wide
        $cnc6 = "&ct=" fullword wide
        $cnc7 = "&bv=" fullword wide
        $cnc8 = "&op=" fullword wide
        $cnc9 = "&td=" fullword wide
        $cnc10 = "&uni=" fullword wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($f*) or all of ($s*) or (3 of ($s*) and 2 of ($f*)) or 3 of ($x*) or 8 of ($v1*) or (4 of ($cnc*) and 4 of ($v1*)) or 12 of them)
}

rule MALWARE_Win_DLLLoader {
    meta:
        author = "ditekSHen"
        description = "Detects unknown DLL Loader"
    strings:
        $s1 = "LondLibruryA" fullword ascii
        $s2 = "LdrLoadDll" fullword ascii
        $s3 = "snxhk.dll" fullword ascii
        $s4 = "DisableThreadLibraryCalls" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Farfli {
    meta:
        author = "ditekSHen"
        description = "Detects Farfli backdoor"
    strings:
        $s1 = "%ProgramFiles%\\Google\\" fullword ascii
        $s2 = "%s\\%d.bak" fullword ascii
        $s3 = "%s Win7" fullword ascii
        $s4 = "%s:%d:%s" fullword ascii
        $s5 = "C:\\2.txt" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Warezov {
    meta:
        author = "ditekSHen"
        description = "Detects Warezov worm/downloader"
    strings:
        $s1 = "ft\\Windows\\CurrentVersion\\Run" wide
        $s2 = "DIR%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s3 = "%WINDIR%\\sqhos32.wmf" wide
        $s4 = "Accept: */*" fullword ascii
        $s5 = "Range: bytes=" fullword ascii
        $s6 = "module.exe" fullword ascii
        $s7 = { 25 73 25 73 2e 25 73 ?? ?? 22 22 26 6c 79 79 56 00 00 00 00 25 73 25 30 34 64 25 30 32 64 25 30 32 64 00 }
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_Arechclient2 {
    meta:
        author = "ditekSHen"
        description = "Detects Arechclient2 RAT"
    strings:
        $s1 = "\\Google\\Chrome\\User Data\\copiedProf\"" wide
        $s2 = "\",\"BotName\":\"" wide
        $s3 = "\",\"BotOS\":\"" wide
        $s4 = "\",\"URLData\":\"" wide
        $s5 = "{\"Type\":\"ConnectionType\",\"ConnectionType\":\"Client\",\"SessionID\":\"" wide
        $s6 = "{\"Type\":\"TestURLDump\",\"SessionID\":\"" wide
        $s7 = "<ReceiveParticipantList>" ascii
        $s8 = "<potocSkr>" ascii
        $s9 = "fuck_sd" fullword ascii
        $s10 = "HandleBotKiller" fullword ascii
        $s11 = "RunBotKiller" fullword ascii
        $s12 = "ConnectToServer" fullword ascii
        $s13 = "KillBrowsers" fullword ascii
        $s14 = "keybd_event" fullword ascii
        $s15 = "FuckCodeImg" fullword ascii
        $v1_1 = "grabber@" fullword ascii
        $v1_2 = "<BrowserProfile>k__" ascii
        $v1_3 = "<SystemHardwares>k__" ascii
        $v1_4 = "<geoplugin_request>k__" ascii
        $v1_5 = "<ScannedWallets>k__" ascii
        $v1_6 = "<DicrFiles>k__" ascii
        $v1_7 = "<MessageClientFiles>k__" ascii
        $v1_8 = /<Scan(Browsers|Wallets|Screen|VPN)>k__BackingField/ fullword ascii
        $v1_9 = "displayName[AString-ZaString-z\\d]{2String4}\\.[String\\w-]{String6}\\.[\\wString-]{2String7}Local Extension Settingshost" wide
        $v1_10 = "\\sitemanager.xml MB or SELECT * FROM Cookiesconfig" wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or 7 of ($v1*) or (6 of ($v1*) and 1 of ($s*)))
}

rule MALWARE_Win_KillMBR {
    meta:
        author = "ditekSHen"
        description = "Detects KillMBR"
    strings:
        $s1 = "\\\\.\\PhysicalDrive" ascii
        $s2 = "/logger.php" ascii
        $s3 = "Ooops! Your MBR was been rewritten" ascii
        $s4 = "No, this ransomware dont encrypt your files, erases it" ascii
    condition:
        uint16(0) == 0x5a4d and (2 of them and #s1 > 10)
}

rule MALWARE_Win_LCPDot {
    meta:
        author = "ditekSHen"
        description = "Detects LCPDot"
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
        $s2 = "Cookie: SESSID=%s" fullword ascii
        $s3 = "Cookie=Enable" fullword ascii
        $s4 = "Cookie=Enable&CookieV=%d&Cookie_Time=32" fullword ascii
        $s5 = ".?AVTShellCodeRuner@@" fullword ascii
        $s6 = ".?AVTHashEncDecoder@@" fullword ascii
        $s7 = ".?AVTWebAddressList@@" fullword ascii
        $s8 = "WinMain.dll" fullword ascii
        $s9 = "HotPlugin" wide
        $o0 = { 4c 89 6c 24 08 4c 89 34 24 44 8d 77 01 44 8d 6f }
        $o1 = { 8b f0 e8 58 34 00 00 48 8b f8 48 85 c0 74 0c 48 }
        $o2 = { c7 44 24 30 47 49 46 38 c7 44 24 34 39 61 27 00 }
    condition:
        uint16(0) == 0x5a4d and 6 of ($s*) or (all of ($o*) and 3 of ($s*))
}

rule MALWARE_Win_Torisma {
    meta:
        author = "ditekSHen"
        description = "Detects Torisma"
    strings:
        $s1 = "ACTION=PREVPAGE&CODE=C%s&RES=%d" fullword ascii
        $s2 = "ACTION=VIEW&PAGE=%s&CODE=%s&CACHE=%s&REQUEST=%d" fullword ascii
        $s3 = "ACTION=NEXTPAGE&CODE=S%s&CACHE=%s&RES=%d" fullword ascii
        $s4 = "Your request has been accepted. ClientID: {" ascii
        $s5 = "Proxy-Connection: Keep-Alive" fullword wide
        $s6 = "Content-Length: %d" fullword wide
        $o0 = { f7 f9 8b c2 89 44 24 34 48 63 44 24 34 48 8b 4c }
        $o1 = { 48 c7 00 ff ff ff ff 48 8b 84 24 90 }
        $o2 = { f3 aa 83 7c 24 30 01 75 34 c7 44 24 20 01 }
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (all of ($o*) and 3 of ($s*))
}

rule MALWARE_Win_Thanos {
    meta:
        author = "ditekSHen"
        description = "Detects Thanos / Prometheus / Spook ransomware"
    strings:
        $f1 = "<WorkerCrypter2>b__" ascii
        $f2 = "<Encrypt2>b__" ascii
        $f3 = "<Killproc>b__" ascii
        $f4 = "<GetIPInfo>b__" ascii
        $f5 = "<MacAddress>k__" ascii
        $f6 = "<IPAddress>k__" ascii
        $f7 = "<Crypt>b__" ascii
        $s1 = "Aditional KeyId:" wide
        $s2 = "process call create cmd.exe /c \\\\" wide
        $s3 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide
        $s4 = "\\HOW_TO_DECYPHER_FILES." wide
        $s5 = "Client Unique Identifier Key:" wide
        $s6 = "/s /f /q c:\\*.VHD c:\\*.bac c:\\*.bak c:\\*.wbcat c:\\*.bkf c:\\Backup*.* c:\\backup*.* c:\\*.set c:\\*.win c:\\*.dsk" fullword wide
        $s7 = "NtOpenProcess" fullword wide
        $s8 = "Builder_Log" fullword wide
        $s9 = "> Nul & fsutil file setZeroData offset=0 length=" wide
        $s10 = "3747bdbf-0ef0-42d8-9234-70d68801f407" wide // mutex
        $s11 = "4b195894-0f06-4fdd-afb4-b17fb9246a59" wide
        $s12 = "cec564ff-2433-4771-b918-15f58ef6e26c" wide
        $s13 = "56258a19-7489-468b-86ee-e7899203d67c" wide
        $s14 = "WalkDirectoryTree" fullword ascii
        $s15 = "hashtableLock" fullword ascii
        $s16 = "get_ParentFrn" fullword ascii
        $m1 = "SW5mb3JtYXRpb24uLi" wide
        $m2 = "QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($f*) or 5 of ($s*) or (4 of ($f*) and 2 of ($s*) or (all of ($m*) and 3 of them)) or 8 of them)
}

rule MALWARE_Win_TManager {
    meta:
        author = "ditekSHen"
        description = "Detects TManager RAT. Associated with TA428"
    strings:
        $s1 = "WSAStartup Error!" fullword wide
        $s2 = "KB3112342.LOG" fullword wide
        $s3 = "\\cmd.exe -c" fullword wide
        $s4 = "sock_hmutex" fullword wide
        $s5 = "cmd_hmutex" fullword wide
        $s6 = "powershell" fullword wide
        $s7 = "%s_%d.bmp" fullword wide
        $s8 = "!Error!" fullword wide
        $s9 = "[Execute]" fullword ascii
        $s10 = "[Snapshot]" fullword ascii
        $s11 = "GetLanIP error!" fullword ascii
        $s12 = "chcp & exit" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_Sn0wLogger {
    meta:
        author = "ditekSHen"
        description = "Detects Sn0w Logger"
    strings:
        $s1 = "\\SnowP\\Example\\Secured\\" ascii
        $s2 = "{0}{3}Content-Type: {4}{3}Content-Disposition: form-data; name=\"{1}\"{3}{3}{2}{3}" wide
        $s3 = "\"encrypted_key\":\"(.*?)\"" fullword wide
        $s4 = "<SendToDiscord>d__" ascii
        $s5 = "_urlWebhook" ascii
        $r1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" fullword wide
        $r2 = "^\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*$" fullword wide
        $r3 = "mfa\\.[\\w-]{84}" fullword wide
        $r4 = "(\\w+)=(\\d+)-(\\d+)$" fullword wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (all of ($r*) and 2 of ($s*)) or 7 of them)
}

rule MALWARE_Win_DanaBot {
    meta:
        author = "ditekSHen"
        description = "Detects DanaBot variants"
    strings:
        $s1 = "ms ie ftp passwords" fullword wide
        $s2 = "CookieEntryEx_" fullword wide
        $s3 = "winmgmts:\\\\localhost\\root\\cimv2" fullword wide
        $s4 = "S-Password.txt" fullword wide
        $s5 = "del_ini://Main|Password|" fullword wide
        $s6 = "cmd.exe /c start chrome.exe --no-sandbox" wide
        $s7 = "cmd.exe /c start firefox.exe -no-remote" wide
        $s8 = "\\rundll32.exe shell32.dll,#" wide
        $s9 = "S_Error:TORConnect" wide
        $s10 = "InjectionProcess" fullword ascii
        $s11 = "proxylogin" fullword wide
        $s12 = "\\FS_Morff\\FS_Temp\\" wide
        $ds1 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $ds2 = "PExtended4" fullword ascii
        $ds3 = "%s-%s" fullword wide
        $ds4 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF0123456789ABCDEF" fullword wide
        //$o1 = { 55 8b ec 33 c0 55 68 d7 60 4f 00 64 ff 30 64 89 }
        //$o2 = { e8 45 ec f0 ff e8 3c e2 f0 ff 68 00 04 00 00 e8 }
        //$o3 = { e8 98 3a f2 ff 84 c0 74 0a 8d 44 24 0c 50 e8 fe }
        //$o4 = { ba 80 d7 4f 00 a1 54 90 4f 00 e8 7e 4a f1 ff e9 }
        //$o5 = { 80 bc 24 4a 01 00 00 01 75 14 ba 80 d7 4f 00 a1 }
        //$o6 = { ba 80 d7 4f 00 a1 80 8f 4f 00 e8 4c 4a f1 ff e9 }
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or all of ($ds*))
}

rule MALWARE_Win_Klackring {
    meta:
        author = "ditekSHen"
        description = "Detects Klackring variants. Associated with ZINC / Lazarus"
    strings:
        $s1 = "%s\\%s.dll" fullword wide
        $s2 = "cmd.exe /c move /Y %s %s" fullword wide
        $s3 = "%s\\win32k.sys" fullword wide
        $s4 = "NetSvcInst_Rundll32.dll" fullword ascii
        $s5 = "Spectrum.dll" fullword ascii wide
        $s6 = "%s\\cmd.exe" fullword wide
        $s7 = ".?AVA5Stream@@" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_ComeBacker {
    meta:
        author = "ditekSHen"
        description = "Detects ComeBacker variants. Associated with ZINC / Lazarus"
    strings:
        $s1 = "ENGINE_get_RAND" ascii
        $s2 = "./{IES" fullword ascii
        $s3 = "TODO: <Company name>" fullword wide
        $s4 = "@Microsoft Corperation. All rights reserved." fullword wide
        $s5 = "Microsoft@Windows@Operating System" fullword wide
        $x1 = "C:\\Windows\\System32\\rundll32.exe %s,%s %s %s" fullword ascii wide
        $x2 = "ASN2_TYPE_new" fullword ascii wide
        $x3 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($x*))
}

rule MALWARE_Win_SunCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects SunCrypt ransomware"
    strings:
        $s1 = "-noshares" fullword wide
        $s2 = "-nomutex" fullword wide
        $s3 = "-noreport" fullword wide
        $s4 = "-noservices" fullword wide
        $s5 = "$Recycle.bin" fullword wide
        $s6 = "YOUR_FILES_ARE_ENCRYPTED.HTML" fullword wide
        $s7 = "\\\\?\\%c:" fullword wide
        $s8 = "locker.exe" fullword ascii
        $s9 = "DllRegisterServer" fullword ascii
        $g1 = "main.EncFile" fullword ascii nocase
        $g2 = "main.detectName" fullword ascii nocase
        $g3 = "main.detectIP" fullword ascii nocase
        $g4 = "main.detectDebugProc" fullword ascii nocase
        $g5 = "main.Bypass" ascii nocase
        $g6 = "main.allocateMemory" fullword ascii nocase
        $g7 = "main.killAV" fullword ascii nocase
        $g8 = "main.disableShadowCopy" fullword ascii nocase
        $g9 = "main.(*windowsDrivesModel).LoadDrives" fullword ascii nocase
        $g10 = "main.IsFriends" fullword ascii nocase
        $g11 = "main.walkMsg" fullword ascii nocase
        $g12 = "main.makeSecretMessage" fullword ascii nocase
        $g13 = "main.stealFiles" fullword ascii nocase
        $g14 = "main.newKey" fullword ascii nocase
        $g15 = "main.openBrowser" fullword ascii nocase
        $g16 = "main.killProc" fullword ascii nocase
        $g17 = "main.selfRemove" fullword ascii nocase
        $m1 = "<h2>\\x20Offline\\x20HowTo\\x20</h2>\\x0a\\x09\\x09\\x09\\x09<p>Copy\\x20&\\x20Paste\\x20this\\x20message\\x20to" ascii
        $m2 = "\\x20restore\\x20your\\x20files." ascii
        $m3 = "\\x20your\\x20documents\\x20and\\x20files\\x20encrypted" ascii
        $m4 = "\\x20lose\\x20all\\x20of\\x20your\\x20data\\x20and\\x20files." ascii
        $m5 = ",'/#/client/','<h2>\\x20Whats\\x20Happen" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 6 of ($g*) or 3 of ($m*))
}

rule MALWARE_Win_Zegost {
    meta:
        author = "ditekSHen"
        description = "Detects Zegost"
    strings:
        $s1 = "rtvscan.exe" fullword ascii
        $s2 = "ashDisp.exe" fullword ascii
        $s3 = "KvMonXP.exe" fullword ascii
        $s4 = "egui.exe" fullword ascii
        $s5 = "avcenter.exe" fullword ascii
        $s6 = "K7TSecurity.exe" fullword ascii
        $s7 = "TMBMSRV.exe" fullword ascii
        $s8 = "RavMonD.exe" fullword ascii
        $s9 = "kxetray.exe" fullword ascii
        $s10 = "mssecess.exe" fullword ascii
        $s11 = "QUHLPSVC.EXE" fullword ascii
        $s12 = "360tray.exe" fullword ascii
        $s13 = "QQPCRTP.exe" fullword ascii
        $s14 = "knsdtray.exe" fullword ascii
        $s15 = "V3Svc.exe" fullword ascii
        $s16 = "??1_Winit@std@@QAE@XZ" fullword ascii
        $s17 = "ClearEventLogA" fullword ascii
        $s18 = "SeShutdownPrivilege" fullword ascii
        $s19 = "%s\\shell\\open\\command" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_GENERIC01 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables, mostly DLLs"
    strings:
        $s1 = "\\wmkawe_%d.data" ascii
        $s2 = "\\resmon.resmoncfg" ascii
        $s3 = "ByPassUAC" fullword ascii
        $s4 = "rundll32.exe C:\\ProgramData\\Sandboxie\\SbieMsg.dll,installsvc" fullword ascii nocase
        $s5 = "%s\\SbieMsg." ascii
        $s6 = "Stupid Japanese" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_GENERIC02 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables"
    strings:
        $s1 = "{%s-%d-%d}" fullword wide
        $s2 = "update" fullword wide
        $s3 = "https://" fullword wide
        $s4 = "http://" fullword wide
        $s5 = "configure" fullword ascii
        $s6 = { 8d 4f 02 e8 8c ff ff ff 8b d8 81 fb 00 dc 00 00 }
        $s7 = { 83 c1 02 e8 3c ff ff ff 8b c8 ba ff 03 00 00 8d }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_DLAgent06 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches"
      snort2_sid = "920122"
      snort3_sid = "920119"
    strings:
        $s1 = "totallist" fullword ascii wide
        $s2 = "LINKS_HERE" fullword wide
        $s3 = "[SPLITTER]" fullword wide
        $var2_1 = "DownloadWeb" fullword ascii
        $var2_2 = "WriteByte" fullword ascii
        $var2_3 = "MemoryStream" fullword ascii
        $var2_4 = "DownloadString" fullword ascii
        $var2_5 = "WebClient" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and 2 of ($var2*)) or (4 of ($var2*) and 2 of ($s*)))
}

rule MALWARE_Win_PWSH_PoshKeylogger {
    meta:
      author = "ditekSHen"
      description = "Detects PowerShell PoshKeylogger"
    strings:
        $s1 = "::GetKeyboardState" ascii
        $s2 = "GetAsyncKeyState(" ascii
        $s3 = "::MapVirtualKey(" ascii
        $s4 = "::GetAsyncKeyState" ascii
        $s5 = "Start-Sleep" ascii
        $s6 = "send-mailmessage" ascii
        $s7 = "[System.IO.File]::AppendAllText($" ascii
        $s8 = "new-object Management.Automation.PSCredential $" ascii
    condition:
        6 of them
}

rule MALWARE_Win_FujinamaRAT {
    meta:
      author = "ditekSHen"
      description = "Detects FujinamaRAT"
      snort2_sid = "920124"
      snort3_sid = "920121"
    strings:
       $s1 = "GetAsyncKeyState" fullword ascii
       $s2 = "HTTP/1.0" fullword wide
       $s3 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" fullword wide
       $s4 = "frmMain" fullword ascii
       $s5 = "G<=>?@ABGGGGGGGGGGGGGGGGGGGGGGGGGGCDEF" fullword ascii
       $s6 = "VBA6.DLL" fullword ascii
       $s7 = "t_save" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_Phorpiex {
    meta:
      author = "ditekSHen"
      description = "Detects Phorpiex variants"
    strings:
       $s1 = "ShEllExECutE=__\\DriveMgr.exe" fullword wide nocase
       $s2 = "/c start __ & __\\DriveMgr.exe & exit" fullword wide nocase
       $s3 = "%s\\autorun.inf" fullword wide
       $s4 = "svchost." wide
       $s5 = "%ls\\%d%d" wide
       $s6 = "bitcoincash:" ascii
       $s7 = "%ls:*:Enabled:%ls" fullword wide
       $s8 = "%s\\%s\\DriveMgr.exe" fullword wide
       $s9 = "api.wipmania.com" ascii
       $v1_1 = "%appdata%" fullword wide
       $v1_2 = "(iPhone;" ascii
       $v1_3 = "/tst.php" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or all of ($v1*))
}

rule MALWARE_Win_EXEPWSH_DLAgent {
    meta:
        author = "ditekSHen"
        description = "Detects SystemBC"
    strings:
        $pwsh = "powershell" fullword ascii
        $bitstansfer = "Start-BitsTransfer" ascii wide
        $s1 = "GET %s HTTP/1" ascii
        $s2 = "User-Agent:" ascii
        $s3 = "-WindowStyle Hidden -ep bypass -file \"" fullword ascii
        $s4 = "LdrLoadDll" fullword ascii
        $v1 = "BEGINDATA" fullword ascii
        $v2 = /HOST\d:/ ascii
        $v3 = /PORT\d:/ ascii
        $v4 = "TOR:" fullword ascii
        $v5 = "Fwow64" fullword ascii
        $v6 = "start" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (($pwsh and ($bitstansfer or 2 of ($s*))) or (5 of ($v*)))
}

rule MALWARE_Win_HDLocker {
    meta:
        author = "ditekSHen"
        description = "Detects HDLocker ransomware"
    strings:
        $s1 = "HDLocker_" fullword ascii
        $s2 = ".log" fullword ascii
        $s3 = "Scripting.FileSystemObject" fullword ascii
        $s4 = "Boot" fullword ascii
        $s5 = "hellwdo" fullword ascii
        $s6 = "blackmoon" fullword ascii
        $s7 = "BlackMoon RunTime Error:" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_Vovalex {
    meta:
        author = "ditekSHen"
        description = "Detects Vovalex ransomware"
    strings:
        $s1 = "README.VOVALEX.txt" fullword ascii
        $s2 = "\\src\\phobos\\std\\" ascii
        $s3 = "LoadLibraryA(\"Advapi32.dll\")" fullword ascii
        $s4 = "Failed to spawn process \"" fullword ascii
        $s5 = "=== Bypassed ===" fullword ascii
        $s6 = "If you don't know where to buy" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_Dharma {
    meta:
        author = "ditekSHen"
        description = "Detects Dharma ransomware"
    strings:
        $s1 = "C:\\crysis\\Release\\PDB\\payload.pdb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_CryptoLocker {
    meta:
        author = "ditekSHen"
        description = "Detects Cryptolocker ransomware variants (Betarasite)"
    strings:
        $x1 = "CryptoLocker" fullword wide
        $x2 = ".betarasite" fullword wide
        $x3 = "CMSTPBypass" fullword ascii
        $s1 = "CommandToExecute" fullword ascii
        $s2 = "SetInfFile" fullword ascii
        $s3 = "SchoolPrject1" ascii
        $s4 = "$730d5f64-bd57-47c1-9af4-d20aec714d02" fullword ascii
        $s5 = "Encrypt" fullword ascii
        $s6 = "Invalide Key! Please Try Again." fullword wide
        $s7 = "RegAsm" fullword wide
        $s8 = "Your key will be destroyed" wide
        $s9 = "encrypted using RC4 and RSA-2048" wide
        $c1 = "https://coinbase.com" fullword wide
        $c2 = "https://localbictoins.com" fullword wide
        $c3 = "https://bitpanda.com" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or (2 of ($x*) and 5 of ($s*)) or (all of ($c*) and 1 of ($x*) and 2 of ($s*)))
}

rule MALWARE_Win_PWSH_PoshWiFiStealer {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell PoshWiFiStealer"
    strings:
        $s1 = "netsh wlan export profile" ascii
        $s2 = "Send-MailMessage" ascii
        $u1 = "https://github.com/axel05869/Wifi-Grab" ascii
        $u2 = "/exploitechx/wifi-password-extractor" ascii
    condition:
        all of ($s*) or all of ($u*)
}

rule MALWARE_Win_SteamHook {
    meta:
        author = "ditekSHen"
        description = "Detects potential Steam stealer"
    strings:
        $s1 = "Mozilla/4.0 (compatible; )" fullword ascii
        $s2 = "/steam/upload.php" ascii
        $s3 = ".*?(ssfn\\d+)" fullword ascii
        $s4 = "add cookie failed..." fullword ascii
        $s5 = "Content-Type: multipart/form-data; boundary=--MULTI-PARTS-FORM-DATA-BOUNDARY" fullword ascii
        $pdb1 = "\\SteamHook\\Install\\" ascii
        $pdb2 = "\\SteamHook\\dll\\" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($pdb*) or (1 of ($pdb*) and 3 of ($s*)))
}

rule MALWARE_Win_NetWire {
    meta:
        author = "ditekSHen"
        description = "Detects NetWire RAT"
    strings:
        $x1 = "SOFTWARE\\NetWire" fullword ascii
        $x2 = { 4e 65 74 57 69 72 65 00 53 4f 46 54 57 41 52 45 5c 00 }
        $s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
        $s2 = "filenames.txt" fullword ascii
        $s3 = "GET %s HTTP/1.1" fullword ascii
        $s4 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
        $s5 = "Host.exe" fullword ascii
        $s6 = "-m \"%s\"" fullword ascii
        $g1 = "HostId" fullword ascii
        $g2 = "History" fullword ascii
        $g3 = "encrypted_key" fullword ascii
        $g4 = "Install Date" fullword ascii
        $g5 = "hostname" fullword ascii
        $g6 = "encryptedUsername" fullword ascii
        $g7 = "encryptedPassword" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($x*) or (1 of ($x*) and 2 of ($s*)) or (all of ($g*) and (2 of ($s*) or 1 of ($x*))))
}

rule MALWARE_Win_BreakStaf {
    meta:
        author = "ditekSHen"
        description = "Detects BreakStaf ransomware"
    strings:
        $s1 = "C:\\Program files" wide
        $s2 = "C:\\Program files (x86)" wide
        $s3 = "C:\\System Volume Information" wide
        $s4 = "C:\\$Recycle.Bin" wide
        $s5 = "C:\\Windows" wide
        $s6 = ".?AVRandomNumberGenerator@Crypto" ascii
        $s7 = ".?AV?$SymmetricCipherFinal@" ascii
        $s8 = ".breakstaf" fullword wide nocase
        $s9 = "readme.txt" fullword wide nocase
        $s10 = ".VHD" fullword wide nocase
        $s11 = ".vhdx" fullword wide nocase
        $s12 = ".BAK" fullword wide nocase
        $s13 = ".BAC" fullword wide nocase
    condition:
        uint16(0) == 0x5a4d and 12 of them
}

rule MALWARE_Win_Kitty {
    meta:
        author = "ditekSHen"
        description = "Detects HelloKitty ransomware, triggers on FIVEHANDS"
    strings:
        $s1 = "Kitty" wide
        $s2 = "-path" fullword wide
        $s3 = "select * from Win32_ShadowCopy" fullword wide
        $s4 = "Win32_ShadowCopy.ID='%s'" fullword wide
        $s5 = "programdata" fullword wide
        $s6 = "$recycle.bin" fullword wide
        $s7 = ".crypt" fullword wide
        $s8 = "%s/secret/%S" wide
        $s9 = "decrypts3nln3tic.onion" wide
        $n1 = "read_me_lkd.txt" wide
        $n2 = "DECRYPT_NOTE.txt" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 1 of ($n*) and 4 of ($s*))
}

rule MALWARE_Win_DLAgent07 {
    meta:
        author = "ditekSHen"
        description = "Detects delf downloader agent"
    strings:
        $s1 = "C:\\Users\\Public\\Libraries\\temp" fullword ascii
        $s2 = "SOFTWARE\\Borland\\Delphi" ascii
        $s3 = "Mozilla/5.0(compatible; WinInet)" fullword ascii
        $o1 = { f3 a5 e9 6b ff ff ff 5a 5d 5f 5e 5b c3 a3 00 40 }
        $o2 = { e8 83 d5 ff ff 8b 15 34 40 41 00 89 10 89 58 04 }
        $o3 = { c3 8b c0 53 51 e8 f1 ff ff ff 8b d8 85 db 74 3e }
        $o4 = { e8 5c e2 ff ff 8b c3 e8 b9 ff ff ff 89 04 24 83 }
        $o5 = { 85 c0 74 1f e8 62 ff ff ff a3 98 40 41 00 e8 98 }
        $o6 = { 85 c0 74 19 e8 be ff ff ff 83 3d 98 40 41 00 ff }
        $x1 = "22:40:08        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\"" ascii
        $x2 = "uuid:A9BD8E384B2FDE118D26E6EE744C235C\" stRef:documentID=\"uuid:A8BD8E384B2FDE118D26E6EE744C235C\"/>" ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($s*) and 5 of ($o*)) or (all of ($s*) and 2 of ($o*)) or (all of ($x*) and 2 of them))
}

rule MALWARE_Win_Clop {
    meta:
        author = "ditekSHen"
        description = "Detects Clop ransomware variants"
    strings:
        $x1 = "Cllp^_-" ascii
        $s2 = "temp.dat" fullword wide
        $s3 = "README_README.txt" wide
        $s4 = "BEGIN PUBLIC KEY" ascii
        $s5 = "runrun" wide
        $s6 = "wevtutil.exe" ascii
        $s7 = "%s%s.Cllp" fullword wide
        $s8 = "WinCheckDRVs" fullword wide
        $o1 = { 6a ff 56 89 9d 28 dd ff ff ff d0 a1 64 32 41 00 }
        $o2 = { 56 89 9d 28 dd ff ff ff 15 78 32 41 00 eb 07 43 }
        $o3 = { 68 ?? 34 41 00 8d 85 58 dd ff ff 50 ff d7 85 c0 }
        $o4 = { 68 d0 34 41 00 50 ff d6 8b bd 28 d5 ff ff 83 c4 }
        $o5 = { a1 64 32 41 00 43 56 89 9d 08 d5 ff ff ff d0 8b }
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($x*) and (3 of ($s*) or 4 of ($o*))) or (all of ($o*) and 2 of ($s*)) or (4 of ($s*) and 4 of ($o*)))
}

rule MALWARE_Win_Maktub {
    meta:
        author = "ditekSHen"
        description = "Detects Maktub ransomware"
    strings:
        $s1 = "Content-Disposition: attachment; filename=" ascii
        $s2 = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" fullword ascii
        $s3 = "/tor/status-vote/current/consensus" ascii
        $s4 = "/tor/server/fp/" ascii
        $s5 = "/tor/rendezvous2/" ascii
        $s6 = "404 Not found" fullword ascii
        $s7 = /_request@\d+/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_PWSHLoader_RunPE01 {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell PE loader / executer. Observed Gorgon TTPs"
    strings:
        $rp1 = "GetType('RunPe.RunPe'" ascii
        $rp2 = "GetType(\"RunPe.RunPe\"" ascii
        $rm1 = "GetMethod('Run'" ascii
        $rm2 = "GetMethod(\"Run\"" ascii
        $s1 = ".Invoke(" ascii
        $s2 = "[Reflection.Assembly]::Load(" ascii
    condition:
        all of ($s*) and 1 of ($rp*) and 1 of ($rm*)
}

rule MALWARE_Win_PWSHLoader_RunPE02 {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell PE loader / executer. Observed Gorgon TTPs"
    strings:
        $s1 = "'.Replace('" ascii nocase
        $s2 = "'aspnet_compiler.exe'" ascii
        $s3 = "[Byte[]]$" ascii
        $pe1 = "(77,90," ascii
        $pe2 = "='4D5A" ascii
    condition:
        all of ($s*) and (#pe1 > 1 or #pe2 > 1) and #s1 > 4
}

rule MALWARE_Win_PELoader_RunPE {
    meta:
        author = "ditekSHen"
        description = "Detects PE loader / injector. Observed Gorgon TTPs"
    strings:
        $s1 = "commandLine'" fullword ascii
        $s2 = "RunPe.dll" fullword ascii
        $s3 = "HandleRun" fullword ascii
        $s4 = "inheritHandles" fullword ascii
        $s5 = "BlockCopy" fullword ascii
        $s6 = "WriteProcessMemory" fullword ascii
        $s7 = "startupInfo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_PELoader_INF {
    meta:
        author = "ditekSHen"
        description = "Detects PE loader / injector. Potentical HCrypt. Observed Gorgon TTPs"
    strings:
        $x1 = "Managament.inf" fullword ascii
        $x2 = "rOnAlDo" fullword ascii
        $x3 = "untimeResourceSet" fullword ascii
        $x4 = "3System.Resources.Tools.StronglyTypedResourceBuilder" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_DLAgent08 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches"
      snort2_sid = "920122"
      snort3_sid = "920119"
    strings:
        $pat = /\/base\/[A-F0-9]{32}\.html/ ascii wide
    condition:
        uint16(0) == 0x5a4d and $pat and #pat > 1
}

rule MALWARE_Win_DoejoCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects DoejoCrypt / DearCry ransomware"
    strings:
        $s1 = "DEARCRY!" fullword ascii
        $s2 = ".CRYPT" fullword ascii
        $s3 = "\\EncryptFile -svcV2\\" ascii
        $s4 = "please send me the following hash!" ascii
        $s5 = "dear!!!" fullword ascii
        $s6 = "/readme.txt" fullword ascii
        $o1 = { c3 8b 65 e8 c7 45 fc fe ff ff ff 8b b5 f4 e9 ff }
        $o2 = { 0f 8c 27 ff ff ff 33 db 57 e8 7b 36 00 00 eb 0a }
        $o3 = { 0f 8c 2a ff ff ff 53 57 e8 b7 42 00 00 8b 4c 24 }
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (all of ($o*) and (2 of ($s*)))
}

rule MALWARE_Win_SunShuttle {
    meta:
        author = "ditekSHen"
        description = "Detects SunShuttle / GoldMax"
    strings:
        $s1 = "main.beaconing" fullword ascii
        $s2 = "main.clean_file" fullword ascii
        $s3 = "main.decrypt" fullword ascii
        $s4 = "main.define_internal_settings" fullword ascii
        $s5 = "main.delete_empty" fullword ascii
        $s6 = "main.encrypt" fullword ascii
        $s7 = "main.false_requesting" fullword ascii
        $s8 = "main.removeBase64Padding" fullword ascii
        $s9 = "main.resolve_command" fullword ascii
        $s10 = "main.retrieve_session_key" fullword ascii
        $s11 = "main.save_internal_settings" fullword ascii
        $s12 = "main.send_command_result" fullword ascii
        $s13 = "main.send_file_part" fullword ascii
        $s14 = "main.wget_file" fullword ascii
        $s15 = "main.write_file" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them      
}

rule MALWARE_Win_RanzyLocker {
    meta:
        author = "ditekSHen"
        description = "Detects RanzyLocker / REntS ransomware"
    strings:
        $hr1 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550" ascii                             // wbadmin DELETE SYSTEMSTATEBACKUP
        $hr2 = "776D69632E65786520534841444F57434F5059202F6E6F696E746572616374697665" ascii                         // wmic.exe SHADOWCOPY /nointeractive
        $hr3 = "626364656469742E657865202F736574207B64656661756C747D207265636F76657279656E61626C6564204E6F" ascii   // bcdedit.exe /set {default} recoveryenabled No
        $hr4 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550202D64656C6574654F6C64657374" ascii // wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
        $hr5 = "626364656469742E657865202F736574207B64656661756C747D20626F6F74737461747573706F6C6963792069676E6F7265616C6C6661696C75726573" ascii // bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
        $hr6 = "76737361646D696E2E6578652044656C65746520536861646F7773202F416C6C202F5175696574" ascii               // vssadmin.exe Delete Shadows /All /Quiet
        $hx1 = "476C6F62616C5C33353335354641352D303745392D343238422D423541352D314338384341423242343838" ascii        // Global\35355FA5-07E9-428B-B5A5-1C88CAB2B488 (mutex)
        $hx2 = "534F4654574152455C4D6963726F736F66745C45524944" ascii                                               // SOFTWARE\Microsoft\ERID
        $hx3 = "227375626964223A22" ascii // subid
        $hx4 = "226E6574776F726B223A22" ascii // network
        $hx5 = "726561646D652E747874" ascii // readme.txt
        $hx6 = "-nolan" fullword wide
        $o1 = { 8d 45 e9 89 9d 54 ff ff ff 88 9d 44 ff ff ff 3b }
        $o2 = { 8b 44 24 2? 8b ?c 24 34 40 8b 54 24 38 89 44 24 }
        $o3 = { 8b 44 24 2? 8b ?c 24 1c 89 44 24 34 8b 44 24 28 }
        $o4 = { 8b 44 24 2? 8b ?c 24 34 05 00 00 a0 00 89 44 24 }
    condition:
        uint16(0) == 0x5a4d and (all of ($hx*) or (2 of ($hr*) and 2 of ($hx*)) or (all of ($o*) and 2 of ($h*)))
}

rule MALWARE_Win_WobbyChipMBR {
    meta:
        author = "ditekSHen"
        description = "Detects WobbyChipMBR / Covid-21 ransomware"
    strings:
        $x1 = "You became a Victim of the Covid-21 Ransomware" ascii wide
        $x2 = "Reinstalling Windows has been blocked" ascii wide
        $x3 = "Enter Decryption Key:" ascii wide
        $x4 = "encrypted with military grade encryption" ascii wide
        $s1 = "schtasks.exe /Create /TN wininit /ru SYSTEM /SC ONSTART /TR" ascii
        $s2 = "\\EFI\\Boot\\bootx64.efi" ascii wide
        $s3 = "DumpHex" fullword ascii
        $s4 = "TFTP Error" fullword wide
        $s5 = "HD(Part%d,MBRType=%02x,SigType=%02x)" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or all of ($s*) or (1 of ($x*) and 2 of ($s*)))
}

rule MALWARE_Win_Snatch {
    meta:
        author = "ditekSHen"
        description = "Detects Snatch / GoRansome / MauriGo ransomware"
    strings:
        $s1 = "main.encryptFile" ascii
        $s2 = "main.encryptFileExt" ascii
        $s3 = "main.deleteShadowCopy" ascii
        $s4 = "main.Shadow" fullword ascii
        $s5 = "main.RecoverMe" fullword ascii
        $s6 = "main.EncryptWithPublicKey" ascii
        $s7 = "main.EncoderLookupDir" fullword ascii
        $s8 = "main.ALIGNUP" fullword ascii
        $s9 = "main.encrypt" fullword ascii
        $s10 = "github.com/mauri870/ransomware" ascii
        $m1 = "Dear You, ALl Your files On YOUR network computers are encrypted" ascii
        $m2 = "You have to pay the ransom of %s USD in bitcoins to the address" ascii
        $m3 = "REMEMBER YOU FILES ARE IN SAVE HANDS AND WILL BE RESTORED OR RECOVERED ONCE PAYMENT IS DONE" ascii
        $m4 = ":HELP FEEED A CHILD:" ascii
        $m5 = ">SYSTEM NETWORK ENCRYPTED<" ascii
        $m6 = "YOUR IDENTIFICATION : %s" ascii
        $m7 = "convince you of our honesty" ascii
        $m8 = "use TOR browser to talk with support" ascii
        $m9 = "encrypted and attackers are taking" ascii
        $p1 = "/Go/src/kitty/kidrives/" ascii
        $p2 = "/LGoGo/encoder.go" ascii nocase
        $p3 = "/Go/src/kitty/kidata/" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($m*) or (1 of ($m*) and 1 of ($s*)) or (all of ($p*) and (1 of ($s*) or 1 of ($m*))))
}

rule MALWARE_Win_Meteorite {
    meta:
        author = "ditekSHen"
        description = "Detects Meteorite downloader"
    strings:
        $x1 = "MeteoriteDownloader" fullword ascii wide
        $x2 = "Meteorite Downloader" fullword ascii wide
        $x3 = "Meteorite Downloader v" wide
        $s1 = "regwrite" fullword wide
        $s2 = "urlmon" fullword ascii
        $s3 = "wscript.shell" fullword wide
        $s4 = "modMain" fullword ascii
        $s5 = "VBA6.DLL" fullword ascii
        $s6 = "^_http" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or (5 of ($s*)))
}

rule MALWARE_Win_LegionLocker {
     meta:
        author = "ditekSHen"
        description = "Detects LegionLocker ransomware"
    strings:
        $m1 = "+Do not run task manager, powershell, cmd etc." ascii wide
        $m2 = "3 hours your files will be deleted." ascii wide
        $m3 = "files have been encrypted by Legion Locker" ascii wide
        $s1 = "passwordBytes" fullword ascii
        $s2 = "_start_enc_" ascii
        $s3 = "_del_desktop_" ascii
        $s4 = "Processhacker" wide
        $s5 = "/k color 47 && del /f /s /q %userprofile%\\" wide
        $s6 = "Submit code" fullword wide
        $pdb1 = "\\obj\\Debug\\LegionLocker.pdb" ascii
        $pdb2 = "\\obj\\Release\\LegionLocker.pdb" ascii
    condition:
      uint16(0) == 0x5a4d and (1 of ($m*) or 1 of ($pdb*) or 4 of ($s*))
}

rule MALWARE_Win_DLAgentGo {
    meta:
        author = "ditekSHen"
        description = "Detects Go-based downloader"
    strings:
        $s1 = "main.downloadFile" fullword ascii
        $s2 = "main.fetchFiles" fullword ascii
        $s3 = "main.createDefenderAllowanceException" fullword ascii
        $s4 = "main.unzip" fullword ascii
        $s5 = "HideWindow" fullword ascii
        $s6 = "/go/src/installwrap/main.go" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_BlackMoon {
    meta:
        author = "ditekSHen"
        description = "Detects executables using BlackMoon RunTime"
    strings:
        $s1 = "blackmoon" fullword ascii
        $s2 = "BlackMoon RunTime Error:" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_IceID {
    meta:
        author = "ditekSHen"
        description = "Detects IceID / Bokbot variants"
    strings:
       $n1 = "POST" fullword wide
       $n2 = "; _gat=" fullword wide
       $n3 = "; _ga=" fullword wide
       $n4 = "; _u=" fullword wide
       $n5 = "; __io=" fullword wide
       $n6 = "; _gid=" fullword wide
       $n7 = "Cookie: __gads=" fullword wide
       $s1 = "c:\\ProgramData" ascii
       $s2 = "loader_dll_64.dll" fullword ascii
       $s3 = "loader_dll_32.dll" fullword ascii
       $s4 = "/?id=%0.2X%0.8X%0.8X%s" ascii
       $s5 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($n*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($n*)))
}

rule MALWARE_Win_Purge {
    meta:
        author = "ditekSHen"
        description = "Detects Purge ransomware"
    strings:
        $n1 = "imagesave/imagesize.php" ascii
        $n2 = "imageinfo.html" ascii
        $n3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" ascii
        $n4 = "Content-Type: application/x-www-form-urlencoded" ascii
        $m1 = "YOUR_ID: %x%x" wide
        $m2 = "Specially for your PC was generated personal" wide
        $m3 = "which is on our Secret Server" wide
        $m4 = "wait for a miracle and get your price" wide
        $s1 = "%s\\SpyHunter Remove Ransomware" wide
        $s2 = "$recycle.bin" fullword wide
        $s3 = "TheEnd" fullword wide
        $s4 = "%s\\HELP_DECRYPT_YOUR_FILES.TXT" fullword wide
        $s5 = "%s.id_%x%x_email_" wide
        $s6 = "scmd" fullword wide
        $s7 = "process call create \"%s\"" wide
        $s8 = "FinishEnds" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($n*) or 2 of ($m*) or (3 of ($s*) and (1 of ($n*) or 1 of ($m*))))
}

rule MALWARE_Win_NjRAT {
    meta:
        author = "ditekSHen"
        description = "Detects NjRAT / Bladabindi"
    strings:
        $s1 = "netsh firewall delete allowedprogram" wide
        $s2 = "netsh firewall add allowedprogram" wide
        $s3 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
        $s4 = "Execute ERROR" wide
        $s5 = "Download ERROR" wide
        $s6 = "[kl]" fullword wide
        $s7 = "UploadValues" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_DarkTrackRAT {
    meta:
        author = "ditekSHen"
        description = "Detects OzoneRAT / DarkTrack / DarkSky"
    strings:
        $x1 = "Klog.dat" ascii
        $x2 = "I_AM_DT" ascii
        $x3 = " Alien" ascii
        $x4 = "Local Victim" ascii
        $x5 = "Dtback\\AlienEdition\\Server\\SuperObject.pas" ascii
        $x6 = "].encryptedUsername" ascii
        $x7 = "].encryptedPassword" ascii
        $x8 = { 49 41 4d [6] 44 41 52 [0-2] 4b [6] 44 54 41 43 4b }
        $s1 = "AntiVirusProduct" ascii
        $s2 = "AntiSpywareProduct" ascii
        $s3 = "ConnectServer" ascii
        $s4 = "ExecQuery" ascii
        $s5 = "\\Drivers\\Etc\\Hosts" fullword ascii
        $s6 = "BTMemoryLoadLibary: Get DLLEntyPoint" ascii
        $s7 = "\\\\.\\SyserDbgMsg" fullword ascii
        $s8 = "\\\\.\\SyserBoot" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or 6 of ($s*))
}

rule MALWARE_Win_Godzilla {
    meta:
        author = "ditekSHen"
        description = "Detects Godzilla loader"
    strings:
        $x1 = "MSVBVM60.DLL" fullword ascii
        $x2 = "Loginserver8" fullword ascii
        $x3 = "Proflogger7" fullword ascii
        $s1 = "Badgeless5" fullword ascii
        $s2 = "Montebrasite3" fullword ascii
        $s3 = "Atelomyelia4" fullword ascii
        $s4 = "Xxencoded5" fullword ascii
        $s5 = "Garneau2" fullword ascii
        $s6 = "Hypostasis0" fullword ascii
        $s7 = "Piarhemia4" fullword ascii
        $s8 = "Foredestine8" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of ($x*) and 2 of ($s*)
}

rule MALWARE_Win_UNK03 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown malware"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii
        $s2 = "rundll32.exe C:\\Windows\\System32\\shimgvw.dll,ImageView_Fullscreen %s" ascii
        $s3 = "%s.jpg" ascii
        $s4 = "%s\\sz.txt" ascii
        $s5 = "ChromeSecsv9867%d7.exe" ascii
        $s6 = "%s\\appl%c.jpg" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_UNK04 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown malware (proxy tool)"
    strings:
        $x1 = "127.0.0.1/%d" fullword ascii
        $x2 = "SYSTEM\\CurrentControlSet\\SERVICES\\PORTPROXY\\V4TOV4\\TCP" fullword ascii
        $x3 = "%s rundll32.exe" fullword ascii
        $s1 = "kxetray.exe" fullword ascii
        $s2 = "ksafe.exe" fullword ascii
        $s3 = "Mcshield.exe" fullword ascii
        $s4 = "Miner.exe" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of ($x*) and 2 of ($s*)
}

rule MALWARE_Win_Karkoff {
    meta:
        author = "ditekSHen"
        description = "Detects Karkoff"
    strings:
        $x1 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
        $x2 = "CMD.exe" fullword wide
        $x3 = "Karkoff.ProjectInstaller.resources" fullword ascii
        $s1 = /try\shttp(s)?\s(ip|domain)/ fullword wide
        $s2 = "Reg cleaned!" fullword wide nocase
        $s3 = "Content-Disposition: form-data; name=\"{1}\"" fullword wide
        $s4 = "^[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$" fullword wide
        $s5 = "new backdoor" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 4 of ($s*) or (2 of ($x*) and 2 of ($s*)))
}

rule MALWARE_Win_DLAgent09 {
    meta:
        author = "ditekSHen"
        description = "Detects known downloader agent"
    strings:
        $h1 = "//:ptth" ascii wide nocase
        $h2 = "//:sptth" ascii wide nocase
        $s1 = "DownloadString" fullword ascii wide
        $s2 = "StrReverse" fullword ascii wide
        $s3 = "FromBase64String" fullword ascii wide
        $s4 = "WebClient" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($h*) and all of ($s*))
}

rule MALWARE_Win_CoinMiningBot {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining bot"
    strings:
        $s1 = "FullScreenDetect" fullword ascii
        $s2 = "GetChildProcesses" fullword ascii
        $s3 = "HideBotPath" fullword ascii
        $s4 = "Inject" fullword ascii
        $s5 = "DownloadFile" fullword ascii
        $s6 = "/Data/GetUpdateInfo" wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_FYAnti {
    meta:
        author = "ditekSHen"
        description = "Hunt for FYAnti third-stage loader DLLs"
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and pe.exports("FuckYouAnti")
}

rule MALWARE_Win_DLAgent10 {
    meta:
        author = "ditekSHen"
        description = "Detects known downloader agent"
    strings:
        $s1 = "powershell.exe" ascii wide nocase
        $s2 = ".DownloadFile(" ascii wide nocase
        $s3 = "_UseShellExecute" ascii wide nocase
        $s4 = "_CreateNoWindow" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_PureLoader {
    meta:
        author = "ditekSHen"
        description = "Detects Pure loader / injector"
    strings:
        $s1 = "InvokeMember" fullword wide
        $s2 = "ConcatProducer" fullword wide
        $s3 = ".Classes.Resolver" wide
        $s4 = "get_DLL" fullword ascii
        $s5 = "BufferedStream" fullword ascii
        $s6 = "GZipStream" fullword ascii
        $s7 = "MemoryStream" fullword ascii
        $s8 = "Decompress" fullword ascii
        $s9 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_VBS_DLAgent01 {
    meta:
        author = "ditekSHen"
        description = "Detects VBS MSHTA downloader"
    strings:
        $s1 = "llehS.tpircsW" ascii
        $s2 = ".Run" ascii
        $s3 = "mshta http" ascii nocase
        $s4 = "StrReverse" ascii
    condition:
        all of them
}

rule MALWARE_Win_RanumBot {
    meta:
        author = "ditekSHen"
        description = "Detects RanumBot / Windigo / GoStealer"
    strings:
        // variant 1
        $f1 = "main.addSchedulerTaskSSH" fullword ascii
        $f2 = "main.attackRouter" fullword ascii
        $f3 = "main.decryptPassword" fullword ascii
        $f4 = "main.handleScanRequest" fullword ascii
        $f5 = "main.scanNetwork" fullword ascii
        $f6 = "main.extractCredentials" fullword ascii
        $s1 = "H_T= H_a= H_g= MB,  W_a= and  h_a= h_g= h_t= max= ptr  siz= tab= top= u_a= u_g=%s/16%s:%d%s:22+0330+0430+0530+0545+0630+0845+10" ascii
        $s2 = "<== as  at  fp= is  lr: of  on  pc= sp: sp=) = ) m=+Inf, n -Inf00%x112212343125: p=ABRTACDTACSTAEDTAESTAKDTAKSTALRMAWSTAhomAtoiCESTChamDashEESTGOGCJulyJuneKILLLEAFLisuMiaoModiNZDTNZSTNewaPIPEQUITSASTSEGVTERMThai" ascii
        $s3 = "W*struct { P *big.Int; Q *big.Int; G *big.Int; Y *big.Int; Rest []uint8 \"ssh:\\\"rest\\\"\" }" ascii
        $s4 = "policy=api,ftp,local,password,policy,read,reboot,sensitive,sniff,ssh,telnet,test,web,winbox,write" ascii
        $s5 = "/Users/alexander/go/src/mikrotik/winbox.go" ascii
        // variant 2
        $xf1 = "main.readConfig" fullword ascii
        $xf2 = "main.ensureRunningAsUser" fullword ascii
        $xf3 = "main.configRegPath" fullword ascii
        $xf4 = "main.oldConfigRegPath" fullword ascii
        $uf1 = "main.locateChrome" fullword ascii
        $uf2 = "main.decryptAndUploadProfile" fullword ascii
        $uf3 = "main.decryptCookies" fullword ascii
        $uf4 = "main.extractPasswords" fullword ascii
        $uf5 = "main.getFirefoxProfile" fullword ascii
        $uf6 = "main.postBrowsersData" fullword ascii
        $uf7 = "main.uploadFirefoxProfile" fullword ascii
        $uf8 = "main.zipFirefoxProfile" fullword ascii
        $uf9 = /main\.detect(Browsers|Chrome|Coccoc|Edge|Firefox|InternetExplorer|Opera|Yandex)/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($f*) or 4 of ($s*) or (2 of ($f*) and 2 of ($s*)) or (all of ($xf*) and 1 of ($uf*)) or 6 of ($uf*))
}

rule MALWARE_Win_DllHijacker01 {
    meta:
        author = "ditekSHen"
        description = "Hunt for VSNTAR21 / DllHijacker01 IronTiger / LuckyMouse / APT27 malware"
    strings:
        $s1 = "libvlc_add_intf" fullword ascii
        $s2 = "libvlc_dllonexit" fullword ascii
        $s3 = "libvlc_getmainargs" fullword ascii
        $s4 = "libvlc_initenv" fullword ascii
        $s5 = "libvlc_set_app_id" fullword ascii
        $s6 = "libvlc_set_app_type" fullword ascii
        $s7 = "libvlc_set_user_agent" fullword ascii
        $s8 = "libvlc_wait" fullword ascii
        $s9 = "dll.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_HyperBro02 {
    meta:
        author = "ditekSHen"
        description = "Detects HyperBro IronTiger / LuckyMouse / APT27 malware"
    strings:
        $s1 = "\\cmd.exe /A" fullword wide
        $s2 = "C:\\windows\\explorer.exe" fullword wide
        $s3 = "\\\\.\\pipe\\testpipe" fullword wide
        $s4 = "Elevation:Administrator!new:{" wide
        $s5 = "log.log" fullword wide
        $s6 = "%s\\%d.exe" fullword wide
        $s7 = ".?AVTPipeProtocol@@" fullword ascii
        $s8 = ".?AVTCaptureMgr@@" fullword ascii
        $s9 = "system-%d" fullword wide
        $s10 = "[test] %02d:%02d:%02d:%03d %s" fullword wide
        $s11 = "\\..\\data.dat" fullword wide
        $s12 = "\\..\\config.ini" fullword wide
        $s13 = { 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 20 00 2d 00 77 00 6f 00 72 00 6b 00 65 00 72 00 }
        $s14 = { 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 20 00 2d 00 64 00 61 00 65 00 6d 00 6f 00 6e 00 }
        $cnc1 = "https://%s:%d/ajax" fullword wide
        $cnc2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" fullword wide
        $cnc3 = "139.180.208.225" fullword wide
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (2 of ($cnc*) and 2 of ($s*)))
}

/*
Too many FPs
rule MALWARE_Win_HyperBro03 {
    meta:
        author = "ditekSHen"
        description = "Hunt HyperBro IronTiger / LuckyMouse / APT27 malware"
    strings:
        //$h1 = "HControl" ascii wide
        //$h2 = "HSleep" ascii wide
        //$h3 = "HTrans" ascii wide
        $i1 = "IAgent" ascii wide
        $i2 = "ITcpAgent" ascii wide
        $i3 = "IAgentListener" ascii wide
        $t1 = "TCommon" ascii
        $t2 = "TFileInfo" ascii
        $t3 = "TFileRename" ascii
        $t4 = "TFileUpload" ascii
        $t5 = "TServicesInfo" ascii
        $t6 = "TListUser" ascii
        $t7 = "TTransmit" ascii
        $vc1 = "CSSLAgent" ascii wide
        $vc2 = "CSocks5" ascii wide
        $vc3 = "CTcpAgent" ascii wide
        $cm1 = "CMCapture" ascii wide
        $cm2 = "CMFile" ascii wide
        $cm3 = "CMPipeClient" ascii wide
        $cm4 = "CMPipeServer" ascii wide
        $cm5 = "CMProcess" ascii wide
        $cm6 = "CMServices" ascii wide
        $cm7 = "CMShell" ascii wide
    condition:
        uint16(0) == 0x5a4d and (all of ($i*) or 6 of ($t*) or 6 of ($cm*) or all of ($vc*))
        //uint16(0) == 0x5a4d and (all of ($h*) or all of ($i*) or 6 of ($t*) or 6 of ($cm*) or all of ($vc*))
}
*/

rule MALWARE_Win_DllHijacker02 {
    meta:
        author = "ditekSHen"
        description = "Detects ServiceCrt / DllHijacker03 IronTiger / LuckyMouse / APT27 malware"
    strings:
        $s1 = "ServiceCrtMain" fullword ascii
        $s2 = "mpsvc.dll" fullword ascii
        $o1 = { 84 db 0f 85 4c ff ff ff e8 14 06 00 00 8b f0 83 }
        $o2 = { f7 c1 00 ff ff ff 75 c5 eb 13 0f ba 25 10 20 01 }
        $o3 = { 8d 04 b1 8b d9 89 45 fc 8d 34 b9 a1 18 20 01 10 }
        $o4 = { b0 01 c3 68 b8 2c 01 10 e8 83 ff ff ff c7 04 24 }
        $o5 = { eb 34 66 0f 12 0d 00 fe 00 10 f2 0f 59 c1 ba cc }
        $o6 = { 73 c7 dc 0d 4c ff 00 10 eb bf dd 05 34 ff 00 10 }
    condition:
        uint16(0) == 0x5a4d and all of ($s*) and 5 of ($o*)
}

rule MALWARE_Win_Zeoticus {
    meta:
        author = "ditekSHen"
        description = "Detects Zeoticus ransomware"
    strings:
        $s1 = "Dear %s" fullword wide
        $s2 = "\\??\\UNC\\%s\\%s\\" wide
        $s3 = "\\\\%ws\\admin$\\%ws" wide
        $s4 = "%s /node:\"%ws\" /user:\"%ws\" /password:" wide
        $s5 = "process call create" wide
        $s6 = ">----===Zeoticus" ascii
        $s7 = "ZEOTICUSV2" ascii
        $s8 = "GetExtendedTcpTable" fullword ascii
        $s9 = "SHAMROckSWTF" ascii
        $s10 = "NTDLL.RtlAllocateHeap" fullword ascii
        $s11 = ".pandora" fullword wide
        $s12 = { 70 00 20 00 72 00 20 00 69 00 20 00 76 00 20 00 65 00 20 00 74 }
        $pdb = "_cryptor\\shell_gen\\Release\\" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or ($pdb))
}

rule MALWARE_Win_DLAgent11 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader agent"
    strings:
        $pdb = "\\loader2\\obj\\Debug\\loader2.pdb" ascii
        $s1 = "DownloadFile" fullword ascii
        $s2 = "ZipFile" fullword ascii
        $s3 = "WebClient" fullword ascii
        $s4 = "ExtractToDirectory" fullword ascii
        $s5 = "System Clear" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (($pdb) and 4 of ($s*)))
}

rule MALWARE_Win_SoftCNApp {
    meta:
        author = "ditekSHen"
        description = "Detects SoftCNApp"
    strings:
        $s1 = "\\\\.\\PIPE\\SOC%d" fullword ascii
        $s2 = "Mozilla/5.0 (Windows NT 6.1)" fullword ascii
        $s3 = "Param: sl=%d; sl=%d; sl=%d; sl=%d; sl=%d;" fullword ascii
        $s4 = ".?AVCHPPlugin@@" fullword ascii
        $s5 = ".?AVCHPCmd@@" fullword ascii
        $s6 = ".?AVCHPExplorer@@" fullword ascii
        $s7 = "%s\\svchost.exe -O" fullword wide
        $s8 = "\"%s\\%s\" -P" fullword ascii
        $n1 = "45.63.58.34" fullword ascii
        $n2 = "127.0.0.1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (all of ($n*) and 2 of ($s*)))
}

rule MALWARE_Win_CovenantGruntStager {
     meta:
        author = "ditekSHen"
        description = "Detects Covenant Grunt Stager"
    strings:
        $x1 = "VXNlci1BZ2VudA" ascii wide
        $x2 = "cGFnZT17R1VJRH0mdj0x" ascii wide
        $x3 = "0eXBlPXtHVUlEfSZ2PTE" ascii wide
        $x4 = "tZXNzYWdlPXtHVUlEfSZ2PTE" ascii wide
        $x5 = "L2VuLXVzL" ascii wide
        $x6 = "L2VuLXVzL2luZGV4Lmh0bWw" ascii wide
        $x7 = "L2VuLXVzL2RvY3MuaHRtbD" ascii wide
        $s1 = "ExecuteStager" ascii
        $s2 = "UseCertPinning" fullword ascii
        $s3 = "FromBase64String" fullword ascii
        $s4 = "ToBase64String" fullword ascii
        $s5 = "DownloadString" fullword ascii
        $s6 = "UploadString" fullword ascii
        $s7 = "GetWebRequest" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or all of ($s*) or (1 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Win_Fabookie {
     meta:
        author = "ditekSHen"
        description = "Detects Fabookie / ElysiumStealer"
    strings:
        $s1 = "rwinssyslog" fullword wide
        $s2 = "_kasssperskdy" fullword wide
        $s3 = "[Title:%s]" fullword wide
        $s4 = "[Execute]" fullword wide
        $s5 = "[Snapshot]" fullword wide
        $s6 = "Mozilla/4.0 (compatible)" fullword wide
        $s7 = "d-k netsvcs" fullword wide
        $s8 = "facebook.websmails.com" fullword wide
        $s9 = "CUdpClient::Start" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x0805) and 6 of them
}

rule MALWARE_Win_CobianRAT {
     meta:
        author = "ditekSHen"
        description = "Detects CobianRAT, a fork of Njrat"
    strings:
        $s1 = "1.0.40.7" fullword wide
        $s2 = "DownloadData" fullword wide
        $s3 = "Executed As" fullword wide
        $s4 = "\\Plugins" fullword wide
        $s5 = "LOGIN" fullword wide
        $s6 = "software\\microsoft\\windows\\currentversion\\run" wide
        $s7 = "Hidden" fullword wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_Cuba {
    meta:
        author = "ditekSHen"
        description = "Detects Cuba ransomware"
    strings:
        $s1 = ".cuba" fullword wide
        $s2 = "\\\\%d.%d.%d.%d" fullword wide
        $s3 = "!!FAQ for Decryption!!.txt" fullword wide
        $s4 = "vmcompute" fullword wide
        $s5 = "MSExchange" wide
        $s6 = "glocal" fullword wide
        $s7 = "network" fullword wide
        $s8 = "\\$Recycle.Bin\\" fullword wide
        $s9 = "NetShareEnum" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_Leivion {
    meta:
        author = "ditekSHen"
        description = "Detects Leivion"
    strings:
        $s1 = "/var/lib/veil/go/src/runtime/mem_windows.go" fullword ascii
        $s2 = "/var/lib/veil/go/src/internal/singleflight/singleflight.go" fullword ascii
        $s3 = "/var/lib/veil/go/src/net/http/sniff.go" fullword ascii
        $s4 = "/var/lib/veil/go/src/net/sendfile_windows.go" fullword ascii
        $s5 = "/var/lib/veil/go/src/os/exec_" ascii
        $s6 = "/var/lib/veil/go/src/runtime/mgcsweep.go" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_Banload {
    meta:
        author = "ditekSHen"
        description = "Detects Banload"
    strings:
        $s1 = "main.die" fullword ascii
        $s2 = "main.postResults" fullword ascii
        $s3 = "main.checkin" fullword ascii
        $s4 = "RegQueryValueExWRemoveDirectoryWSETTINGS_TIMEOUTTerminateProcessUpgrade RequiredUser-Agent: %s" ascii
        $s5 = "pcuser-agentws2_32.dll (targetpc= DigestType ErrCode=%v" ascii
        $s6 = "invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrie" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_TYRAT {
    meta:
        author = "ditekSHen"
        description = "Detects TYRAT"
    strings:
        $s1 = "C:\\$MSIRecycle.Bin\\" fullword ascii
        $s2 = "Range: bytes=%d-" fullword ascii
        $s3 = "GET%sHTTP/1.1" fullword ascii
        $s4 = "DllServer.dll" fullword ascii
        $s5 = ".Bin\\bnch" ascii
        $s6 = "User-Agent: wget" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_InfinityLock {
    meta:
        author = "ditekSHen"
        description = "Detects InfinityLock ransomware"
    strings:
        $s1 = "_Encrypted$" fullword ascii
        $s2 = "PublicKeyToken=" fullword ascii nocase
        $s3 = "GenerateHWID" fullword ascii
        $s4 = "CreateKey" fullword ascii
        $d1 = "ProgrammFiles" fullword ascii
        $d2 = "OneDrive" fullword ascii
        $d3 = "ProgrammsX86" fullword ascii
        $d4 = "UserDirs" fullword ascii
        $d5 = "B_Drive" fullword ascii
        $pdb1 = "F:\\DESKTOP!\\ChkDsk\\ChkDsk\\obj\\" ascii
        $pdb2 = "\\ChkDsk\\obj\\Debug\\PremiereCrack.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and 1 of ($d*)) or (4 of ($d*) and 2 of ($s*)) or (any of ($pdb*) and 1 of ($s*) and 1 of ($d*)))
}

rule MALWARE_Win_MountLocker {
    meta:
        author = "ditekSHen"
        description = "Detects MountLocker ransomware"
    strings:
        $s1 = "] locker.dir.check > " ascii wide
        $s2 = "] locekr.kill." ascii wide
        $s3 = "] locker.worm" ascii wide
        $s4 = "%CLIENT_ID%" fullword ascii
        $s5 = "RecoveryManual.html" ascii wide
        $s6 = "RECOVERY MANUAL" ascii
        $s7 = ".ReadManual.%0.8X" ascii wide
        $s8 = "/?cid=%CLIENT_ID%" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule MALWARE_Win_PingBack {
    meta:
        author = "ditekSHen"
        description = "Detects PingBack ICMP backdoor"
    strings:
        $s1 = "Sniffer ok!" fullword ascii
        $s2 = "recv icmp packet!" fullword ascii
        $s3 = "WSASocket() failed: %d" fullword ascii
        $s4 = "file on remote computers success" ascii
        $s5 = "listen port error!" fullword ascii
        $s6 = "\\PingBackService" ascii
        $c1 = "exec" fullword ascii
        $c2 = "rexec" fullword ascii
        $c3 = "exep" fullword ascii
        $c4 = "download" fullword ascii
        $c5 = "upload" fullword ascii
        $c6 = "shell" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or all of ($c*) or (4 of ($c*) and 2 of ($s*)))
}

rule MALWARE_Win_BazarLoader {
    meta:
        author = "ditekSHen"
        description = "Detects BazarLoader variants"
    strings:
        $s1 = "Startdelay for %d ms to avoid some dynamic AV detects!" ascii
        $s2 = "Use Debug for moving faster!" ascii
        $s3 = "Logging Mutex %s to %s" ascii
        $s4 = "FIRST AND ONLY COPY RUNNING! Mutex %s" ascii
        $s5 = "the most secret 3d GetWinApiPointers line in the world!" ascii
        $s6 = "[+] makeMD5hash. " ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($s*)
}

rule MALWARE_Win_CoinMiner01 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
    strings:
        $s1 = "-o pool." ascii wide
        $s2 = "--cpu-max-threads-hint" ascii wide
        $s3 = "-P stratum" ascii wide
        $s4 = "--farm-retries" ascii wide
        $dl = "github.com/ethereum-mining/ethminer/releases/download" ascii wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or ($dl))
}

rule PUA_Win_UltraSurf {
    meta:
        author = "ditekSHen"
        description = "Detects UltraSurf / Ultrareach PUA"
    strings:
        $s1 = "Ultrareach Internet Corp." ascii
        $s2 = "UltrasurfUnionRectUrlFixupWUse Proxy" ascii
        $s3 = "Ultrasurf UnlockFileUrlEscapeWUser-Agent" ascii wide
        $s4 = "Ultrasurf0#" ascii
        $m1 = "main.bindata_read" fullword ascii
        $m2 = "main.icon64_png" fullword ascii
        $m3 = "main.setProxy" fullword ascii
        $m4 = "main.openbrowser" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (all of ($m*) and 1 of ($s*)))
}

rule MALWARE_Win_Hello {
    meta:
        author = "ditekSHen"
        description = "Hunt for Hello / WickrMe ransomware"
    strings:
        $s1 = "DeleteBackupFiles" ascii wide
        $s2 = "GetEncryptFiles" ascii wide
        $s3 = "DeleteVirtualDisks" ascii wide
        $s4 = "DismountVirtualDisks" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule MALWARE_Win_ButeRAT {
    meta:
        author = "ditekSHen"
        description = "Detects ButeRAT"
    strings:
        $x1 = "TVqQAAMAA" ascii
        $s1 = "ipinfo.io/geo" wide
        $s2 = "/index.php" wide
        $s3 = "Copy-Item -Path" wide
        $s4 = ";Start-Process" wide
        $s5 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide
        $s6 = "LOCALAPPDATA" fullword wide
        $s7 = "passwords.json" wide
        $s8 = "Scripting.FileSystemObject" fullword wide
        $z1 = /(edge|chrome|opera|exodus|jaxx|atomic|coinomi)\.zip/ ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) or 1 of ($z*)) and (4 of ($s*)) or (6 of ($s*)) or (#z1 > 4 and 2 of them))
}

rule MALWARE_Win_CookieStealer {
    meta:
        author = "ditekSHen"
        description = "Detects generic cookie stealer"
    strings:
        $s1 = "([\\S]+?)=([^;|^\\r|^\\n]+)" fullword ascii
        $s2 = "(.+?): ([^;|^\\r|^\\n]+)" fullword ascii
        $s3 = "Set-Cookie: ([^\\r|^\\n]+)" fullword ascii
        $s4 = "cmd.exe /c taskkill /f /im chrome.exe" fullword ascii
        $s5 = "FIREFOX.EXE|Google Chrome|IEXPLORE.EXE" ascii
        $pdb1 = "F:\\facebook_svn\\trunk\\database\\Release\\DiskScan.pdb" fullword ascii
        $pdb2 = "D:\\Projects\\crxinstall\\trunk\\Release\\spoofpref.pdb" fullword ascii
        $ua1 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36" fullword ascii
        $ua2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and 1 of ($pdb*) and 1 of ($ua*)) or (all of ($ua*) and 1 of ($pdb*) and 2 of ($s*)))
}

rule MALWARE_Win_BitCoinGrabber {
    meta:
        author = "ditekSHen"
        description = "Detects generic bitcoin stealer"
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s2 = "Bitcoin-Grabber" ascii
        $s3 = "Bitcoin_Grabber" ascii
        $s4 = "encrypt resources [compress]T" fullword ascii
        $s5 = "code control flow obfuscationT" fullword ascii
        $s6 = "\\Users\\lakol\\Desktop\\a\\Crypto Currency Wallet Changer\\" ascii
        $pat1 = "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}\\b" fullword wide
        $pat2 = "\\b0x[a-fA-F0-9]{40}\\b" fullword wide
        $pat3 = "\\b4([0-9]|[A-B])(.){93}\\b" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (all of ($pat*) and 2 of ($s*))
}

rule MALWARE_Win_FOXGRABBER {
    meta:
        author = "ditekSHen"
        description = "Detects FOXGRABBER utility"
    strings:
        $s1 = "start grabbing" wide
        $s2 = "end grabbing in" wide
        $s3 = "error of copying files from comp:" wide
        $s4 = "\\Firefox\\" wide nocase
        $pdb1 = "\\obj\\Debug\\grabff.pdb" ascii
        $pdb2 = "\\obj\\Release\\grabff.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}

rule MALWARE_Win_BrowserGrabber {
    meta:
        author = "ditekSHen"
        description = "Hunt for FOXGRABBER-like samples but for various browsers"
    strings:
        $s1 = "start grabbing" wide
        $s2 = "end grabbing in" wide
        $s3 = "error of copying files from comp:" wide
        $s4 = /(Chrome|Edge)/ wide
        $ff = "\\Firefox\\" wide nocase
        $pdb1 = "\\obj\\Debug\\grab" ascii
        $pdb2 = "\\obj\\Release\\grab" ascii
    condition:
        uint16(0) == 0x5a4d and not ($ff) and (all of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}

rule MALWARE_Win_DeathRansom {
    meta:
        author = "ditekSHen"
        description = "Detects known DeathRansom ransomware"
    strings:
        $s1 = "%s %f %c" fullword ascii
        $pdb1 = ":\\wud.pdb" ascii
        $spdb2 = "\\crypt_server\\runtime\\crypt" ascii
        $spdb3 = "\\bin\\nuvin.pdb" ascii
        $h1 = "#Dunubeyokunov" wide
        $h2 = "^Neyot dehipijakeyelih" wide
        $h3 = "talin%Sanovurenofibiw" wide
        $h4 = "WriteFile" fullword ascii
        $h5 = "ClearEventLogA" fullword ascii
        $h6 = "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" ascii wide
    condition:
        uint16(0) == 0x5a4d and (all of ($pdb*) or (all of ($s*) and 1 of ($pdb*)) or 5 of ($h*))
}

rule MALWARE_Win_UnlockYourFiles {
    meta:
        author = "ditekSHen"
        description = "Detects UnlockYourFiles ransomware"
    strings:
        $s1 = "filesx0" wide
        $s2 = "_auto_file" wide
        $s3 = "<EncyptedKey>" fullword wide
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\" wide
        $s5 = "DecryptAllFile" fullword ascii
        $s6 = "AES_Only_Decrypt_File" fullword ascii
        $m1 = "Free files decrypted" wide
        $m2 = "Restore my files" wide
        $m3 = "Type tour password..." wide
        $m4 = "files encrypted by strong password" ascii
        $m5 = "buy bitcoin" ascii
        $m6 = "Unlock File" fullword wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or 5 of ($m*) or (2 of ($s*) and 2 of ($m*)))
}

rule MALWARE_Win_DecryptMyFiles {
    meta:
        author = "ditekSHen"
        description = "Detects DecryptMyFiles ransomware"
    strings:
        $s1 = "FILES ENCRYPTED" wide
        $s2 = "pexplorer.exe" fullword wide
        $s3 = "uniquesession" fullword ascii
        $s4 = ".[decryptmyfiles.top]." fullword ascii
        $s5 = "decrypt 1 file" ascii
        $s6 = "(databases,backups, large excel" ascii
        $c1 = "api/connect.php" ascii
        $c2 = "decryptmyfiles.top" ascii
        $c3 = "/contact/" ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or all of ($c*) or (2 of ($c*) and 2 of ($s*)))
}

rule MALWARE_Win_Motocos {
    meta:
        author = "ditekSHen"
        description = "Detects Motocos ransomware"
    strings:
        $s1 = "Block Investigation Tools" wide
        $s2 = "powershell.exe,taskmgr.exe,procexp.exe,procmon.exe" wide
        $s3 = "google.com,youtube.com,baidu.com,facebook.com,amazon.com,360.cn,yahoo.com,wikipedia.org,zoom.us,live.com,reddit.com,netflix.com,microsoft.com,instagram.com,vk.com," wide
        $s4 = "START ----" wide
        $s5 = "TEngine.Clear_EventLog_Result" wide
        $s6 = "TEngine.EncryptLockFiles" wide
        $s7 = "TEngine.CleanShadowFiles" wide
        $s8 = "TDNSUtils.SendCommand" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_DLAgent12 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader agent"
    strings:
        $s1 = "WebClient" fullword ascii
        $s2 = "DownloadData" fullword ascii
        $s3 = "packet_server" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them and filesize < 50KB
}

rule MALWARE_Win_DLInjector01 {
    meta:
        author = "ditekSHen"
        description = "Detects specific downloader injector shellcode"
    strings:
        $s1 = "process call create \"%s\"" ascii wide
        $s2 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Enum\\" ascii wide
        $s3 = "%systemroot%\\system32\\ntdll.dll" ascii wide
        $s4 = "qemu-ga.exe" ascii wide
        $s5 = "prl_tools.exe" ascii wide
        $s6 = "vboxservice.exe" ascii wide
        $o1 = { 75 04 74 02 38 6e 8b 34 24 83 c4 04 eb 0a 08 81 }
        $o2 = { 16 f8 f7 ba f0 3d 87 c7 95 13 b7 64 22 be e1 59 }
        $o3 = { 8b 0c 24 83 c4 04 eb 05 ea f2 eb ef 05 e8 ad fe }
        $o4 = { eb 05 1d 51 eb f5 ce e8 80 fd ff ff 77 a1 f4 cd }
        $o5 = { eb 05 6e 33 eb f5 73 e8 64 f6 ff ff 77 a1 f4 77 }
        $o6 = { 59 eb 05 fd 98 eb f4 50 e8 d5 f5 ff ff 3b b9 00 }
        $o7 = "bYkoDA7G" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and all of ($o*)) or (all of ($s*))
}

rule MALWARE_Win_DLInjector02 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader injector"
    strings:
        $x1 = "In$J$ct0r" fullword wide
        $x2 = "%InJ%ector%" fullword wide
        $a1 = "WriteProcessMemory" fullword wide
        $a2 = "URLDownloadToFileA" fullword ascii
        $a3 = "Wow64SetThreadContext" fullword wide
        $a4 = "VirtualAllocEx" fullword wide
        $s1 = "RunPE" fullword wide
        $s2 = "SETTINGS" fullword wide
        $s3 = "net.pipe" fullword wide
        $s4 = "vsmacros" fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or (all of ($a*) and 3 of ($s*)))
}

rule MALWARE_Win_Nermer {
    meta:
        author = "ditekSHen"
        description = "Detects Nermer ransomware"
    strings:
        $x1 = "gPROTECT_INFO.TXT" fullword wide
        $x2 = ".nermer" fullword wide
        $s1 = "db_journal" fullword wide
        $s2 = "quicken2015backup" fullword wide
        $s3 = "mysql" fullword wide
        $s4 = "sas7bdat" fullword wide
        $s5 = "httpd.exe" fullword wide
        $s6 = "Intuit.QuickBooks.FCS" fullword wide
        $s7 = "convimage" fullword wide
        $s8 = ".?AV?$_Binder@U_Unforced@std@@P8shares_t@" ascii
        $s9 = "BgIAAACkAABSU0ExAAgAAAEAAQCt" ascii
        $m1 = "YOUR FILES WERE ENCRYPTED" ascii
        $m2 = "MARKED BY EXTENSION .nermer" ascii
        $m3 = "send us your id: >> {id} <<" ascii
        $m4 = "email us: >> {email} <<" ascii
        $c1 = "/repeater.php" ascii
        $c2 = "HTTPClient/0.1" fullword ascii
        $c3 = "94.156.35.227" ascii
        $c4 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($m*) or all of ($c*) or all of ($s*)  or (4 of ($s*) and (1 of ($x*) or 1 of ($m*) or 2 of ($c*))) or 14 of them)
}

rule MALWARE_Win_Beastdoor {
    meta:
        author = "ditekSHen"
        description = "Detects Beastdoor backdoor"
    strings:
        $s1 = "shellx.pif" fullword ascii nocase
        $s2 = "Beasty" fullword ascii
        $s3 = "* Boot:[" ascii
        $s4 = "^ Shut Down:[" ascii
        $s5 = "set cdaudio door" ascii
        $s6 = "This \"Portable Network Graphics\" image is not valid" wide
        $n1 = ".aol.com" ascii
        $n2 = "web.icq.com" ascii
        $n3 = "&fromemail=" fullword ascii
        $n4 = "&subject=" fullword ascii
        $n5 = "&Send=" fullword ascii
        $n6 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword ascii
        $n7 = "mirabilis.com" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($n*) or (3 of ($s*) and 3 of ($n*)))
}

rule MALWARE_Win_GravityRAT {
    meta:
        author = "ditekSHen"
        description = "Detects GravityRAT"
    strings:
        $s1 = "/GX/GX-Server.php?VALUE=2&Type=" wide
        $s2 = "&SIGNATUREHASH=" wide
        $s3 = "Error => CommonFunctionClass => Upload()" wide
        $s4 = "/GetActiveDomains.php" wide
        $s5 = "DetectVM" ascii wide
        $s6 = "/c {0} > {1}" wide
        $s7 = "DRIVEUPLOADCOMPLETED => TOTALFILES={0}, FILESUPLOADED={1}" wide
        $s8 = "Program => RunAFile()" wide
        $s9 = "DoViaCmd" ascii
        $s10 = ".msoftupdates.com:" wide
        $f1 = "<RootJob>b__" ascii
        $f2 = "<GetFiles>b__" ascii
        $f3 = "<UpdateServer>b__" ascii
        $f4 = "<EthernetId>b__" ascii
        $f5 = "<MatchMacAdd>b__" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($f*) and 1 of ($s*)))
}

rule MALWARE_Win_FatalRAT {
    meta:
        author = "ditekSHen"
        description = "Detects FatalRAT"
    strings:
        $x1 = "XXAcQbcXXfRSScR" fullword ascii
        $s1 = "CHROME_NO_DATA" fullword ascii
        $s2 = "CHROME_UNKNOW" fullword ascii
        $s3 = "-Thread running..." ascii
        $s4 = "InetCpl.cpl,ClearMyTracksByProcess" ascii nocase
        $s5 = "MSAcpi_ThermalZoneTemperature" ascii nocase
        $s6 = "taskkill /f /im rundll32.exe" fullword ascii nocase
        $s7 = "del /s /f %appdata%\\Mozilla\\Firefox" ascii nocase
        $s8 = "\\\\%s\\C$\\" ascii
        $s9 = "fnGetChromeUserInfo" fullword ascii
        $s10 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or 5 of ($s*))
}

rule MALWARE_Win_WinGo {
    meta:
        author = "ditekSHen"
        description = "Detects malicious Golang executables"
    strings:
        $s1 = "Go build ID:" ascii
        $s2 = /main\.[a-z]{9}Delete/ fullword ascii
        $s3 = /main\.[a-z]{9}Update/ fullword ascii
        $s4 = /main\.[a-z]{9}rundll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of them and #s2 > 2 and #s3 > 2 and #s4 > 2)
}

rule MALWARE_Win_GENERIC03 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown malicious executables"
    strings:
        $s1 = "lbroscfg.dll" wide
        $s2 = "cmd /c ping 127.0.0.1 & del /f /q \"" fullword wide
        $s3 = "E:\\Data\\Sysceo\\AD\\" fullword ascii
        $s4 = "C++\\Browser_noime\\" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule MALWARE_Win_PandaStealer {
    meta:
        author = "ditekSHen"
        description = "Detects Panda Stealer"
    strings:
        $s1 = "\\tokens.txt" fullword ascii
        $s2 = "user.config" fullword ascii
        $s3 = "Discord\\" ascii
        $s4 = "%s\\etilqs_" fullword ascii
        $s5 = "buildSettingGrabber" ascii
        $s6 = "buildSettingSteam" ascii
        $s7 = ".?AV?$_Ref_count_obj2@U_Recursive_dir_enum_impl@filesystem@std@@@" ascii
        $s8 = "UPDATE %Q.%s SET sql = substr(sql,1,%d) || ', ' || %Q || substr" ascii
        $s9 = "|| substr(name,%d+18) ELSE name END WHERE tbl_name=%Q AND (" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_Gelsemine {
    meta:
        author = "ditekSHen"
        description = "Detects Gelsemine"
    strings:
        $s1 = "If any of these steps fails.only pick one of the targets for configuration\"If you want to just get on with it*which also use [ " wide
        $s2 = "A make implementation+with core modules (please read NOTES.PER_L)2The per_l Text::Template (please read NOTES.PER_L)" wide
        $s3 = "NOTES.VMS (OpenVMS)!NOTES.WIN (any supported Windows)%NOTES.DJGPP (DOS platform with DJGPP)'NOTES.ANDROID (obviously Android [ND" wide
        $s4 = "A simple example would be this)which is to be understood as one of these" fullword wide
        $s5 = "bala bala bala" fullword wide
        $s6 = "echo FOO" fullword wide
        $s7 = "?_Tidy@?$basic_string@DU?$char_traits@D@std@@V" ascii
        $o1 = { eb 08 c7 44 24 34 fd ff ff ff 8b 44 24 54 8b 4c }
        $o2 = { eb 08 c7 44 24 34 fd ff ff ff 8b 44 24 54 8b 4c }
        $o3 = { 8b 76 08 2b f0 a1 34 ff 40 00 03 f0 89 35 38 ff }
        $o4 = { 83 c4 34 c3 8b 4e 20 6a 05 e8 73 10 00 00 8b 76 }
        $o5 = { 8b 44 24 44 2b d1 03 d0 8b f2 e9 14 ff ff ff 8d }
        $o6 = { 68 00 06 00 00 6a 00 e8 d3 ff ff ff a2 48 00 41 }
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (all of ($o*) and 2 of ($s*)))
}

rule MALWARE_Win_Gelsenicine {
    meta:
        author = "ditekSHen"
        description = "Detects Gelsenicine"
    strings:
        $s1 = "System/" fullword wide
        $s2 = "Windows/" fullword wide
        $s3 = "CommonAppData/" fullword wide
        $s5 = ".?AUEmbeddedResource@@" fullword ascii
        $ms1 = "pulse" fullword wide
        $ms2 = "mainpath" fullword wide
        $ms3 = "mainpath64" fullword wide
        $ms4 = "pluginkey" fullword wide
        $o1 = { 48 8d 54 24 68 48 8b 4c 39 10 e8 4d ff ff ff 44 }
        $o2 = { 48 8d 54 24 30 48 8b cb e8 34 f2 ff ff 84 c0 74 }
        $o3 = { 48 c7 44 24 ?? fe ff ff ff 49 8b f0 48 8b d9 ?? }
        $o4 = { 89 44 24 30 89 44 24 34 48 8b 53 08 48 85 d2 48 }
        $o5 = { ff ff ff ff 49 f7 d1 4c 23 f8 8b 43 10 48 8b e9 }
        $o6 = { 83 c4 24 85 c0 74 3c 8b 0b 8b 41 34 8b 4d 34 2b }
        $o7 = { 8b 45 34 8b 53 fc 50 8b cf 6a 04 68 00 10 00 00 }
        $o8 = { 80 74 1f 8b 4e 34 8b 54 24 18 25 ff ff 00 00 51 }
        $o9 = { eb 47 8b 4c 24 14 8b 56 34 52 8d 3c 08 8b 44 24 }
        $o10 = { 8b 44 24 0c 5d 5e 5b 83 c4 10 c3 8b 4e 34 51 57 }
        $o11 = { 6a 03 53 53 56 68 34 00 e4 74 ff 15 80 d0 e3 74 }
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and (3 of ($ms*) or 4 of ($o*))) or (all of ($ms*) and 2 of ($s*) and 3 of ($o*)))
}

rule MALWARE_Win_Gelsevirine {
    meta:
        author = "ditekSHen"
        description = "Detects Gelsevirine"
    strings:
        $s1 = /64loadpath(xp|sv|7)/ fullword wide
        $s2 = "{\"Actions\":[]}" fullword wide
        $s3 = "PlatformsChunk" fullword wide
        $s4 = "CurrentPluginCategory" fullword wide
        $s5 = "CurrentOperationPlatform" fullword wide
        $s6 = "PersistencePlugins" fullword wide
        $s7 = "memory_library_file" fullword wide
        $s8 = "LoadPluginBP" fullword ascii
        $s9 = "GetOperationBasicInformation" fullword ascii
        $s10 = "commonappdata/Intel/Runtime" wide
        $s11 = "cfsst x64" fullword wide
        $s12 = "ForkOperation" fullword ascii
        $c1 = "domain.dns04.com:8080;domain.dns04.com:443;acro.ns1.name:80;acro.ns1.name:1863;" wide
        $c2 = "<base64 content=\"" fullword ascii
        $c3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
        $m1 = "6BDA7FEF-232F-4EA6-8FC8-24F58CD7B366" ascii wide
        $m2 = "46EBBDC3-EEDC-42D4-BA1D-D454DFCE8E42" ascii wide
        $m3 = "135054C6-8036-42C7-A97C-31F37D7728BD" ascii wide
        $m4 = "DC7FDDF7-B2F1-4B99-BE6A-AA683FF11CE6" ascii wide
        $m5 = "131C8113-E083-4C7F-BEAF-82D73B01F2C5" ascii wide
        $m6 = "4CCF506D-2F61-4C3A-B9C6-9FA47D43A3FC" ascii wide
        $m7 = "B2DC745A-66AE-4A19-B11C-AD74D46B7EE0" ascii wide
        $m8 = "6BDA7FEF-232F-4EA6-8FC8-24F58CD7B366" ascii wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (2 of ($c*) and 4 of ($s*)) or (5 of ($m*) and (1 of ($c*) or 3 of ($s*))))
}

rule MALWARE_Win_IPsecHelper {
    meta:
        author = "ditekSHen"
        description = "Detects IPsecHelper backdoor"
    strings:
        $s1 = "rundll32.exe advapi32.dll,ProcessIdleTasks" wide
        $s2 = "CommandExecute" fullword ascii
        $s3 = "DownloadExecuteUrl" fullword ascii
        $s4 = "DownloadExecuteFile" fullword ascii
        $s5 = "CmdExecute" fullword ascii
        $s6 = "ExecuteProcessWithResult" fullword ascii
        $s7 = "IsFirstInstance ==> checked" fullword wide
        $s8 = "del \"%PROG%%SERVICENAME%\".*" fullword wide
        $s9 = ".CreateConfig" wide
        $s10 = ".SelfDelete" wide
        $c1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; EmbeddedWB 14.52 from: http://www.google.com/ EmbeddedWB 14.52;" wide
        $c2 = "boot.php" wide
        $c3 = "lastupdate.php" wide
        $c4 = "main.php" wide
        $c5 = "InternetNeeded" wide
        $c6 = "DeviceIdSalt" wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or 4 of ($c*) or 8 of them)
}

rule MALWARE_Win_Apostle {
    meta:
        author = "ditekSHen"
        description = "Detects Apsotle"
    strings:
        $s1 = "bytesToBeEncrypted" fullword ascii
        $s2 = "SelfDelete" fullword ascii
        $s3 = "ReadMeFileName" ascii
        $s4 = "DesktopFileName" ascii
        $s5 = "SetWallpaper" fullword ascii
        $s6 = "get_EncryptionKey" fullword ascii
        $s7 = "disall" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_DEADWOOD {
    meta:
        author = "ditekSHen"
        description = "Detects DEADWOOD"
    strings:
        $s1 = "Service Start Work !!!!" fullword ascii
        $s2 = "Error GetTokenInformation : " fullword ascii
        $s3 = "\\Windows\\System32\\net.exe" fullword wide
        $s4 = "App Start Work !!!!" fullword ascii
        $s5 = "vmmouse" fullword wide
        $s6 = "CDPUserSvc_" wide
        $s7 = "WpnUserService_" wide
        $s8 = "User is :" wide
        $s9 = "\\params" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_Turian {
    meta:
        author = "ditekSHen"
        description = "Hunt for Turian / Qurian"
        hash1 = "d1218ab9d608ee0212e880204e4d7d75f29f03b77248bca7648d111d67405759"
        cnc_domain = "windowsupdate[.]dyndns[.]info"
        cnc_ip = "58[.]158[.]177[.]102"
    strings:
        $s1 = "%s a -m5 -hp1qaz@WSX3edc -r %s %s\\*.*" ascii wide
        $s2 = "%s a -m5 -hpMyHost-1 -r %s %s\\*.*" ascii wide
        $s3 = "%s a -m5 -hp1qaz@WSX3edc -ta%04d%02d%02d000000 -r %s c:" ascii wide
        $s4 = "%s a -m5 -hpMyHost-1 -ta%04d%02d%02d000000 -r %s c:"
        $s5 = "cmd /c dir /s /O:D %s>>\"%s\"" ascii wide
        $s6 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v %s /t REG_SZ /d \"%s\" /f" fullword ascii
        $s7 = "Not Connect!" fullword ascii
        $p1 = "RECYCLER\\S-1-3-33-854245398-2067806209-0000980848-2003\\" ascii wide
        $p2 = "%sRECYCLER.{S-1-3-33-854245398-2067806209-0000980848-2003}\\" ascii wide
        $p3 = "\\RECYCLER.{S-1-3-33-854245398-2067806209-0000980848-2003}\\" ascii wide
        $p4 = "\\RECYCLER.{645ff040-5081-101b-9f08-00aa002f954e}\\" ascii wide
        $p5 = "%sRECYCLER.{645ff040-5081-101b-9f08-00aa002f954e}\\" ascii wide
        $c1 = "CONNECT %s:%u HTTP/1." ascii wide
        $c2 = "User-Agent: Mozilla/4.0" ascii wide
        $m1 = "winsupdatetw" fullword ascii wide
        $m2 = "clientsix" fullword ascii wide
        $m3 = "updatethres" fullword ascii wide
        $m4 = "uwatchdaemon" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or (all of ($c*) and (2 of ($s*) or 1 of ($m*) or 1 of ($p*))) or (1 of ($m*) and 1 of ($s*) and (1 of ($c*) or 1 of ($p*))))
}

/*
Too many FPs
rule MALWARE_Win_DLAgent13 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader agent. Observed to drop AceRAT"
    strings:
        $x1 = "Dropper" fullword ascii
        $x2 = "/C chcp 65001 && ping 127.0.0.1 && DEL" wide
        $x3 = "&& ping 127.0.0.1 && DEL /F /S /Q /A \"" wide
        $s1 = "WebClient" fullword ascii
        $s2 = "DownloadFile" fullword ascii
        $s3 = "ProcessStartInfo" fullword ascii
        $s4 = "set_FileName" fullword ascii
        $s5 = "GetTempPath" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of($x*) or (2 of ($x*) and 3 of ($s*)))
}
*/

rule MALWARE_Win_DLAgent14 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader injector"
    strings:
        $s1 = "%ProgramData%\\AVG" fullword wide
        $s2 = "%ProgramData%\\AVAST Software" fullword wide
        $s3 = "%wS\\%wS.vbs" fullword wide
        $s4 = "%wS\\%wS.exe" fullword wide
        $s5 = "CL,FR,US,CY,FI,HR,HU,RO,PL,IT,PT,ES,CA,DK,AT,NL,AU,AR,NP,SE,BE,NZ,SK,GR,BG,NO,GE" ascii
        $s6 = "= CreateObject(\"Microsoft.XMLHTTP\")" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_MarkiRAT {
    meta:
        author = "ditekSHen"
        description = "Detects MarkiRAT"
    strings:
        $pdb = "\\mfcmklg.pdb" ascii
        $s1 = "runinhome Completed" wide
        $s2 = "ERROR find next file<br>" wide
        $s3 = "<br><mark>Hello: %s</mark>" wide
        $s4 = "<br><mark>CLIPBOARD[" wide
        $s5 = "@userhome@" wide
        $s6 = "Global\\{2194ABA1-BFFA-4e6b-8C26-D1BB20190312}" wide
        $s7 = "taskkill /im svehost.exe /t /f" fullword ascii
        $s8 = "taskkill /im keepass.exe /t /f" fullword ascii
        $ba = /bitsadmin \/(addfile|cancel|SetPriority|resume)/ ascii wide
        $c1 = "/ech/client.php?u=" wide
        $c2 = "/up/uploadx.php?u=" wide
        $c3 = "/ech/echo.php?req=rr&u=" wide
        $c4 = "/ech/rite.php" wide
        $c5 = "http://microsoft.com-view.space/i.php?u=" wide
        $c6 = "Content-Disposition: form-data; name=\"uploadedfile\"; filename=\"" ascii
    condition:
        uint16(0) == 0x5a4d and (($pdb and any of them) or (5 of ($s*)) or (3 of ($c*)) or ((#ba > 3 and 4 of them)))
}

rule MALWARE_Win_KlingonRAT {
    meta:
        author = "ditekSHen"
        description = "Detects KlingonRAT"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "/UCRelease/src/client/uac/once/"
        $s2 = "%T\\AppData\\Local\\Windows Update\\"
        $s3 = "%TSoftware\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
        $s4 = "wmic /namespace:'\\\\root\\subscription' PATH"
        $s5 = "C:\\Windows\\System32\\fodhelper.exeCaption,ParentProcessId,ProcessId"
        $s6 = "ldpro.exelsass.exeluall.exeluspt.exe"
        $s7 = "scangui.exedeps/lsass.exeetrustcipe.exefile"
        $s8 = "alogserv.exeaplica32.exeapvxdwin.exeatro55en.exeautodown.exeavconsol.exeavgserv9.exeavkwctl9.exeavltmain.exeavpdos32.exeavsynmgr.exeavwupd32.exeavwupsrv.exe"
        $c1 = "%s/keyLogger?machineId=%s" ascii
        $c2 = "%s/stealer?machineId=%s" ascii
        $c3 = "%s/lsass?machineId=%s" ascii
        $c4 = "%s/logger?machineId=%s" ascii
        $c5 = "%s/machineInfo?machineId=%s" ascii
        $c6 = "failurehttps://%s:%d/botif-modified-sinceillegal" ascii
    condition:
        uint16(0) == 0x5a4d and ($go) and (3 of ($c*) or 5 of ($s*) or (3 of ($s*) and 1 of ($c*)))
}

rule MALWARE_Win_BotSh1zoid {
    meta:
        author = "ditekSHen"
        description = "Detects BotSh1zoid"
    strings:
        $x1 = "\\BotSh1zoid\\" ascii
        $x2 = "\\BuildPacker.pdb" ascii
        $s1 = "WDefender" fullword ascii
        $s2 = "CheckDefender" fullword ascii
        $s3 = "RunPS" fullword ascii
        $s4 = "DownloadFile" fullword ascii
        $v1_1 = "<Pass encoding=\"base64\">(.*)</Pass>" wide
        $v1_2 = "Grabber\\" wide
        $v1_3 = "/log.php" wide
        $v1_4 = /Browsers\\(Logins|Cards|Cookies)/ wide
        $v1_5 = "<StealSteam>b__" ascii
        $v1_6 = "record_header_field" fullword ascii
        $v1_7 = "JavaScreenshotiptReader" fullword ascii
        $v1_8 = "HTTPDebuggerPro" wide
        $v1_9 = "IEInspector" wide
        $v1_10 = "Fiddler" wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or (7 of ($v1*)))
}

rule MALWARE_Win_AllaKore {
     meta:
        author = "ditekSHen"
        description = "Detects AllaKore"
    strings:
        $x1 = "AllaKore Remote - Chat" fullword wide
        $x2 = "AllaKore Remote - Share Files" fullword wide
        $x3 = "CYRUS - Chat" fullword wide
        $x4 = "CYRUS - Share Files" fullword wide
        $x5 = "<|REDIRECT|><|GETFOLDERS|>" fullword wide
        $x6 = "<|REDIRECT|><|DOWNLOADFILE|>" fullword wide
        $x7 = "<|REDIRECT|><|WHEELMOUSE|>" fullword wide
        $x8 = "<|REDIRECT|><|SETMOUSE" wide
        $x9 = "<|CHECKIDPASSWORD|>" fullword wide
        $x10 = "<|KEYBOARDSOCKET|>" fullword wide
        $x11 = "<|REDIRECT|><|CLIPBOARD|>" fullword wide
        $x12 = "<|IDEXISTS!REQUESTPASSWORD|>" fullword wide
        $x13 = "<|GETFULLSCREENSHOT|>" fullword wide
        $x14 = "<|MAINSOCKET|>" fullword ascii
        $s1 = "You can not connect with yourself!" wide
        $s2 = "Waiting for authentication..." wide
        $s3 = "Connected support!" wide
        $s4 = "ID does nor exists." wide
        $s5 = "Finding the ID..." wide
        $s6 = "PC is Busy!" wide
        $s7 = "Upload &  Execute" fullword ascii
        $s8 = "Download file selected" fullword ascii
        $s9 = "CaptureKeys_TimerTimer" fullword ascii
        $s10 = "Remote File Manager" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or 4 of ($s*) or (3 of ($s*) and 2 of ($x*)))
}

rule MALWARE_Win_ReverseRAT {
     meta:
        author = "ditekSHen"
        description = "Detects ReverseRAT"
    strings:
        $pdb1 = "\\ReverseRat.pdb" ascii nocase
        $pdb2 = "\\ReverseRat\\obj\\" ascii nocase
        $s1 = "processCmd" fullword ascii
        $s2 = "CmdOutputDataHandler" fullword ascii
        $s3 = "sendingProcess" fullword ascii
        $s4 = "SetStartup" fullword ascii
        $s5 = "RunServer" fullword ascii
        $s6 = "_OutputDataReceived" ascii
        $s7 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 
                00 03 0a 00 00 13 74 00 65 00 72 00 6d 00
                69 00 6e 00 61 00 74 00 65 00 00 09 65 00
                78 00 69 00 74 00 }
    condition:
        uint16(0) == 0x5a4d and ((1 of ($pdb*) and 2 of ($s*)) or 5 of ($s*))
}

rule MALWARE_Win_SmokeLoader {
    meta:
        author = "ditekSHen"
        description = "Detects SmokeLoader variants"
    strings:
        $x1 = "G2A/CLP/05/RYS" fullword wide // mutex
        $x2 = "0N1Y/53R10U5/BU51N355" fullword wide // mutex
        $x3 = "CH4PG3PB-6HT2VI9C-O2NL2NO5-QP1BW0EG" fullword wide // mutex
        $s1 = "Azure-Update-Task" fullword wide
        $s2 = "C:\\Windows\\System32\\schtasks.exe" fullword wide
        $s3 = "/C /create /F /sc minute /mo 1 /tn \"" fullword wide
        $s4 = "\\Microsoft\\Network" fullword wide
        $s5 = "\\Microsoft\\TelemetryServices" fullword wide
        $s6 = "\" /tr \"" fullword wide
        $e1 = "\\sqlcmd.exe" fullword wide
        $e2 = "\\sihost.exe" fullword wide
        $e3 = "\\fodhelper.exe" fullword wide
        //$o1 = { 6a 34 59 66 39 0e 75 7c 0f b7 46 02 6a 30 5a 83 }
        //$o2 = { 5e c9 c3 56 8d 85 f8 fd ff ff 50 8d 85 f0 fb ff }
        //$o3 = { 8b d9 eb 03 8b 5d ec 0f b7 c2 89 45 ec 0f b7 c2 }
        //$o4 = { 8b 5d fc 66 89 04 77 46 eb 2a 8b 5d fc 85 db 74 }
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 4 of ($s*)) or (5 of ($s*) and 1 of ($e*)))
}

rule MALWARE_Win_DLInjector03 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown loader / injector"
    strings:
        $x1 = "LOADER ERROR" fullword ascii
        $s1 = "_ZN6curlpp10OptionBaseC2E10CURLoption" fullword ascii
        $s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_CoinMiner02 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
    strings:
        $s1 = "%s/%s (Windows NT %lu.%lu" fullword ascii
        $s2 = "\\Microsoft\\Libs\\WR64.sys" wide
        $s3 = "\\\\.\\WinRing0_" wide
        $s4 = "pool_wallet" ascii
        $s5 = "cryptonight" ascii
        $s6 = "mining.submit" ascii
        $c1 = "stratum+ssl://" ascii
        $c2 = "daemon+http://" ascii
        $c3 = "stratum+tcp://" ascii
        $c4 = "socks5://" ascii
        $c5 = "losedaemon+https://" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) and 1 of ($c*))
}

rule MALWARE_Win_Mercurial {
    meta:
        author = "ditekSHen"
        description = "Detects Mercurial infostealer"
    strings:
        $x1 = "mercurial grabber" wide nocase
        $x2 = "\"text\":\"Mercurial Grabber |" wide
        $x3 = "/nightfallgt/mercurial-grabber" wide
        $s1 = "/LimerBoy/Adamantium-Thief/" ascii
        $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0" fullword wide
        $s3 = "StealCookies" fullword ascii
        $s4 = "StealPasswords" fullword ascii
        $s5 = "DetectDebug" fullword ascii
        $s6 = "CaptureScreen" fullword ascii
        $s7 = "WebhookContent" fullword ascii
        $s8 = /Grab(Token|Product|IP|Hardware)/ fullword ascii
        $p1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" fullword ascii wide
        $p2 = "mfa\\.[\\w-]{84}" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or 5 of ($s*) or (all of ($p*) and 3 of ($s*)))
}

rule MALWARE_Win_Phonzy {
    meta:
        author = "ditekSHen"
        description = "Detects specific downloader agent"
    strings:
        $ua1 = "User-Agent: Mozilla/5.0 (X11; Linux" wide
        $s1 = "<meta name=\"keywords\" content=\"([\\w\\d ]*)\">" fullword wide
        $s2 = "WebClient" fullword ascii
        $s3 = "WriteAllText" fullword ascii
        $s4 = "DownloadString" fullword ascii
        $s5 = "WriteByte" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($ua*) and ($s1) and 2 of ($s*)))
}

rule MALWARE_Win_Hive {
    meta:
        author = "ditekSHen"
        description = "Detects Hive ransomware"
    strings:
        $url1 = "http://hivecust" ascii
        $url2 = "http://hiveleakdb" ascii
        $s1 = "encrypt_files.go" ascii
        $s2 = "erase_key.go" ascii
        $s3 = "kill_processes.go" ascii
        $s4 = "remove_shadow_copies.go" ascii
        $s5 = "stop_services_windows.go" ascii
        $s6 = "remove_itself_windows.go" ascii
        $x1 = "/encryptor/" ascii
        $x2 = "HOW_TO_DECRYPT.txt" ascii
        $x3 = "FilesEncrypted" fullword ascii
        $x4 = "EncryptionStarted" fullword ascii
        $x5 = "encryptFilesGroup" fullword ascii
        $x6 = "Your data will be undecryptable" ascii
        $x7 = "- Do not fool yourself. Encryption has perfect secrecy" ascii
        $v1_1 = ".EncryptFiles." ascii
        $v1_2 = ".EncryptFilename." ascii
        $v1_3 = ")*struct { F uintptr; .autotmp_14 string }" ascii
        $v1_4 = "D*struct { F uintptr; data *[]uint8; seed *uint8; fnc *main.decFunc }" ascii
        $v1_5 = "golang.org/x/sys/windows.getSystemWindowsDirectory" ascii
        $v1_6 = "path/filepath.WalkDir" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($url*) or all of ($s*) or 4 of ($x*) or 5 of ($v1*))
}

rule MALWARE_Win_Spyro {
    meta:
        author = "ditekSHen"
        description = "Detects Spyro / VoidCrypt / Limbozar ransomware"
    strings:
        $s1 = "Decrypt-info.txt" ascii wide
        $s2 = "AbolHidden" ascii wide
        $s3 = "C:\\ProgramData\\prvkey" ascii wide
        $s4 = ".?AV?$TF_CryptoSystemBase@VPK_Encryptor@CryptoPP" ascii
        $s5 = "C:\\Users\\LEGION\\" ascii
        $s6 = "C:\\ProgramData\\pkey.txt" fullword ascii
        $s7 = ".Spyro" fullword ascii
        $m1 = "Go to C:\\ProgramData\\ or in Your other Drives" wide
        $m2 = "saving prvkey.txt.key file will cause" wide
        $m3 = "in Case of no Answer:" wide
        $m4 = "send us prvkey*.txt.key" wide
        $m5 = "Somerhing went wrong while writing payload on disk" ascii
        $m6 = "this country is forbidden.\"}" ascii
        $c1 = "Voidcrypt/1.0" ascii
        $c2 = "h1dd3n.cc" ascii
        $c3 = "/voidcrypt/index.php" ascii
        $c4 = "&user=" ascii
        $c5 = "&disk-size=" ascii
        $c6 = "unique-id=" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 4 of ($c*) or 3 of ($m*) or 8 of them)
}

rule MALWARE_Win_DarkVNC {
    meta:
        author = "ditekSHen"
        description = "Detects DarkVNC"
    strings:
        $s1 = "USR-%s(%s)_%S-%S%u%u" fullword wide
        $s2 = "BOT-%s(%s)_%S-%S%u%u" fullword wide
        $s3 = "USR-UnicodeErr(Err)_%s-%s%u%u" fullword ascii
        $s4 = "BOT-UnicodeErr(Err)_%s-%s%u%u" fullword ascii
        $s5 = "PRM_STRG" fullword wide
        $s6 = "bot_shell >" ascii
        $s7 = "monitor_off / monitor_on" ascii
        $s8 = "kbd_off / kbd_on" ascii
        $s9 = "ActiveDll: Dll inject thread for process 0x%x terminated with status: %u" ascii
        $s10 = "PsSup: File %s successfully started with parameter \"%s\"" ascii
        $s11 = "PsSup: ShellExecute failed. File: %s, error %u" ascii
        $s12 = "#hvnc" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_RSJON {
    meta:
        author = "ditekSHen"
        description = "Detects RSJON / Ryzerlo / HiddenTear ransomware"
    strings:
        $pdb1 = "C:\\Users\\brknc\\source\\repos\\" ascii
        $pdb2 = "\\rs-jon\\obj\\Debug\\rs-jon.pdb" ascii
        $pdb3 = "\\rs-jon\\obj\\Release\\rs-jon.pdb" ascii
        $x1 = "READ_ME_PLZ.txt" wide
        $x2 = "Files has been encrypted with rs-jon" wide
        $x3 = ".rsjon" wide
        $x4 = "bitcoins or kebab" wide
        $x5 = /rs[-_]jon/ fullword ascii wide
        $s1 = "SPIF_UPDATEINIFILE" fullword ascii
        $s2 = "SPI_SETDESKWALLPAPER" fullword ascii
        $s3 = "bytesToBeEncrypted" fullword ascii // Same as Apsotle
        $s4 = "SendPassword" fullword ascii
        $s5 = "EncryptFile" ascii
        $s6 = "fWinIni" fullword ascii
        $s7 = "BTCAdress" fullword ascii
        $s8 = "self_destruck" fullword ascii // Simialr to Apsotle (SelfDelete)
        $c1 = "?computer_name=" wide
        $c2 = "&serialnumber=" wide
        $c3 = "&password=" wide
        $c4 = "&allow=ransom" wide
        $c5 = "://darkjon.tk/" wide
        $c6 = "/rnsm/write.php" wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or 6 of ($s*) or 4 of ($c*) or (2 of ($c*) and 4 of ($s*)) or (1 of ($pdb*) and 1 of them))
}

rule MALWARE_Win_BoxCaon {
    meta:
        author = "ditekSHen"
        description = "Detects IndigoZebra BoxCaon"
    strings:
        $s1 = "<RetCMD null>" fullword wide
        $s2 = "<txt null>" fullword wide
        $s3 = "C:\\Users\\Public\\%d\\" fullword wide
        $s4 = "api.dropboxapi.com" fullword wide
        $s5 = "/2/files/upload" fullword wide
        $ts1 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" ascii wide
        $ts2 = "%s /A /C \"%s\" > %s" ascii wide
        $ts3 = "ersInfo" ascii wide
        $ts4 = "%svmpid%d.log" ascii wide
        $ts5 = "%scscode%d.log" ascii wide
    condition:
        (uint16(0) == 0x5a4d and all of ($s*)) or all of ($ts*)
}

rule MALWARE_Win_AvosLocker {
    meta:
        author = "ditekSHen"
        description = "Hunt for AvosLocker ransomware"
    strings:
        $s1 = "GET_YOUR_FILES_BACK.txt" ascii wide
        $s2 = ".avos" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Diavol {
    meta:
        author = "ditekSHen"
        description = "Detects Diavol ransomware"
    strings:
        $s1 = "README_FOR_DECRYPT.txt" ascii wide nocase
        $s2 = ".lock64" fullword ascii wide
        $s3 = "LockMainDIB" ascii wide
        $s4 = "locker.divided" ascii wide
        $s5 = "%tob_dic%/" wide
        $s6 = "%cid_bot%" wide
        $m1 = "GENBOTID" ascii wide
        $m2 = "SHAPELISTS" ascii wide
        $m3 = "REGISTER" ascii wide
        $m4 = "FROMNET" ascii wide
        $m5 = "SERVPROC" ascii wide
        $m6 = "SMBFAST" ascii wide
        $c1 = "/Bnyar8RsK04ug/" fullword ascii
        $c2 = "/landing" fullword ascii
        $c3 = "/wipe" fullword ascii
        $c4 = "&ip_local1=111.111.111.111&ip_local2=222.222.222.222&ip_external=2.16.7.12" fullword ascii
        $c5 = "&group=" fullword ascii
        $c6 = "/BnpOnspQwtjCA/register" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or 5 of ($m*) or 4 of ($c*) or 7 of them)
}

rule MALWARE_Win_MargulasRAT {
    meta:
        author = "ditekSHen"
        description = "Detects MargulasRAT"
    strings:
        $pdb1 = "G:\\VP-S-Fin\\memory\\" ascii
        $pdb2 = "G:\\VP-S-Fin\\Margulas\\" ascii
        $pdb3 = "G:\\VP-S-Fin\\remote" ascii
        $pdb4 = "G:\\VP-S-Fin\\" ascii
        $s1 = "/C choice /C Y /N /D Y /T 1 & Del " fullword wide
        $s2 = "strToHash" fullword ascii
        $s3 = "\\socking" fullword wide
        $s4 = "\\wininets" fullword wide
        $s5 = "ClientSocket" fullword ascii
        $s6 = "new Stream()" fullword wide
        $s7 = "CipherText" fullword ascii
        $s8 = "WriteAllBytes" fullword ascii
        $s9 = { 00 50 72 6f 63 65 73 73 00 45 78 69 73 74 73 00}
        $s10 = "pxR/THCwdLuruMmw8wB8xAUvbno1yPGBTOV9IoOkAp/n7+paQm74pkzlfSKDpAKfTOV9IoOkAp9M5X0ig6QCn0zlfSKDpAKfTOV9IoOkAp" wide
        $c1 = "149.248.52.61" wide
        $c2 = "://vpn.nic.in" wide
        $c3 = "://www.mod.gov.in/dod/sites/default/files/" wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($pdb*) and (1 of ($c*) or 3 of ($s*))) or (1 of ($c*) and 3 of ($s*)) or (6 of ($s*)))
}

rule MALWARE_Win_LilithRAT {
    meta:
        author = "ditekSHen"
        description = "Detects LilithRAT"
        hash1 = "132870a1ae6a0bdecaa52c03cfe97a47df8786f148fa8ca113ac2a8d59e3624a"
        hash2 = "ab7b6e0b28995bdeea44f20c0aba47f95e1d6ba281af3541cd2c04dc6c2a3ad9" // actor testing?
        hash3 = "b2eeb487046ba1d341fb964069b7e83027b60003334e04e41b467e35c3d2460f"
        hash4 = "cebcda044c60b709ba4ee0fa9e1e7011a6ffc17285bcc0948d27f866ec8d8f20"
    strings:
        $pdb1 = "c:\\Users\\Groovi\\Documents\\Visual Studio 2008\\Projects\\TestDll\\" ascii
        $pdb2 = "C:\\Users\\iceberg\\Downloads\\RAT-Server-master\\RAT-Server-master\\RAT\\Debug\\RAT.pdb" ascii
        $pdb3 = "C:\\Users\\Samy\\Downloads\\Compressed\\Lilith-master\\Debug\\Lilith.pdb" ascii
        $s1 = "log.txt" fullword ascii
        $s2 = "keylog.txt" fullword ascii
        $s3 = "File Listing Completed Successfully." fullword ascii
        $s4 = "Download Execute" fullword ascii
        $s5 = "File Downloaded and Executed Successfully." fullword ascii
        $s6 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii
        $s7 = "CMD session closed" ascii
        $s8 = "Restart requested: Restarting self" fullword ascii
        $s9 = "Termination requested: Killing self" fullword ascii
        $s10 = "Couldn't write to CMD: CMD not open" fullword ascii
        $s11 = "keydump" fullword ascii
        $s12 = "remoteControl" fullword ascii
        $s13 = "packettype" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($pdb*) or 6 of ($s*) or (1 of ($pdb*) and 4 of ($s*)))
}

rule MALWARE_Win_EpicenterRAT {
    meta:
        author = "ditekSHen"
        description = "Detects EpicenterRAT"
    strings:
        $pdb1 = "c:\\Users\\Zombie\\Desktop\\MutantNinja\\" ascii
        $pdb2 = "\\Epicenter Client\\" ascii
        $s1 = "PROCESS_LIST<%SEP%>" fullword wide
        $s2 = "GETREADY_RECV_FILE<%SEP%>" fullword wide
        $s3 = "DISPLAY<%SEP%>" wide
        $s4 = "GETSCREEN<%SEP%>" fullword wide
        $s5 = "dumpImageName" fullword ascii
        $s6 = "dumpLoc" fullword ascii
        $s7 = "EXPECT<%SEP%>filelist<%SEP%>" fullword wide
        $s8 = "<%FSEP%>FOLDER<%FSEP%>-<%SEP%>" fullword wide
        $s9 = "KILLPROC<%SEP%>" fullword wide
        $s10 = "LAUNCHPROC<%SEP%>" fullword wide
        $s11 = "cmd.exe /c start /b " fullword wide
        $s12 = "savservice" fullword wide
        $s13 = "getvrs" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($pdb*) or 5 of ($s*))
}

rule MALWARE_Win_LastConn {
    meta:
        author = "ditekSHen"
        description = "Detects LastConn"
    strings:
        $s1 = "System.Net.Http.SysSR" fullword wide
        $s2 = "System.Net.Http.WrSR" fullword wide
        $s3 = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFFK" fullword wide
        $s4 = { 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 0c 6e
               00 6f 00 74 00 69 00 66 00 79 00 04 06 12 80 e8
               05 00 00 12 80 e8 08 75 00 73 00 65 00 72 00 08
               74 00 65 00 61 00 6d 00 06 61 00 70 00 70 00 0c
               6e 00 6f 00 61 00 75 00 74 00 68 00 }
        $s5 = { 68 00 69 00 64 00 64 00 65 00 6e 00 10 64 00 69
               00 73 00 61 00 6c 00 6c 00 6f 00 77 00 0e 65 00
               78 00 74 00 65 00 6e 00 64 00 73 00 04 69 00 64
               00 16 75 00 6e 00 69 00 71 00 75 00 65 00 49 00
               74 00 65 00 6d 00 73 }
        $s6 = "<RunFileOnes>d__" ascii
        $s7 = "<UploadFile>d__" ascii
        $s8 = "<ChunkUpload>d__" ascii
        $s9 = "<StartFolder>d__" ascii
        $s10 = "<ReadFileAlw>d__" ascii
        $s12 = "<WriteFileToD>d__" ascii
        $s13 = "<ReadFile>d__" ascii
        $s14 = "<GetUpload>d__" ascii
        $s15 = "CDropbox.Api.DropboxRequestHandler+<RequestJsonStringWithRetry>d__" ascii
    condition:
        uint16(0) == 0x5a4d and 12 of them
}

rule MALWARE_Win_CrimsonRAT {
    meta:
        author = "ditekSHen"
        description = "Detects CrimsonRAT"
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" fullword wide
        $s2 = "system volume information|" fullword wide
        $s3 = "program files (x86)|" fullword wide
        $s4 = "program files|" fullword wide
        $s5 = "<SAVE_AUTO<|" fullword wide
        $s6 = "add_up_files" fullword ascii
        $s7 = "see_folders" ascii
        $s8 = "see_files" ascii
        $s9 = "see_scren" ascii
        $s10 = "see_recording" ascii
        $s11 = "see_responce" ascii
        $s12 = "pull_data" ascii
        $s13 = "do_process" ascii
        $s14 = "do_updated" ascii
        $s15 = "IPSConfig" fullword ascii
        $s16 = "#Runing|ver#" wide
        $s17 = "|fileslog=" wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_ActionRAT {
    meta:
        author = "ditekSHen"
        description = "Detects ActionRAT, CSharp and Delfi variants"
    strings:
        $x1 = /<action>(connect|command|drives|getfiles|upload|execute|download)<action>/ fullword wide
        $x2 = "aHR0cDovLzE0NC45MS42NS4xMDAv" wide
        $x3 = "aHR0cDovL21mYWhvc3QuZGRucy5uZXQv" wide
        $f1 = "<updateCommand>b__" ascii
        $f2 = "<getDrives>b__" ascii
        $f3 = "<getStatus>b__" ascii
        $f4 = "<getDirectories>b__" ascii
        $f5 = "<updateUpload>b__" ascii
        $f6 = "<infinity>b__" ascii
        $f7 = "<uploadFile>b__" ascii
        $s1 = "beaconURL" ascii
        $s2 = "PingReply" ascii
        $s3 = "updateUpload" ascii
        $s4 = "updateCommand" ascii
        $s5 = "runCommand" ascii
        $s6 = "uploadFile" ascii
        $s7 = "SELECT * FROM MSFT_NetAdapter WHERE ConnectorPresent = True AND DeviceID = '{0}'" fullword wide
        $s8 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s9 = "Mozilla/3.0" fullword wide
        $s10 = "|directory|N/A|" fullword wide
        $s11 = "cmd.exe /c" fullword wide
        $c1 = /Content-Disposition: form-data; name=(hostname|hid|id|action|secondary)/ fullword wide
        $c2 = /(classification|updatecs|update|beacon)\.php/ wide
        $c3 = "Content-Disposition: form-data;name=\"{0}\";filename=\"{1}\"filepath=\"{2}\"" fullword wide
        $pdb1 = "D:\\Projects\\C#\\HTTP-Simple\\WindowsMediaPlayer - HTTP - " ascii
        $pdb2 = "\\WindowsMediaPlayer10\\obj\\x86\\Release\\winow4.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (#x1 > 5 or (all of ($f*) and (1 of ($s*) or 2 of ($c*))) or 7 of ($s*) or all of ($c*) or (all of ($pdb*) and 4 of them) or ( 2 of ($x*) and 5 of them))
}

rule MALWARE_Win_Nodachi {
    meta:
        author = "ditekSHen"
        description = "Detects Nodachi infostealer"
    strings:
        $x1 = "//AppData//Roaming//kavachdb//kavach.db" ascii
        $s1 = "/upload/drive/v3/files/{fileId}" ascii
        $s2 = "main.getTokenFromWeb" ascii
        $s3 = "main.tokenFromFile" ascii
        $s4 = "/goLazagne/" ascii
        $s5 = "/extractor/withoutdrive/main.go" ascii
        $s6 = "struct { Hostname string \"json:\\\"hostname\\\"\"; EncryptedUsername string \"json:\\\"encryptedUsername\\\"\"; EncryptedPassword string \"json:\\\"encryptedPassword\\\"\" }" ascii
        $s7 = "C://Users//public//cred.json" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or (4 of ($s*)))
}

rule MALWARE_Win_IAmTheKingQueenOfHearts {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing Queen Of Hearts payload"
    strings:
        $s1 = "{'session':[{'name':'" ascii
        $s2 = "begin mainthread ok" wide
        $s3 = "getcommand error" wide
        $s4 = "querycode error" wide
        $s5 = "Code = %d" wide
        $s6 = "cookie size :%d" wide
        $s7 = "send request error:%d" wide
        $s8 = "PmMytex%d" wide
        $s9 = "%s_%c%c%c%c_%d" wide
        $s10 = "?what@exception@std@@UBEPBDXZ" ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_IAmTheKingQueenOfClubs {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing Queen Of Clubs payload"
    strings:
        $s1 = "Not Support!" fullword wide
        $s2 = "%s|%s|%s|%s" fullword wide
        $s3 = "cmd.exe" fullword wide
        $s4 = "for(;;){$S=Get-Content \"%s\";IF($S){\"\" > \"%s\";$t=iex $S 2>\"%s\";$t=$t+' ';echo $t >>\"%s\";}sleep -m " wide
        $s5 = "PowerShell.exe -nop -c %s" fullword wide
        $s6 = "%s \"%s\" Df" fullword wide
        $s7 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_IAmTheKing {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing payload"
    strings:
        $s1 = "DeleteFile \"%s\" Failed,Err=%d" wide
        $s2 = "DeleteFile \"%s\" Success" wide
        $s3 = "ExcuteFile \"%s\" Failed,Err=%d" wide
        $s4 = "ExcuteFile \"%s\" Success" wide
        $s5 = "CreateDownLoadFile \"%s\" Failed,Error=%d" wide
        $s6 = "uploadFile \"%s\" Failed,errorcode=%d" wide
        $s7 = "CreateUpLoadFile \"%s\" Success" wide
        $s8 = "im the king" ascii
        $s9 = "dont disturb me" fullword ascii
        $s10 = "kill me or love me" fullword ascii
        $s11 = "please leave me alone" fullword ascii
        $s12 = "calculate the NO." fullword ascii
        $s13 = "\\1-driver-vmsrvc" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule MALWARE_Win_GoBrut {
    meta:
        author = "ditekSHen"
        description = "Detects unknown Go multi-bruteforcer bot (StealthWorker / GoBrut) against multiple systems: QNAP, MagOcart, WordPress, Opencart, Bitrix, Postgers, MySQL, Drupal, Joomla, SSH, FTP, Magneto, CPanel"
    strings:
        $x1 = "/src/StealthWorker/Worker" ascii
        $x2 = "/go/src/Cloud_Checker/" ascii
        $x3 = "brutXmlRpc" ascii
        $s1 = "main.WPBrut" ascii
        $s2 = "main.WPChecker" ascii
        $s3 = "main.WooChecker" ascii
        $s4 = "main.StandartBrut" ascii
        $s5 = "main.StandartBackup" ascii
        $s6 = "main.WpMagOcartType" ascii
        $s7 = "main.StandartAdminFinder" ascii
        $w1 = "/WorkerQnap_brut/main.go" ascii
        $w2 = "/WorkerHtpasswd_brut/main.go" ascii
        $w3 = "/WorkerOpencart_brut/main.go" ascii
        $w4 = "/WorkerBitrix_brut/main.go" ascii
        $w5 = "/WorkerPostgres_brut/main.go" ascii
        $w6 = "/WorkerMysql_brut/main.go" ascii
        $w7 = "/WorkerFTP_brut/main.go" ascii
        $w8 = "/WorkerSSH_brut/main.go" ascii
        $w9 = "/WorkerDrupal_brut/main.go" ascii
        $w10 = "/WorkerJoomla_brut/main.go" ascii
        $w11 = "/WorkerMagento_brut/main.go" ascii
        $w12 = "/WorkerWHM_brut/main.go" ascii
        $w13 = "/WorkerCpanel_brut/main.go" ascii
        $w14 = "/WorkerPMA_brut/main.go" ascii
        $w15 = "/WorkerWP_brut/main.go" ascii
        $p1 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=cpanel" ascii
        $p2 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=ftpBrut" ascii
        $p3 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=mysql_b" ascii
        $p4 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=qnapBrt" ascii
        $p5 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=OCartBrt" ascii
        $p6 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=phpadmin" ascii
        $p7 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=bitrixBrt" ascii
        $p8 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=drupalBrt" ascii
        $p9 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=joomlaBrt" ascii
        $p10 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=htpasswdBrt" ascii
        $p11 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=magentoBrt" ascii
        $p12 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=postgres_b" ascii
        $p13 = "AUTH_FORM=Y&TYPE=AUTH&USER_LOGIN=%s&USER_PASSWORD=%s&Login=&captcha_sid=&captcha_word=" ascii
        $p14 = "%qlog=%s&pwd=%s&wp-submit=Log In&redirect_to=%s/wp-admin/&testcookie=1" ascii
        $p15 = "name=%s&pass=%s&form_build_id=%s&form_id=user_login_form&op=Log" ascii
        $p16 = "username=%s&passwd=%s&option=com_login&task=login&return=%s&%s=1" ascii
        $v1_1 = "brutC" fullword ascii
        $v1_2 = "XmlRpc" fullword ascii
        $v1_3 = "shouldRetry$" ascii
        $v1_4 = "HttpC|%" ascii
        $v1_5 = "ftpH%_" ascii
        $v1_6 = "ssh%po" ascii
        $v1_7 = "?sevlyar/4-da" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and ((2 of ($x*) and 3 of ($s*)) or all of ($s*) or 6 of ($w*) or 6 of ($p*) or 6 of ($v1*) or 12 of them)
}

rule MALWARE_Win_BioPass_Dropper {
    meta:
        author = "ditekSHen"
        description = "Detects Go BioPass dropper"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "main.NetWorkStatus" ascii
        $s2 = "main.NoErrorRunFunction" ascii
        $s3 = "main.FileExist" ascii
        $s4 = "main.execute" ascii
        $s5 = "main.PsGenerator" ascii
        $s6 = "main.downFile" ascii
        $s7 = "main.Unzip" ascii
        $url1 = "https://flashdownloadserver.oss-cn-hongkong.aliyuncs.com/res/" ascii
        $x1 = "SCHTASKS /Run /TN SYSTEM_CDAEMON" ascii
        $x2 = "SCHTASKS /Run /TN SYSTEM_SETTINGS" ascii
        $x3 = "SCHTASKS /Run /TN SYSTEM_TEST && SCHTASKS /DELETE /F /TN SYSTEM_TEST" ascii
        $x4 = ".exe /install /quiet /norestart" ascii
        $x5 = "exec(''import urllib.request;exec(urllib.request.urlopen(urllib.request.Request(\\''http" ascii
        $x6 = "powershell.exe -Command $" ascii
        $x7 = ".Path ='-----BEGIN RSA TESTING KEY-----" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($x*) or (1 of ($url*) and ($go)) or 9 of them)
}

rule MALWARE_Win_A310Logger {
    meta:
        author = "ditekSHen"
        description = "Detects A310Logger"
        snort_sid = "920204-920207"
    strings:
        $s1 = "Temporary Directory * for" fullword wide
        $s2 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*RD_" wide
        $s3 = "@ENTIFIER=" wide
        $s4 = "ExecQuery" fullword wide
        $s5 = "MSXML2.ServerXMLHTTP.6.0" fullword wide
        $s6 = "Content-Disposition: form-data; name=\"document\"; filename=\"" wide
        $s7 = "CopyHere" fullword wide
        $s8 = "] Error in" fullword wide
        $s9 = "shell.application" fullword wide nocase
        $s10 = "SetRequestHeader" fullword wide
        $s11 = "\\Ethereum\\keystore" fullword wide
        $s12 = "@TITLE Removing" fullword wide
        $s13 = "@RD /S /Q \"" fullword wide
        $en1 = "Unsupported encryption" fullword wide
        $en2 = "BCryptOpenAlgorithmProvider(SHA1)" fullword wide
        $en3 = "BCryptGetProperty(ObjectLength)" fullword wide
        $en4 = "BCryptGetProperty(HashDigestLength)" fullword wide
        // varaint 1
        $v1_1 = "PW\\FILES\\SC::" wide
        $v1_2 = "AddAttachment" fullword wide
        $v1_3 = "Started:" fullword wide
        $v1_4 = "Ended:" fullword wide
        $v1_5 = "sharedSecret" fullword wide
        $v1_6 = "\":\"([^\"]+)\"" fullword wide
        $v1_7 = "\\credentials.txt" fullword wide
        $v1_8 = "WritePasswords" fullword ascii
        $v1_9 = "sGeckoBrowserPaths" fullword ascii
        $v1_10 = "get_sPassword" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (3 of ($en*) and 4 of ($s*)) or (5 of ($s*) and 1 of ($en*)) or 5 of ($v1*) or (4 of ($v1*) and 2 of ($s*) and 2 of ($en*)))
}

rule MALWARE_Win_CryLock {
    meta:
        author = "ditekSHen"
        description = "Detects CryLock ransomware"
    strings:
        $s1 = "Encrypted by BlackRabbit. (BR-" ascii
        $s2 = "{ENCRYPTENDED}" ascii
        $s3 = "{ENCRYPTSTART}" ascii
        $s4 = "<%UNDECRYPT_DATETIME%>" ascii
        $s5 = "<%RESERVE_CONTACT%>" ascii
        $s6 = "how_to_decrypt.hta" ascii wide
        $s7 = "END ENCRYPT ONLY EXTENATIONS" ascii
        $s8 = "END UNENCRYPT EXTENATIONS" ascii
        $s9 = "END COMMANDS LIST" ascii
        $s10 = "END PROCESSES KILL LIST" ascii
        $s11 = "END SERVICES STOP LIST" ascii
        $s12 = "END PROCESSES WHITE LIST" ascii
        $s13 = "END UNENCRYPT FILES LIST" ascii
        $s14 = "END UNENCRYPT FOLDERS LIST" ascii
        $s15 = "Encrypted files:" ascii
        $s16 = { 65 78 74 65 6e 61 74 69 6f 6e 73 00 ff ff ff ff
                 06 00 00 00 63 6f 6e 66 69 67 00 00 ff ff ff ff
                 (0a|0d 0a) 00 00 00 63 6f 6e 66 69 67 2e 74 78 
                 74 00 00 ff ff ff ff 03 00 00 00 68 74 61 }
        $p1 = "-exclude" fullword
        $p2 = "-makeff" fullword
        $p3 = "-full" fullword
        $p4 = "-nolocal" fullword
        $p5 = "-nolan" fullword
        $p6 = "\" -id \"" fullword
        $p7 = "\" -wid \"" fullword
        $p8 = "\"runas\"" fullword
        $p9 = " -f -s -t 00" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 6 of ($p*))
}

rule MALWARE_Win_DeepRats {
    meta:
        author = "ditekSHen"
        description = "Detects DeepRats ("
        hash1 = "1f8b7e1b14869d119c5de1f05330094899bd997fca4c322d852db85cbd9271e6"
    strings:
        $s1 = "https://freegeoip.live/json/https://myexternalip.com/rawin" ascii
        $s2 = "github.com/cretz/bine" ascii
        $s3 = "github.com/kbinani/screenshot" ascii
        $s4 = "socks5://%s:%d" ascii
        $s5 = "socks5://%s:%s@%s:%d" ascii
        $s6 = "http://%s:%d" ascii
        $s7 = "http://%s@%s:%d" ascii
        $s8 = "%SystemRoot%\\system32\\--CookieAuthentication" ascii
        $s9 = "tor_addr_" ascii
        $f1 = ".GetVnc" ascii
        $f2 = ".GetCommand" ascii
        $f3 = ".GetPayload" ascii
        $f4 = ".ListenCommands" ascii
        $f5 = ".ReceiveFile" ascii
        $f6 = ".RegisterImplant" ascii
        $f7 = ".Screenshot" ascii
        $f8 = ".SendFile" ascii
        $f9 = ".StartShell" ascii
        $f10 = ".UnregisterImplant" ascii
        $f11 = ".VncInstalled" ascii
        $f12 = ".PingPong" ascii
        $f13 = ".ListenCMD" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or 8 of ($f*))
}

rule MALWARE_Win_Gasket {
    meta:
        author = "ditekSHen"
        description = "Detects Gasket"
    strings:
        $s1 = "main.checkGasket" ascii
        $s2 = "main.connectGasket" ascii
        $s3 = "/cert/trust/dev/stderr/dev/stdout/index.html" ascii
        $f1 = ".SetPingHandler." ascii
        $f2 = ".SetPongHandler." ascii
        $f3 = ".computeMergeInfo." ascii
        $f4 = ".computeDiscardInfo." ascii
        $f5 = ".readPlatformMachineID." ascii
        $f6 = ".(*Session).establishStream." ascii
        $f7 = ".(*Session).handleGoAway." ascii
        $f8 = ".(*Stream).processFlags." ascii
        $f9 = ".(*Session).handlePing." ascii
        $f10 = ".(*windowsService).Install." ascii
        $f11 = ".(*windowsService).Uninstall." ascii
        $f12 = ".(*windowsService).Status." ascii
        $f13 = ".getStopTimeout." ascii
        $f14 = ".DialContext." ascii
        $f15 = ".WriteControl." ascii
        $f16 = ".(*Server).authenticate." ascii
        $f17 = ".(*Server).ServeConn." ascii
        $f18 = ".(*TCPProxy).listen." ascii
        $f19 = ".UserPassAuthenticator.Authenticate." ascii
        $f20 = ".(*InfoPacket).XXX_" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 16 of ($f*))
}

rule MALWARE_Win_SilentMoon {
    meta:
        author = "ditekSHen"
        description = "Detects SilentMoon"
    strings:
        $s1 = "\\\\.\\Global\\PIPE\\" fullword wide
        $s2 = "REMOTE_NS:ERROR:%d" fullword ascii
        $s3 = "REMOTE:ERROR:%d" fullword ascii
        $s4 = "COMNAP,COMNODE,SQLQUERY,SPOOLSS,LLSRPC,browser" fullword wide
        $s5 = "Mem alloc err" fullword ascii
        $s6 = "block %d: crc = 0x%08x, combined CRC = 0x%08x, size = %d" ascii
        $x1 = "ACTION:UNSUPPORTED" fullword ascii
        $x2 = "?ServiceMain@@YAXKPAPA_W@Z" fullword ascii
        $x3 = "?ServiceCtrlHandler@@YGKKKPAX0@Z" fullword ascii
        $x4 = "%d socks, %d sorted, %d scanned" ascii
        $x5 = "GoldenSky" fullword wide
        $x6 = "SilentMoon" fullword wide
        $x7 = "internalstoragerpc" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 3 of ($x*))
}

rule MALWARE_Win_Lu0Bot {
    meta:
        author = "ditekSHen"
        description = "Detects Lu0Bot"
    strings:
        $s1 = "WinExec" fullword ascii
        $s2 = "AlignRects" fullword ascii
        $o1 = { be 00 20 40 00 89 f7 89 f0 81 c7 a? 01 00 00 81 }
        $o2 = { 53 50 e8 b0 01 00 00 e9 99 01 00 00 e8 ae 01 00 }
    condition:
        uint16(0) == 0x5a4d and filesize < 4KB and 1 of ($s*) and all of ($o*)
}

rule MALWARE_Win_ShellcodeDLEI {
    meta:
        author = "ditekSHen"
        description = "Detects shellcode downloader, executer, injector"
    strings:
        $s1 = "PPidSpoof" fullword ascii
        $s2 = "ProcHollowing" fullword ascii
        $s3 = "CreateProcess" fullword ascii
        $s4 = "DynamicCodeInject" fullword ascii
        $s5 = "PPIDDynCodeInject" fullword ascii
        $s6 = "MapAndStart" fullword ascii
        $s7 = "PPIDAPCInject" fullword ascii
        $s8 = "PPIDDLLInject" fullword ascii
        $s9 = "CopyShellcode" fullword ascii
        $s10 = "GetEntryFromBuffer" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 5 of ($s*)
}

rule MALWARE_Win_BlueBot {
    meta:
        author = "ditekSHen"
        description = "Detects BlueBot"
    strings:
        $x1 = "Blue_Botnet" wide
        $x2 = "5-START-http" ascii
        $x3 = "*300-END-" ascii
        $x4 = "botlogger.php" wide
        $s1 = "//TARGET//" wide
        $s2 = "//BLOG//" wide
        $s3 = "MCBOTALPHA" wide
        $s4 = "//IPLIST//" wide
        $s5 = "Host: //BLOG//" wide
        $s6 = "User-Agent: //USERAGENT//" wide
        $s7 = "<string>//TARGET//</string>" wide
        $s8 = "POST //URL// HTTP/1.1/r/n" wide
        $v1 = "<attack>b__" ascii
        $v2 = "PressData" fullword ascii
        $v3 = "POSTPiece" fullword ascii
        $v4 = /(load|tcp|udp)Stuff/ fullword ascii
        $v5 = "isAttacking" fullword ascii
        $v6 = "DoSAttack" fullword ascii
        $v7 = "prv_attack" fullword ascii
        $v8 = "blogList"fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 5 of ($s*) or 5 of ($v*) or 9 of them)
}

rule MALWARE_Win_UNKCobaltStrike {
    meta:
        author = "ditekSHen"
        description = "Detects unknown malware, potentially CobaltStrike related"
    strings:
        $s1 = "https://%hu.%hu.%hu.%hu:%u" ascii wide
        $s2 = "https://microsoft.com/telemetry/update.exe" ascii wide
        $s3 = "\\System32\\rundll32.exe" ascii wide
        $s4 = "api.opennicproject.org" ascii wide
        $s5 = "%s %s,%s %u" ascii wide
        $s6 = "User32.d?" ascii wide
        $s7 = "StrDupA" fullword ascii wide
        $s8 = "{6d4feed8-18fd-43eb-b5c4-696ad06fac1e}" ascii wide
        $s9 = "{ac41592a-3d21-46b7-8f21-24de30531656}" ascii wide
        $s10 = "bd526:3b.4e32.57c8.9g32.35ef41642767~" ascii wide
        $s11 = { 4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97 } // BITS
        $s12 = { 0d 4c e3 5c c9 0d 1f 4c 89 7c da a1 b7 8c ee 7c } // BITS
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_EXEPWSHDL {
    meta:
        author = "ditekSHen"
        description = "Detects executable downloaders using PowerShell"
    strings:
        $x1 = "[Ref].Assembly.GetType(" ascii wide
        $x2 = ".SetValue($null,$true)" ascii wide
        $s1 = "replace" ascii wide
        $s2 = "=@(" ascii wide
        $s3 = "[System.Text.Encoding]::" ascii wide
        $s4 = ".substring" ascii wide
        $s5 = "FromBase64String" ascii wide
        $d1 = "New-Object" ascii wide
        $d2 = "Microsoft.XMLHTTP" ascii wide
        $d3 = ".open(" ascii wide
        $d4 = ".send(" ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of ($x*) and (3 of ($s*) or all of ($d*))
}

rule MALWARE_Win_MB150 {
    meta:
        author = "ditekSHen"
        description = "Detects MB150? Go ransomware"
    strings:
        $x1 = /main\.evade_(clicks_count|cpu_count|disk_size|foreground_window|hostname|mac|printer|screen_size|system_memory|time_acceleration|tmp|utc)/ fullword ascii
        $x2 = /main\.sandbox_(hostname|mac_addresses)/ fullword ascii
        $x3 = "main.drop_ransom_note" fullword ascii
        $x4 = "main.ransom_amount" fullword ascii
        $x5 = "main.create_encryption_key" fullword ascii
        $x6 = "main.encrypt" fullword ascii
        $x7 = "main.encrypt_encryption_key" fullword ascii
        $x8 = "main.encrypt_file" fullword ascii
        $x9 = "main.ext_blacklist" fullword ascii
        $mac1 = "00:03:FF00:05:6900:0C:2900:16:3E00:1C:1400:1C:4200:50:56" ascii nocase
        $mac2 = "00-03-FF00-05-6900-0C-2900-16-3E00-1C-1400-1C-4200-50-56" ascii nocase
        $mac3 = "0003FF000569000C2900163E001C14001C42005056" ascii nocase
        $go = "Go build ID:" ascii
        $s1 = "main.MB150" ascii
        $s2 = "http://1.1.1.1" ascii
        $s3 = "your personnal ID" ascii
        $s4 = "ransom amount" ascii
        $s5 = "binance.com" ascii
        $s6 = "getmonero.org" ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or ($go and 4 of ($s*)) or (1 of ($mac*) and (2 of ($x*) or 3 of ($s*))))
}

rule MALWARE_Win_Chaos {
    meta:
        author = "ditekSHen"
        description = "Detects Chaos ransomware"
    strings:
        $s1 = "<EncyptedKey>" fullword wide
        $s2 = "<EncryptedKey>" fullword wide
        $s3 = "C:\\Users\\" fullword wide
        $s4 = "read_it.txt" fullword wide
        $s5 = "#base64Image" fullword wide
        $s6 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" fullword wide
        $s7 = /check(Spread|Sleep|AdminPrivilage|deleteShadowCopies|disableRecoveryMode|deleteBackupCatalog)/ fullword ascii nocase
        $s8 = /(delete|disable)(ShadowCopies|RecoveryMode|BackupCatalog)/ fullword ascii nocase
        $s9 = "spreadName" fullword ascii
        $s10 = "processName" fullword ascii
        $s11 = "sleepOutOfTempFolder" fullword ascii
        $s12 = "AlreadyRunning" fullword ascii
        $s13 = "random_bytes" fullword ascii
        $s14 = "encryptDirectory" fullword ascii nocase
        $s15 = "EncryptFile" fullword ascii nocase
        $s16 = "intpreclp" fullword ascii
        $s17 = "bytesToBeEncrypted" fullword ascii
        $s18 = "textToEncrypt" fullword ascii
        $m1 = "Chaos is" wide
        $m2 = "Payment informationAmount:" wide
        $m3 = "Coinmama - hxxps://www.coinmama.com Bitpanda - hxxps://www.bitpanda.com" wide
        $m4 = "where do I get Bitcoin" wide
    condition:
        uint16(0) == 0x5a4d and 6 of ($s*) or all of ($m*) or (2 of ($m*) and 4 of ($s*))
}

rule MALWARE_Win_HorusEyesRAT {
    meta:
        author = "ditekSHen"
        description = "Detects HorusEyesRAT"
    strings:
        $x1 = "\\HorusEyesRat-" ascii
        $x2 = "\\HorusEyesRat.pdb" ascii
        $x3 = "get_horus_eye" ascii
        $s1 = "get_Type_Packet" fullword ascii
        $s2 = "PacketLib" fullword ascii nocase
        $s3 = "System.Net.Sockets" fullword ascii
        $s4 = "PROCESS_MODE_BACKGROUND_BEGIN" fullword ascii
        $s5 = "EXECUTION_STATE" fullword ascii
        $s6 = /Plugins\\[A-Z]{2}.dll/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 3 of ($s*)) or (4 of ($s*) and #s6 > 4))
}

rule MALWARE_Win_BreakWin {
    meta:
        author = "ditekSHen"
        description = "Detects BreakWin Wiper"
    strings:
        $s1 = "Started wiping file %s with %s." fullword wide
        $s2 = "C:\\Program Files\\Lock My PC" wide
        $s3 = "Stardust is still alive." fullword wide
        $s4 = "Failed to terminate the locker process." fullword wide
        $s5 = "C:\\Windows\\System32\\cmd.exe" fullword wide
        $s6 = "Process created successfully. Executed command: %s." fullword wide
        $s7 = "locker_background_image_path" fullword ascii
        $s8 = "takeown.exe /F \"C:\\Windows\\Web\\Screen\" /R /A /D Y" fullword ascii
        $s9 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /reset /T" fullword ascii
        $s10 = "takeown.exe /F \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /R /A /D Y" fullword ascii
        $s11 = ".?AVProcessSnapshotCreationFailedException@@" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_zgRAT {
    meta:
        author = "ditekSHen"
        description = "Detects zgRAT"
    strings:
        $s1 = "file:///" fullword wide
        $s2 = "{11111-22222-10009-11112}" fullword wide
        $s3 = "{11111-22222-50001-00000}" fullword wide
        $s4 = "get_Module" fullword ascii
        $s5 = "Reverse" fullword ascii
        $s6 = "BlockCopy" fullword ascii
        $s7 = "ReadByte" fullword ascii
        $s8 = { 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00
                00 0b 46 00 69 00 6e 00 64 00 20 00 00 13 52 00
                65 00 73 00 6f 00 75 00 72 00 63 00 65 00 41 00
                00 11 56 00 69 00 72 00 74 00 75 00 61 00 6c 00
                20 00 00 0b 41 00 6c 00 6c 00 6f 00 63 00 00 0d
                57 00 72 00 69 00 74 00 65 00 20 00 00 11 50 00
                72 00 6f 00 63 00 65 00 73 00 73 00 20 00 00 0d
                4d 00 65 00 6d 00 6f 00 72 00 79 00 00 0f 50 00
                72 00 6f 00 74 00 65 00 63 00 74 00 00 0b 4f 00
                70 00 65 00 6e 00 20 00 00 0f 50 00 72 00 6f 00
                63 00 65 00 73 00 73 00 00 0d 43 00 6c 00 6f 00
                73 00 65 00 20 00 00 0d 48 00 61 00 6e 00 64 00
                6c 00 65 00 00 0f 6b 00 65 00 72 00 6e 00 65 00
                6c 00 20 00 00 0d 33 00 32 00 2e 00 64 00 6c 00
                6c }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_CoinMiner03 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
    strings:
        $s1 = "UnVzc2lhbiBTdGFuZGFyZCBUaW1l" wide
        $s2 = "/xmrig" wide
        $s3 = "/gminer" wide
        $s4 = "-o {0} -u {1} -p {2} -k --cpu-priority 0 --threads={3}" wide
        $s5 = "--algo ethash --server" wide
        $s6 = "--algo kawpow --server" wide
        $cnc1 = "/delonl.php?hwid=" fullword wide
        $cnc2 = "/gateonl.php?hwid=" fullword wide
        $cnc3 = "&cpuname=" fullword wide
        $cnc4 = "&gpuname=" fullword wide
        $cnc5 = "{0}/gate.php?hwid={1}&os={2}&cpu={3}&gpu={4}&dateinstall={5}&gpumem={6}" fullword wide
        $cnc6 = "/del.php?hwid=" fullword wide
        $f1 = "<StartGpuethGminer>b__" ascii
        $f2 = "<StartGpuetcGminer>b__" ascii
        $f3 = "<StartGpurvnGminer>b__" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($cnc*) or (2 of ($f*) and (1 of ($s*) or 1 of ($f*))) or all of ($f*) or 5 of ($s*))
}

rule MALWARE_Win_Zeppelin {
    meta:
        author = "ditekSHen"
        description = "Detects Zeppelin (Delphi) ransomware"
    strings:
        $s1 = "TUnlockAndEncrypt" ascii
        $s2 = "TExcludeFiles" ascii
        $s3 = "TExcludeFolders" ascii
        $s4 = "TDrivesAndShares" ascii
        $s5 = "TTaskKiller" ascii
        $x1 = "!!! D !!!" ascii
        $x2 = "!!! LOCALPUBKEY !!!" ascii
        $x3 = "!!! ENCLOCALPRIVKEY !!!" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($x*) or (2 of ($x*) and 2 of ($s*)))
}

rule MALWARE_Win_SlackBot {
    meta:
        author = "ditekSHen"
        description = "Detects SlackBot"
    strings:
        $x1 = "lp0o4bot v" ascii
        $x2 = "slackbot " ascii
        $s1 = "cpu: %lumhz %s, uptime: %u+%.2u:%.2u, os: %s" fullword ascii
        $s2 = "%s, running for %u+%.2u:%.2u" fullword ascii
        $s3 = "PONG :%s" fullword ascii
        $s4 = "PRIVMSG %s :%s" fullword ascii
        $s5 = "Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)" fullword ascii
        $m1 = "saving %s to %s" ascii
        $m2 = "visit number %u failed" ascii
        $m3 = "sending %s packets of %s bytes to %s with a delay of %s" ascii
        $m4 = "file executed" ascii
        $m5 = "packets sent" ascii
        $m6 = "upgrading to %s" ascii
        $m7 = "rebooting..." ascii
        $c1 = "!@remove" fullword ascii
        $c2 = "!@restart" fullword ascii
        $c3 = "!@reboot" fullword ascii
        $c4 = "!@rndnick" fullword ascii
        $c5 = "!@exit" fullword ascii
        $c6 = "!@sysinfo" fullword ascii
        $c7 = "!@upgrade" fullword ascii
        $c8 = "!@login" fullword ascii
        $c9 = "!@run" fullword ascii
        $c10 = "!@webdl" fullword ascii
        $c11 = "!@cycle" fullword ascii
        $c12 = "!@clone" fullword ascii
        $c13 = "!@visit" fullword ascii
        $c14 = "!@udp" fullword ascii
        $c15 = "!@nick" fullword ascii
        $c16 = "!@say" fullword ascii
        $c17 = "!@quit" fullword ascii
        $c18 = "!@part" fullword ascii
        $c19 = "!@join" fullword ascii
        $c20 = "!@raw" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or all of ($m*) or (10 of ($c*) and (1 of ($x*) or 3 of ($s*) or 2 of ($m*))))
}

rule MALWARE_Win_SweetyStealer {
    meta:
        author = "ditekSHen"
        description = "Detects SweetyStealer"
    strings:
        $s1 = "SWEETY STEALER" wide
        $s2 = "\\SWEETYLOG.zip" fullword wide
        $s3 = "\\SWEETY STEALER\\SWEETY\\" ascii
        $s4 = "\\Sweety" fullword wide
        $s5 = "SWEETYSTEALER." ascii
        $s6 = "in Virtual Environment, so we prevented stealing" wide
        $s7 = ":purple_square:" wide
        $f1 = "<GetDomainDetect>b__" ascii
        $f2 = "<GetAllProfiles>b__" ascii
        $f3 = "<ProcessExtraFieldZip64>b__" ascii
        $f4 = "<PostExtractCommandLine>k__" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($s*) or (3 of ($f*) and 1 of ($s*))
}

rule MALWARE_Win_GENIRCBot {
    meta:
        author = "ditekSHen"
        description = "Detects generic IRCBots"
    strings:
        $s1 = "@login" ascii nocase
        $s2 = "PRIVMSG" fullword ascii
        $s3 = "JOIN" fullword ascii
        $s4 = "PING :" fullword ascii
        $s5 = "NICK" fullword ascii
        $s6 = "USER" fullword ascii
        $x1 = "irc.danger.net" fullword ascii nocase
        $x2 = "evilBot" fullword ascii nocase
        $x3 = "#evilChannel" fullword ascii nocase
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 2 of ($x*))
}

rule MALWARE_Win_Nitro {
    meta:
        author = "ditekSHen"
        description = "Detects Nitro Ransomware"
    strings:
        $x1 = ".givemenitro" wide
        $x2 = "Nitro Ransomware" ascii wide
        $x3 = "\\NitroRansomware.pdb" ascii
        $x4 = "NitroRansomware" ascii wide nocase
        $s1 = "Valid nitro code was received" wide
        $s2 = "discord nitro" ascii wide nocase
        $s3 = "Starting file encryption" wide
        $s4 = "NR_decrypt.txt" wide
        $s5 = "open it unless you have the decryption key." ascii
        $s6 = "<EncryptAll>b__" ascii
        $s7 = "<DecryptAll>b__" ascii
        $s8 = "DECRYPT_PASSWORD" fullword ascii
        $s9 = "IsEncrypted" fullword ascii
        $s10 = "CmdProcess_OutputDataReceived" fullword ascii
        $s11 = "encryptedFileLog" fullword ascii
        $s12 = "Encrypting:" fullword wide
        $s13 = "decryption key. If you do so, your files may get corrupted" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or (3 of ($s*) and 1 of ($x*)) or (7 of ($s*)))
}

rule MALWARE_Win_NanoCore {
    meta:
        author = "ditekSHen"
        description = "Detects NanoCore"
    strings:
        $x1 = "NanoCore Client" fullword ascii
        $x2 = "NanoCore.ClientPlugin" fullword ascii
        $x3 = "NanoCore.ClientPluginHost" fullword ascii
        $i1 = "IClientApp" fullword ascii
        $i2 = "IClientData" fullword ascii
        $i3 = "IClientNetwork" fullword ascii
        $i4 = "IClientAppHost" fullword ascii
        $i5 = "IClientDataHost" fullword ascii
        $i6 = "IClientLoggingHost" fullword ascii
        $i7 = "IClientNetworkHost" fullword ascii
        $i8 = "IClientUIHost" fullword ascii
        $i9 = "IClientNameObjectCollection" fullword ascii
        $i10 = "IClientReadOnlyNameObjectCollection" fullword ascii
        $s1 = "ClientPlugin" fullword ascii
        $s2 = "EndPoint" fullword ascii
        $s3 = "IPAddress" fullword ascii
        $s4 = "IPEndPoint" fullword ascii
        $s5 = "IPHostEntr" fullword ascii
        $s6 = "get_ClientSettings" fullword ascii
        $s7 = "get_Connected" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 8 of ($i*) or all of ($s*) or (1 of ($x*) and (3 of ($i*) or 2 of ($s*))))
}

rule MALWARE_Win_Satan {
    meta:
        author = "ditekSHen"
        description = "Detects Satan ransomware"
    strings:
        $s1 = "S:(ML;;NRNWNX;;;LW)" fullword wide
        $s2 = "recycle.bin" fullword wide
        $s3 = "tmp_" fullword wide
        $s4 = "%s%08x.%s" fullword wide
        $s5 = "\"%s\" %s" fullword wide
        $s6 = "/c \"%s\"" fullword wide
        $s7 = "Global\\" fullword wide
        $s8 = "rd /S /Q \"%s\"" fullword ascii
        $s9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)" fullword ascii
        $e1 = "*pdf*" fullword wide
        $e2 = "*rtf*" fullword wide
        $e3 = "*doc*" fullword wide
        $e4 = "*docx*" fullword wide
        $e5 = "*xlsx*" fullword wide
        $e6 = "*pptx*" fullword wide
        $e7 = "*moneywell*" fullword wide
        $o1 = { 56 8d 54 24 34 b9 9e f0 ea be e8 c1 f9 ff ff 8d }
        $o2 = { b9 34 f6 40 00 e8 ea 0b 00 00 85 c0 0f 84 91 }
        $o3 = { 53 8d 84 24 34 01 00 00 b9 01 00 00 80 50 a1 64 }
    condition:
        uint16(0) == 0x5a4d and ((8 of ($s*) and 4 of ($e*)) or all of ($s*) or (all of ($e*) and 5 of ($s*)) or (all of ($o*) and 8 of them))
}

rule MALWARE_Win_Neshta {
    meta:
        author = "ditekSHen"
        description = "Detects Neshta"
    strings:
        $s1 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus." fullword ascii
        $s2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Linux_HelloKitty {
    meta:
        author = "ditekSHen"
        description = "Detects Linux version of HelloKitty ransomware"
    strings:
        $s1 = "exec_pipe:%s" ascii
        $s2 = "Error InitAPI !!!" fullword ascii
        $s3 = "No Files Found !!!" fullword ascii
        $s4 = "Error open log File:%s" fullword ascii
        $s5 = "%ld - Files Found  " fullword ascii
        $s6 = "Total VM run on host:" fullword ascii
        $s7 = "error:%d open:%s" fullword ascii
        $s8 = "work.log" fullword ascii
        $s9 = "esxcli vm process kill" ascii
        $s10 = "readdir64" fullword ascii
        $s11 = "%s_%d.block" fullword ascii
        $s12 = "EVP_EncryptFinal_ex" fullword ascii
        $s13 = ".README_TO_RESTORE" fullword ascii
        $m1 = "COMPROMISED AND YOUR SENSITIVE PRIVATE INFORMATION WAS STOLEN" ascii nocase
        $m2 = "damage them without special software" ascii nocase
        $m3 = "leaking or being sold" ascii nocase
        $m4 = "Data will be Published and/or Sold" ascii nocase
    condition:
        uint16(0) == 0x457f and (6 of ($s*) or (2 of ($m*) and 2 of ($s*)) or 8 of them)
}

rule MALWARE_Win_BlackMatter {
    meta:
        author = "ditekSHen"
        description = "Detects BlackMatter ransomware"
    strings:
        $s1 = "C:\\Windows\\System32\\*.drv" fullword wide
        $s2 = "NYbr-Vk@" fullword ascii
        $s3 = ":7:=:H:Q:W:\\:b:&;O;^;v;" fullword ascii
        $o1 = { b0 34 aa fe c0 e2 fb b9 03 }
        $o2 = { fe 00 ff 75 08 ff 75 0c ff b5 d8 fe ff ff ff b5 }
        $o3 = { 6a 00 ff 75 0c ff b5 d8 fe ff ff ff b5 dc fe ff }
        $o4 = { ff 75 08 ff 75 0c ff b5 d8 fe ff ff ff b5 dc fe }
        $o5 = { 53 56 57 8d 85 70 ff ff ff 83 c0 0f 83 e0 f0 89 }
        $o6 = { c7 85 68 ff ff ff 00 04 00 00 8b 85 6c ff ff ff }
        //SOFTWARE\Microsoft\Crypt
        //Volume{
        //*recycle*
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) and all of ($o*))
}

rule MALWARE_Win_DLInjector04 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader / injector"
    strings:
        $s1 = "Runner" fullword ascii
        $s2 = "DownloadPayload" fullword ascii
        $s3 = "RunOnStartup" fullword ascii
        $a1 = "Antis" fullword ascii
        $a2 = "antiVM" fullword ascii
        $a3 = "antiSandbox" fullword ascii
        $a4 = "antiDebug" fullword ascii
        $a5 = "antiEmulator" fullword ascii
        $a6 = "enablePersistence" fullword ascii
        $a7 = "enableFakeError" fullword ascii
        $a8 = "DetectVirtualMachine" fullword ascii
        $a9 = "DetectSandboxie" fullword ascii
        $a10 = "DetectDebugger" fullword ascii
        $a11 = "CheckEmulator" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and 5 of ($a*)) or 10 of ($a*))
}

rule MALWARE_Win_DarkComet {
    meta:
        author = "ditekSHen"
        description = "Detects DarkComet"
    strings:
        $s1 = "%s, ClassID: %s" ascii
        $s2 = "%s, ProgID: \"%s\"" ascii
        $s3 = "#KCMDDC51#" ascii
        $s4 = "#BOT#VisitUrl" ascii
        $s5 = "#BOT#OpenUrl" ascii
        $s6 = "#BOT#Ping" ascii
        $s7 = "#BOT#RunPrompt" ascii
        $s8 = "#BOT#CloseServer" ascii
        $s9 = "#BOT#SvrUninstall" ascii
        $s10 = "#BOT#URLUpdate" ascii
        $s11 = "#BOT#URLDownload" ascii
        $s12 = /BTRESULT(Close|Download|HTTP|Mass|Open|Ping\|Respond|Run|Syn|UDP|Uninstall\|uninstall|Update|Visit)/ ascii
        $s13 = "dclogs\\" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_Macoute {
    meta:
        author = "ditekSHen"
        description = "Detects Macoute"
    strings:
        $s1 = "scp%s%s%s%s" ascii
        $s2 = "putfile %s %s" ascii
        $s3 = "pscp|%s|%s:%s" ascii
        $s4 = "connect %host %port\\n" ascii
        $s5 = "/ecoute/spool/%s-%lu" ascii
        $s6 = "<f n=\"%s\" s=\"%lu\" d=\"%d-%d-%d\"/>" ascii
        $s7 = "CMPT;%s;%s;%s;%s;%s" ascii
        $s8 = "%s\\apoScreen%lu.dll" ascii
        $s9 = "/cap/%s%lu.jpg" ascii
        $s10 = "INFO;%u;%u;%u;%d;%d;%d;%d;%d;%d;%d;%s" ascii
        $s11 = "SUBJECT: %s is comming!" ascii
        $s12 = "Content-type: multipart/mixed; boundary=\"#BOUNDARY#\"" ascii
        $s13 = "FROM: %s@yahoo.com" ascii
        $s14 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" ascii
        $s15 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" ascii
    condition:
        uint16(0) == 0x5a4d and 10 of them
}

rule MALWARE_Win_CoinMiner04 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
    strings:
        $s1 = "createDll" fullword ascii
        $s2 = "getTasks" fullword ascii
        $s3 = "SetStartup" fullword ascii
        $s4 = "loadUrl" fullword ascii
        $s5 = "Processer" fullword ascii
        $s6 = "checkProcess" fullword ascii
        $s7 = "runProcess" fullword ascii
        $s8 = "createDir" fullword ascii
        $cnc1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" fullword wide
        $cnc2 = "?hwid=" fullword wide
        $cnc3 = "?timeout=1" fullword wide
        $cnc4 = "&completed=" fullword wide
        $cnc5 = "/cmd.php" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) and 1 of ($cnc*))
}

rule MALWARE_Win_SideWalk {
    meta:
        author = "ditekSHen"
        description = "Detects SideWalk"
    strings:
        $s1 = "Decommit" fullword ascii
        $s2 = "Shellc0deRunner" fullword ascii
        $s3 = "shellc0de" fullword ascii
        $s4 = "C:\\Windows\\System32\\msdt.exe" fullword wide
        $s5 = "StartProcessWOPid" fullword ascii
        $s6 = "StartProcessWithParent" fullword ascii
        $m1 = "alloctype" fullword ascii
        $m2 = "ThreadIoPriority" fullword ascii
        $m3 = "PebAddress" fullword ascii
        $m4 = "dotnet.4.x64.dll" fullword wide
        $m5 = "LogonNetCredentialsOnly" fullword ascii
        $m6 = "ThreadIdealProcessor" fullword ascii
        $m7 = "LogonWithProfile" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or all of ($m*) or (11 of them))
}

rule MALWARE_Win_VanillaRAT {
    meta:
        author = "ditekSHen"
        description = "Detects VanillaRAT"
    strings:
        $stub = "VanillaStub." ascii wide
        $s1 = "Client.Send: " wide
        $s2 = "Connected to chat" fullword wide
        $s3 = "GetStoredPasswords" fullword wide
        $s4 = "Started screen locker." fullword wide
        $s5 = "[<\\MOUSE>]" fullword wide
        $s6 = "YOUR SCREEN HAS BEEN LOCKED!" fullword wide
        $s7 = "record recsound" fullword wide
        $f1 = "<StartRemoteDestkop>d__" ascii
        $f2 = "<ConnectLoop>d__" ascii
        $f3 = "<Scan0>k__" ascii
        $f4 = "<RemoteShellActive>k__" ascii
        $f5 = "KillClient" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (($stub and (2 of ($s*) or 2 of ($f*))) or 6 of ($s*) or all of ($f*))
}

rule MALWARE_Win_SectopRAT {
    meta:
        author = "ditekSHen"
        description = "Detects SectopRAT"
    strings:
        $s1 = "\\\\.\\root\\cimv2:Win32_Process" wide
        $s2 = "\\\\.\\root\\cimv2:CIM_DataFile.Name=" wide
        $s3 = "^.*(?=Windows)" fullword wide
        $s4 = "C:\\Windows\\System32\\cmd.exe" wide
        $s5 = "C:\\Windows\\explorer.exe" wide
        $s6 = "Disabling IE protection" wide
        $s7 = "stream started succces" wide
        $b1 = "/C start Firefox" wide
        $b2 = "/C start chrome" wide
        $b3 = "/C start iexplore" wide
        $m1 = "DefWindowProc" fullword ascii
        $m2 = "AuthStream" fullword ascii
        $m3 = "KillBrowsers" fullword ascii
        $m4 = "GetAllNetworkInterfaces" fullword ascii
        $m5 = "EnumDisplayDevices" fullword ascii
        $m6 = "RemoteClient.Packets" fullword ascii
        $m7 = "IServerPacket" fullword ascii
        $m8 = "keybd_event" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((5 of ($s*) and 2 of ($b*)) or all of ($s*) or (all of ($b*) and (4 of ($s*) or 5 of ($m*))))
}

rule MALWARE_Win_Neptune {
    meta:
        author = "ditekSHen"
        description = "Detects Neptune keylogger / infostealer"
    strings:
        $x1 = "your keylogger has been freshly installed on" wide
        $x2 = "Attached is a screenshot of the victim" wide
        $x3 = "color: rgb(2, 84, 138);'>Project Neptune</span><br>" wide
        $x4 = ">{Monitor Everything}</span><br><br>" wide
        $x5 = "[First Run] Neptune" wide
        $x6 = "Neptune - " wide
        $s1 = "Melt" fullword wide
        $s2 = "Hide" fullword wide
        $s3 = "SDDate+" fullword wide
        $s4 = "DelOff+" fullword wide
        $s5 = "MsgFalse+" fullword wide
        $s6 = "Clipboard:" fullword wide
        $s7 = "information is valid and working!" wide
        $s8 = ".exe /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" wide
        $s9 = "http://www.exampleserver.com/directfile.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 7 of ($s*) or (1 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Win_Tomiris {
    meta:
        author = "ditekSHen"
        description = "Detects Tomiris"
    strings:
        $f1 = "main.workPath" ascii
        $f2 = "main.selfName" ascii
        $f3 = "main.infoServerAddr" ascii
        $f4 = "main.configFileName" ascii
        $s1 = "C:/Projects/go/src/Tomiris/main.go" ascii
        $s2 = "C:/GO/go1.16.2/src/os/user/lookup_windows.go" ascii
        $s3 = "C:\\GO\\go1.16.2" ascii
        $s4 = ".html.jpeg.json.wasm.webp/p/gf/p/kk1562515" ascii
        $s5 = "\" /ST 10:00alarm clockassistQueueavx512vbmi2avx512vnniwbad" ascii
        $s6 = "write /TR \" Value addr= alloc base  code= ctxt: curg= free  goid  jobs= list= m->p=" ascii
        $t1 = "SCHTASKS /DELETE /F /TN \"%s\"" ascii
        $t2 = "SCHTASKS /CREATE /SC DAILY /TN" ascii
        $t3 = "SCHTASKS /CREATE /SC ONCE /TN \"%s\" /TR \"%s\" /ST %s" ascii
        $t4 = "SCHTASKS /CREATE /SC ONCE /TN \"%s\" /TR \"'%s' %s\" /ST %s" ascii
        $r1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones" ascii
        $r2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($f*) and 3 of ($s*) and 2 of ($t*) and 1 of ($r*)) or (4 of ($s*) and 2 of ($t*) and 1 of ($r*)) or 12 of them)
}

rule MALWARE_Win_JennLog {
    meta:
        author = "ditekSHen"
        description = "Detects JennLog loader"
    strings:
        $x1 = "%windir%\\system32\\rundll32.exe advapi32.dll,ProcessIdleTasks" fullword wide
        $x2 = "https://fkpageintheworld342.com" fullword wide
        $s1 = "ExecuteInstalledNodeAndDelete" fullword ascii
        $s2 = "ProcessExsist" fullword ascii
        $s3 = "helloworld.Certificate.txt" fullword wide
        $s4 = "ASCII85 encoded data should begin with '" fullword wide
        $s5 = "] WinRE config file path: C:\\" ascii
        $s6 = "] Parameters: configWinDir: NULL" ascii
        $s7 = "] Update enhanced config info is enabled." ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or 5 of ($s*) or (all of ($x*) and 2 of ($s*)))
}

rule MALWARE_Win_LockFile {
    meta:
        author = "ditekSHen"
        description = "Detects LockFile ransomware"
    strings:
        $x1 = "LOCKFILE" fullword ascii
        $x2 = "25a01bb859125507013a2fe9737d3c33" fullword ascii
        $s1 = "</key>" fullword ascii
        $s2 = "<computername>%s</computername>" fullword ascii
        $s3 = "<blocknum>%d</blocknum>" fullword ascii
        $s4 = "%s\\%s-%s-%d%s" fullword ascii
        $s5 = ">RAC=OQD:S>P@:AO?R:EEOS:ARDD=N?EENSB" ascii wide
        $m1 = "<title>LOCKFILE</title>" ascii wide nocase
        $m2 = "<hta:application id=LOCKFILE applicationName=LOCKFILE" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or (1 of ($x*) and (2 of ($s*) or 1 of ($m*))) or (1 of ($m*) and (1 of ($x*) or 2 of ($s*))))
}

rule MALWARE_Win_HUNT_FoggyWeb {
    meta:
        author = "ditekSHen"
        description = "Attempt on hunting FoggyWeb"
    strings:
        $u1 = "/adfs/portal/images/theme/light01/" ascii wide
        $u2 = "/adfs/services/trust/2005/samlmixed/upload" ascii wide
        $s1 = "ProcessGetRequest" ascii wide
        $s2 = "ProcessPostRequest" ascii wide
        $s3 = "UrlGetFileNames" ascii wide
        $s4 = "GetWebpImage" ascii wide
        $s5 = "GetWebpHeader" ascii wide
        $s6 = "ExecuteAssemblyRoutine" ascii wide
        $s7 = "ExecuteBinary" ascii wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_HUNT_Apostle {
    meta:
        author = "ditekSHen"
        description = "Attempt on hunting new variants of Apostle"
    strings:
        $x1 = "://t.me/x4ran" ascii wide nocase
        $x2 = "43JuFUyzfcKQwTzCTHpQoA8uLGtbwFBLyeeXoYEEU5dZLhLT1cZJDk4cytjcgQT7kdjSerJqpEp2gUcH91bjLcoq2bqik3j" ascii wide
    condition:
        any of them
}

rule MALWARE_Win_HUNT_GhostEmperor_RemoteControlPayload {
    meta:
        author = "ditekSHen"
        description = "Attempt on hunting GhostEmperor Stage 4 Remote Control Payload"
        reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2021/09/30094337/GhostEmperor_technical-details_PDF_eng.pdf"
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and pe.number_of_exports == 2 and pe.exports("1") and pe.exports("__acrt_iob_func")
}

rule MALWARE_Win_Alkhal {
    meta:
        author = "ditekSHen"
        description = "Detects Alkhal ransomware"
    strings:
        $s1 = "ReadMe.txt" fullword wide
        $s2 = "Recovery.bmp" fullword wide
        $d1 = "\\$RECYCLE.BIN\\" fullword wide
        $d2 = "\\BOOT\\" fullword wide
        $d3 = "\\RECOVERY\\" fullword wide
        $d4 = "\\MICROS~1\\" fullword wide
        $d5 = "\\CODECA~1\\js\\" fullword wide
        $a1 = "takeown.exe" fullword wide
        $a2 = "AppLaunch.exe" fullword wide
        $a3 = "MpCmdRun.exe" fullword wide
        $a4 = "wordpad.exe" fullword wide
        $a5 = "winload.exe" fullword wide
        $a6 = "prevhost.exe" fullword wide
        $a7 = "credwiz.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) and 4 of ($d*) and 3 of ($a*))
}

rule MALWARE_Win_Unicorn {
    meta:
        author = "ditekSHen"
        description = "Detects Unicorn infostealer"
    strings:
        $x1 = "WinHTTP Downloader/1.0" fullword wide
        $x2 = "[CTRL + %c]" fullword wide
        $x3 = "\\UnicornLog.txt" fullword wide
        $x4 = "/*INITIALIZED*/" fullword wide
        $s1 = { 2f 00 63 00 20 00 22 00 43 00 4f 00 50 00 59 00
               20 00 2f 00 59 00 20 00 2f 00 42 00 20 00 22 00
               25 00 73 00 22 00 20 00 22 00 25 00 73 00 22 00
               22 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00
               65 }
        $s2 = { 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00
               2e 00 65 00 78 00 65 00 00 00 00 00 25 00 73 00
               20 00 22 00 25 00 73 00 22 00 2c 00 25 00 68 00
               73 } 
        $s3 = "%*[^]]%c%n" fullword ascii
        $s4 = "file://%s%s%s" fullword ascii
        $s5 = "%s://%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
        $s6 = "regex_start_injects" fullword ascii
        $s7 = "DLEXEC" fullword ascii
        $s8 = "^((((3|1)[A-Za-z0-9]{33}))(\\s|$)|(bc1q)[A-Za-z0-9]{38}(\\s|$))" fullword ascii
        $s9 = "^(0x)?[A-Za-z0-9]{40}(\\s|$)" fullword ascii
        $s10 = "clipRegex" fullword ascii
        $s11 = "%s?k=%s&src=clip&id=%s" fullword ascii
        $s12 = "http://izuw6rclbgl2lwsh.onion/o.php" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 8 of ($s*) or (3 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Win_Spectre {
    meta:
        author = "ditekSHen"
        description = "Detects Spectre infostealer"
        snort_sid = "920233-920234"
    strings:
        $s1 = "\\../../../json.h" wide
        $s2 = "static_cast<std::size_t>(index) < kCachedPowers.size()" fullword wide
        $s3 = " cmd.exe" fullword wide
        $s4 = "m_it.object_iterator != m_object->m_value.object->end()" fullword wide
        $h1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword wide
        $h2 = "----974767299852498929531610575" ascii wide
        $h3 = "Content-Disposition: form-data; name=\"file\"; filename=\"" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and ((all of ($s*) and 1 of ($h*)) or (all of ($h*) and 2 of ($s*)))) or (6 of them)
}

rule MALWARE_Win_HUNT_BlackByte {
    meta:
        author = "ditekSHen"
        description = "Attempt on hunting BlackByte ransomware"
    strings:
        $s1 = "WalkDirAndEncrypt" ascii wide nocase
        $s2 = "FileEncrypt" ascii wide nocase
        $s3 = "BlackByte." ascii wide nocase
        $s4 = "EnumerateDirAndEncrypt" ascii wide nocase
        $s5 = "Dismount-DiskImage" ascii wide nocase
        $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_DLInjector05 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader / injector (NiceProcess)"
    strings:
        $s1 = "pidhtmpfile.tmp" fullword ascii
        $s2 = "pidhtmpdata.tmp" fullword ascii
        $s3 = "pidHTSIG" fullword ascii
        $s4 = "Taskmgr.exe" fullword ascii
        $s5 = "[HP][" ascii
        $s6 = "[PP][" ascii
        $s7 = { 70 69 64 68 74 6d 70 66 69 6c 65 2e 74 6d 70 00
                2e 64 6c 6c 00 00 00 00 70 69 64 48 54 53 49 47
                00 00 00 00 ?? ?? 00 00 54 61 73 6b 6d 67 72 2e
                65 78 65 }
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule MALWARE_Win_Kutaki {
    meta:
        author = "ditekSHen"
        description = "Detects Kutaki"
    strings:
        $x1 = "AASEaHR0cDovL29qb3JvYmlhLmNsdWIvbGFwdG9wL2xhcHRvcC5waHA" ascii
        $x2 = "aHR0cDovL3RlcmViaW5uYWhpY2MuY2x1Yi9zZWMva29vbC50eHQ" ascii
        $s1 = "wewqeuuiwe[XXXXXXX]" ascii
        $s2 = "alt|aHR0cD" ascii
        $s3 = "<rdf:Description about='uuid:fb761dc9-9daf-11d9-9a32-fcf1da45dca2'" ascii
        $s4 = "<rdf:Description about='uuid:0ab54f47-96d6-11d9-a59c-cbc93330e07e'" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 1 of ($s*)) or (all of ($s*)))
}

rule MALWARE_Win_DLInjector06 {
    meta:
        author = "ditekSHen"
        description = "Detects downloader / injector"
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" ascii wide
        $s2 = "Content-Type: application/x-www-form-urlencoded" wide
        $s3 = "https://ipinfo.io/" wide
        $s4 = "https://db-ip.com/" wide
        $s5 = "https://www.maxmind.com/en/locate-my-ip-address" wide
        $s6 = "https://ipgeolocation.io/" wide
        $s7 = "POST" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Crown {
     meta:
        author = "ditekSHen"
        description = "Detects Crown Tech Support Scam"
        snort_sid = "920251-920261"
    strings:
        $d1 = "//prodownload.live" ascii
        $c1 = "&uid=" ascii
        $c2 = "&ver=" ascii
        $c3 = "&mcid=" ascii
        $c4 = ".php?uid=" ascii
        $c5 = ".php?ip=" ascii
        $s1 = "Operating System Support ID:" ascii
        $s2 = "taskkill /IM explorer.exe -f" ascii nocase
        $s3 = "/C taskkill /IM Taskmgr.exe -f" ascii nocase
        $s4 = "FastSuport" fullword ascii
        $s5 = "Support Override!" fullword wide
        $s6 = "Support Assistance Override Activated!" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($c*) or 4 of ($s*) or (1 of ($d*) and (3 of ($c*) or 2 of ($s*))))
}

rule MALWARE_Win_FloodFix {
     meta:
        author = "ditekSHen"
        description = "Detects FloodFix"
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and (pe.exports("FloodFix") or pe.exports("FloodFix2")) and pe.exports("crc32")
}

rule MALWARE_Win_UNK_InfoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects unknown information stealer"
        snort_sid = "920263"
        hash1 = "b7a2cb34d3bc42d6d4c9d9af7dd406e2a5caef8ea46e5d09773feeb9920a6b21"
    strings:
        $s1 = "%s\\%s\\%s-Qt" fullword wide
        $s2 = "%s\\%s.json" fullword wide
        $s3 = "*.mmd*" fullword wide
        $s4 = "%s\\%s.vdf" fullword wide
        $s5 = "%-50s %s" fullword wide
        $s6 = "dISCORD|lOCAL" fullword ascii nocase
        $s7 = "sTORAGE|LEVELDB" fullword ascii nocase
        $s8 = ".coin" fullword ascii
        $s9 = ".emc" fullword ascii
        $s10 = ".lib" fullword ascii
        $s11 = ".bazar" fullword ascii
        $s12 = "id=%d" fullword ascii
        $s13 = "2:?/v /v /v /^Y" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule MALWARE_Win_DECAF {
    meta:
        author = "ditekSHen"
        description = "Detects DECAF ransomware"
    strings:
        $s1 = "main.EncWorker" fullword ascii
        $s2 = "Paths2Encrypt" fullword ascii
        $s3 = "/cmd/encryptor/main.go" ascii
        $s4 = "*win.FileUtils; .autotmp_41 *lib.Encryptor; .autotmp_" ascii
        $s5 = "\"Microsoft Window" fullword wide
        $s6 = "Legal_Policy_Statement" fullword wide
        $s7 = ").Encrypt." ascii
        $s8 = "*struct { F uintptr; pw *os.File; c *" ascii
        $s9 = ".ListFilesToEnc." ascii
        $m1 = "WINNER WINNER CHICKEN DINNER" ascii
        $m2 = "All your servers and computers are encrypted" ascii
        $m3 = "We guarantee to decrypt one image file for free." ascii
        $m4 = "We WILL NOT be able to RESTORE them." ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or 3 of ($m*) or (1 of ($m*) and 2 of ($s*)))
}

rule MALWARE_Win_WinDealer {
    meta:
        author = "ditekSHen"
        description = "Detects WinDealer"
        snort_sid = "920264"
    strings:
        $d1 = "downfile" fullword ascii
        $d2 = "getmypath" fullword ascii
        $d3 = "content-type: monitor" fullword ascii
        $d4 = "content-type: UsedType" fullword ascii
        $d5 = "write command error" fullword ascii
        $d6 = "C:\\WINDOWS\\system32\\kernel32.dll" fullword ascii
        $l1 = "currentconfig" fullword ascii
        $l2 = "remotedomain" fullword ascii
        $l3 = "reserveip" fullword ascii
        $l4 = "otherinfo" fullword ascii
        $l5 = "filelen" fullword ascii
        $l6 = "%s%s.bak" fullword wide
        $l7 = "localmachine" fullword ascii
        $l8 = "remoteip" fullword ascii
        $l9 = "datastate" fullword ascii
        $l10 = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection" fullword ascii
        $s1 = "%s\\%s\\V5_History.dat" fullword wide
        $s2 = "%s\\%s\\history2.dat" fullword wide
        $s3 = "%s\\%s\\history.imw" fullword wide
        $s4 = "%s\\%s\\main.imw" fullword wide
        $s5 = "%s%d.%d.%d.%dWindows/%u" fullword ascii
        $s6 = "%s\\%c_%s_tmp" fullword wide
        $s7 = "%s\\%s\\main.db" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((4 of ($d*) and 1 of ($s*)) or (5 of ($s*) and 1 of ($d*)) or 6 of ($l*) or (pe.exports("DealC") and pe.exports("DealR") and pe.exports("DealS") and 1 of them))
}

rule MALWARE_Win_ExMatter {
    meta:
        author = "ditekSHen"
        description = "Detects BlackMatter data exfiltration tool"
        hash1 = "4a0e10e1e9fea0906379f99fa350b91c2af37f0fd2cc55491643cc71a9887d30"
        hash2 = "a5e050f1278473d41c3a3d6f98f3fd82932f51a937bc57d8f5605815f0efb0f8"
    strings:
        $s1 = "Renci.SshNet." ascii
        $s2 = "DirNotEmpty" fullword ascii
        $s3 = "MkDir" fullword ascii
        $s4 = "RmDir" fullword ascii
        $s5 = "get_MainWindowHandle" fullword ascii
        $s6 = "GetCurrentProcess" fullword ascii
        $s7 = "]]>]]>" fullword wide
        $s8 = "1.3.132.0.35" fullword wide
        $s9 = "1.3.132.0.34" fullword wide
        $s10 = "1.2.840.10045.3.1.7" fullword wide
        $x1 = "sender2.pdb" fullword ascii
        $x2 = { 64 00 61 00 74 00 61 00 ?? 72 00 6f 00 6f 00 74 }
        $x3 = "157.230.28.192" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($x*) and 7 of ($s*)))
}

rule MALWARE_Win_BrbBot {
    meta:
        author = "ditekSHen"
        description = "Detects BrbBot"
        snort_sid = "920265"
    strings:
        $x1 = "brbconfig.tmp" fullword ascii
        $x2 = "brbbot" fullword ascii
        $s1 = "%s?i=%s&c=%s&p=%s" fullword ascii
        $s2 = "exec" fullword ascii
        $s3 = "CONFIG" fullword ascii wide
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)" fullword ascii
        $s5 = { 43 4f 4e 46 49 47 00 00 65 6e 63 6f 64 65 00 00
                73 6c 65 65 70 00 00 00 65 78 69 74 00 00 00 00
                63 6f 6e 66 00 00 00 00 66 69 6c 65 00 00 00 00
                65 78 65 63 }
    condition:
        uint16(0) == 0x5a4d and ((all of ($x*) and 1 of ($s*)) or (1 of ($x*) and 4 of ($s*)) or all of ($s*))
}

rule MALWARE_Win_BabylonRAT {
    meta:
        author = "ditekSHen"
        description = "Detects BabylonRAT / CollectorStealer / ParadoxRAT"
    strings:
        $x1 = "Babylon RAT Client" wide nocase
        $x2 = "ParadoxRAT_Client" fullword ascii
        $s1 = "@ConfigsEx" fullword wide
        $s2 = "ClipBoard.txt" fullword wide
        $s3 = "[%02d/%02d/%d %02d:%02d:%02d] [%s] (%s):" fullword wide
        $s4 = "\\%Y %m %d - %I %M %p" fullword wide
        $s5 = "[%02d/%02d/%d %02d:%02d:%02d] (%s)" fullword wide
        $s6 = " c:\\Windows\\system32\\cmd.exe" fullword wide
        $s7 = "Update Failed [OpenProcess]" wide
        $s8 = "DoS Already Active..." fullword wide
        $s9 = "File Downloaded and Execut" wide
        $s10 = "LgDError33x98dGetProcAddress" fullword wide
        $s11 = "@SPYNET" fullword wide
        $s12 = "Recovery.Recovery" fullword wide
        $s13 = "GetChrome" fullword wide
        $s14 = "\\drivers\\etc\\HOSTS" fullword ascii
        $s15 = "plugin-container.exe" fullword ascii
        $s16 = "bss_server.usrRelay" fullword ascii
        $s17 = "sckRelay" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 8 of ($s*))
}

rule MALWARE_Win_NetSupport {
    meta:
        author = "ditekSHen"
        description = "Detects NetSupport client"
        snort_sid = "920266-920267"
    strings:
        $s1 = ":\\nsmsrc\\nsm\\" fullword ascii
        $s2 = "name=\"NetSupport Client Configurator\"" fullword ascii
        $s3 = "<description>NetSupport Manager Remote Control.</description>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule MALWARE_Win_GoBrutLoader {
    meta:
        author = "ditekSHen"
        description = "Detects GoBrut StealthWorker laoder"
    condition:
        uint16(0) == 0x5a4d and pe.exports("@SetFirstEverVice@8")
}

rule MALWARE_Win_Milan {
    meta:
        author = "ditekSHen"
        description = "Detects Milan Lyceum backdoor"
        hash1 = "21ab4357262993a042c28c1cdb52b2dab7195a6c30fa8be723631604dd330b29"
        hash2 = "a2754d7995426b58317e437f8ed6770cd7bb7b18d971e23b2b300b75e34fa086"
        hash3 = "b46949feeda8726c0fb86d3cd32d3f3f53f6d2e6e3fcd6f893a76b8b2632b249"
        hash4 = "b54a67062bdcd32dfa9f3d7b69780d2e6e4925777290bc34e8f979a1b4b72ea2"
        hash5 = "b766522dd4189fef7775d663e5649ba9d8be8e03022039d20848fcbc3643e5f2"
        hash6 = "d3606e2e36db0a0cb1b8168423188ee66332cae24fe59d63f93f5f53ab7c3029"
        hash7 = "857e2f63a1078d49adc59a03482f7b362563f16fb251f174bdaa7759ed47922a"
        hash8 = "4f1b8c9209fa2684aa3777353222ad1c7716910dbb615d96ffc7882eb81dd248"
    strings:
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; .NET CLR 2.0.50727)" fullword wide
        $ua2 = "Mozilla/5.0 (Android; Mobile; rv:28.0) Gecko/28.0 Firefox/28.0" fullword wide
        $ua3 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 520)" fullword wide
        $ua4 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; XBLWP7; ZuneWP7)" fullword wide
        $ua5 = "Mozilla/5.0 (IE 11.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0) like Gecko" fullword wide
        $ua6 = "Mozilla/5.0 (iPad; U; CPU OS 5_1_1 like Mac OS X; en-us) AppleWebKit/534.46.0 (KHTML, like Gecko) CriOS/19.0.1084.60 Mobile/9B206 Safari/7534.48.3" fullword wide
        $ua7 = "Mozilla/5.0 (Linux; Android 4.1; Galaxy Nexus Build/JRN84D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19" fullword wide
        $ua8 = "Mozilla/5.0 (Linux; Android 7.1.1; ASUS_X017DA Build/NGI77B; rv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Rocket/1.5.1(11790) Chrome/74.0.3729.157 Mobile Safari/537.36" fullword wide
        $ua9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword wide
        $ua10 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36" fullword wide
        $ua11 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword wide
        $ua12 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0" fullword wide
        $n1 = "charset={[A-Za-z0-9\\-_]+}" fullword wide
        $n2 = "Content-Length: {[0-9]+}" fullword wide
        $n3 = "Location: {[0-9]+}" fullword wide
        $n4 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
        $n5 = "{<html>}" fullword wide
        $n6 = "&formid=" fullword ascii
        $n7 = "/?id=" fullword ascii
        $p1 = "\\milan\\Debug\\Milan.pdb" ascii
        $p2 = "\\milan\\Release\\Milan.pdb" ascii
        $p3 = "\\BackDor Last\\" ascii
        $p4 = "\\BackDorLast\\" ascii
        $s1 = "/q \"%s\" & waitfor" wide
        $s2 = "/q \"%s\" & schtasks /delete" wide
        $s3 = "*BOT@;" fullword ascii
        $s4 = "mofcomp \"" fullword ascii
        $s5 = "\"WQL\";};instance of " ascii
        $s6 = "</svalue>" fullword wide
        $s7 = "cmd.exe /C " wide nocase
        $d1 = "akastatus.com" ascii
        $d2 = "centosupdatecdn.com" ascii
        $d3 = "checkinternet.org" ascii
        $d4 = "cybersecnet.co.za" ascii
        $d5 = "cybersecnet.org" ascii
        $d6 = "defenderlive.com" ascii
        $d7 = "defenderstatus.com" ascii
        $d8 = "digitalmarketingagency.net" ascii
        $d9 = "dnsanalizer.com" ascii
        $d10 = "dnscatalog.net" ascii
        $d11 = "dnscdn.org" ascii
        $d12 = "dnsstatus.org" ascii
        $d13 = "excsrvcdn.com" ascii
        $d14 = "hpesystem.com" ascii
        $d15 = "livednscdn.com" ascii
        $d16 = "micrsoftonline.net" ascii
        $d17 = "ndianmombais.com" ascii
        $d18 = "online-analytic.com" ascii
        $d19 = "securednsservice.net" ascii
        $d20 = "sysadminnews.info" ascii
        $d21 = "uctpostgraduate.com" ascii
        $d22 = "updatecdn.net" ascii
        $d23 = "web-traffic.info" ascii
        $d24 = "windowsupdatecdn.com" ascii
        $d25 = "wsuslink.com" ascii
        $d26 = "zonestatistic.com" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($p*) and (2 of ($s*) or 2 of ($ua*))) or (5 of ($n*) and (2 of ($ua*) or 1 of ($p*) or 1 of ($s*))) or (3 of ($s*) and (2 of ($ua*) or 5 of ($n*))) or (2 of ($d*) and 6 of them))
}

rule MALWARE_Win_UNK05 {
    meta:
        author = "ditekSHen"
        description = "Detects potential BazarLoader"
    strings:
        $s1 = "/api/get" ascii wide
        $s2 = "PARENTCMDLINE" fullword ascii 
        $s3 = "https://microsoft.com/telemetry/update.exe" ascii wide
        $s4 = "api.opennicproject.org" fullword ascii wide
        $s5 = "https://%hu.%hu.%hu.%hu:%u" fullword ascii wide
        $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36 Edg/94.0.992.31" ascii wide
        $s7 = "PARENTJOBID" fullword ascii wide
        $s8 = "\\System32\\rundll32.exe" fullword ascii wide
        $s9 = "{ccc38b40-5b04-4fb1-a684-07c7e448d4df}" fullword ascii wide // mutex
        $s10 = "{065f6686-990b-46fc-829c-a53ec188a723}" fullword ascii wide // mutex
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule MALWARE_Win_ClipBanker01 {
    meta:
        author = "ditekSHen"
        description = "Detects ClipBanker infostealer"
    strings:
        $s1 = "Clipper" fullword wide
        $s2 = "Ushell" fullword wide
        $s3 = "Banker" fullword wide
        $s4 = "ClipPurse" fullword wide nocase
        $s5 = "SelfClip" fullword wide
        $s6 = "Cliper" fullword wide
        $s7 = "FHQD4313-33DE-489D-9721-6AFF69841DEA" fullword wide
        $s8 = "Remove.bat" fullword wide
        $s9 = "\\w{1}\\d{12}" fullword wide
        $s10 = "SELECT * FROM Win32_ComputerSystem" fullword wide
        $s11 = "red hat" fullword wide
        $s12 = { 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00
                 2e 00 65 00 78 00 65 00 00 ?? 2f 00 63 00 72 00
                 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00
                 20 00 00 ?? 20 00 2f 00 6d 00 6f 00 20 00 00 ??
                 20 00 2f 00 72 00 6c 00 20 00 00 ?? 20 00 2f 00
                 74 00 6e 00 20 00 00 ?? 20 00 2f 00 74 00 72 00
                 20 00 00 ?? 20 00 ?? 00 ?? 00 00 ?? 2f 00 64 00
                 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 74 00
                 6e }
        $s13 = "ClipChanger" fullword ascii
        $s14 = "CheckVirtual" fullword ascii
        $s15 = "InjReg" fullword ascii
        $s16 = "SuicideFile" fullword ascii
        $s17 = "HideFile" fullword ascii
        $s18 = "AntiVm" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule MALWARE_Win_ZombieBoy {
    meta:
        author = "ditekSHen"
        description = "Detects ZombieBoy Downloader"
    strings:
        $s1 = ":\\Users\\ZombieBoy\\" ascii wide
        $s2 = "RookIE/1.0" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_PCRat {
    meta:
        author = "ditekSHen"
        description = "Detects PCRat / Gh0st"
    strings:
        $s1 = "ClearEventLogA" fullword ascii
        $s2 = "NetUserAdd" fullword ascii
        $s3 = "<H1>403 Forbidden</H1>" fullword ascii
        $s4 = ":]%d-%d-%d  %d:%d:%d" fullword ascii
        $s5 = "Mozilla/4.0 (compatible)" fullword ascii
        $s6 = "<Enter>" fullword ascii
        $s7 = "\\cmd.exe" fullword ascii
        $s8 = "Program Files\\Internet Explorer\\IEXPLORE.EXE" fullword ascii
        $s9 = "Collegesoft ScenicPlayer" fullword wide
        $a1 = "360tray.exe" fullword ascii
        $a2 = "avp.exe" fullword ascii
        $a3 = "RavMonD.exe" fullword ascii
        $a4 = "360sd.exe" fullword ascii
        $a5 = "Mcshield.exe" fullword ascii
        $a6 = "egui.exe" fullword ascii
        $a7 = "kxetray.exe" fullword ascii
        $a8 = "knsdtray.exe" fullword ascii
        $a9 = "TMBMSRV.exe" fullword ascii
        $a10 = "avcenter.exe" fullword ascii
        $a11 = "ashDisp.exe" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of ($s*) and 6 of ($a*)
}

rule MALWARE_Win_Rapid {
    meta:
        author = "ditekSHen"
        description = "Detects Rapid ransomware"
    strings:
        $s1 = "encblklen" fullword ascii
        $s2 = ".rapid" fullword ascii
        $s3 = "BgIAAACkAABSU0E" ascii
        $s4 = "IFdlIHNlbmQ" ascii
        $s5 = "Software\\EncryptKeys" fullword ascii
        $s6 = "local_enc_private_key" fullword ascii
        $s7 = "local_public_key" fullword ascii
        $s8 = "How Recovery Files.txt" ascii
        $s9 = "recovery.txt" ascii
        $s10 = "thr %i run %s" fullword ascii
        $s11 = " /TN Encrypter" ascii
        $s12 = /Encrypter_\d+/ fullword ascii
        $m1 = "tell us your unique ID - ID-" ascii
        $m2 = "really want to restore your files?" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (1 of ($m*) and 4 of ($s*)))
}

rule MALWARE_Win_Satana {
    meta:
        author = "ditekSHen"
        description = "Detects Satana ransomware"
        snort_sid = "920269-920270"
    strings:
        $bf1 = "Try Decrypt: uc_size = %d, c_size = %d" ascii
        $bf2 = "dwMailSelector = %d  dwBtcSelector = %d" ascii
        $bf3 = "%s: Error DecB: 0x%X" ascii
        $bf4 = "MBR written to Disk# %d" ascii
        $bf5 = "!SATANA!" ascii wide nocase
        $bf6 = "1 -th start" fullword ascii
        $bf7 = "id=%d&code=%d&sdata=%d.%d.%d %d %d %s %s %d&name=%s&md5=%s&dlen=%s" ascii
        $bf8 = "threadAdminFlood: %s %s %s" wide
        $bf9 = "%s: NET RES FOUND: %s" wide
    condition:
        (uint16(0) == 0x5a4d and 4 of ($bf*)) or (5 of ($bf*))
}

rule MALWARE_Win_VirLock {
    meta:
        author = "ditekSHen"
        description = "Detects VirLock ransomware"
    strings:
        $x1 = "BThere are two ways to pay a fine:" fullword wide
        $x2 = "^Es gibt zwei M" fullword wide
        $x3 = "glichkeiten, eine Strafe zahlen." fullword wide
        $x4 = /usertile\d+\.bmp/ fullword wide
        $s1 = "WinSock 2.0" fullword ascii
        $s2 = "Running" fullword ascii
        $s3 = "echo WScript.Sleep(50)>%TEMP%/file.vbs" fullword ascii
        $s4 = "cscript %TEMP%/file.vbs" fullword ascii
        $s5 = "del /F /Q file.js" fullword ascii
        $s6 = "del /F /Q %1" fullword ascii
        $s7 = "del /F /Q %0" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and ((2 of ($x*) and 2 of ($s*)) or (5 of ($s*) and 1 of ($x*)))) or (8 of them)
}

rule MALWARE_Win_PirateStealer {
    meta:
        author = "ditekSHen"
        description = "Detects PirateStealer"
    strings:
        $s1 = "PirateStealerBTW" wide
        $s2 = "/PirateStealer/main/src/" wide
        $s3 = "%WEBHOOK_LINK%" fullword wide
        $s4 = "your_webhook_here" fullword wide
        $s5 = "PirateMonsterInjector" ascii wide
        $s6 = "DiscordProcesses" fullword ascii
        $s7 = "GetDiscords" fullword ascii
        $s8 = { 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00 47
               65 74 46 6f 6c 64 65 72 50 61 74 68 00 57 65 62
               68 6f 6f 6b 00 4b 69 6c 6c 00 50 72 6f 67 72 61
               6d 00 53 79 73 74 65 6d 00 4d 61 69 6e 00 }
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule MALWARE_Win_NGLite {
    meta:
        author = "ditekSHen"
        description = "Detects NGLite"
    strings:
        $x1 = "/lprey/main.go" ascii
        $x2 = "/NGLiteV1.01/lprey/" ascii
        $x3 = "/ng.com/lprey/" ascii
        $x4 = "/mnt/hgfs/CrossC2-2.2/src/" ascii
        $x5 = "WHATswrongwithUu" ascii
        $s1 = "main.Preylistener" fullword ascii
        $s2 = "main.Runcommand" fullword ascii
        $s3 = "main.RandomPass" fullword ascii
        $s4 = "main.AesEncode" fullword ascii
        $s5 = "main.RsaEncode" fullword ascii
        $s6 = "main.AesDecode" fullword ascii
        $s7 = "main.initonce" fullword ascii
        $s8 = "main.SendOnce" fullword ascii
        $s9 = "main.clientConf" fullword ascii
        $s10 = "main.Sender" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and ((1 of ($x*) and 2 of ($s*)) or (6 of ($s*)))
}

rule MALWARE_Win_KdcSponge {
    meta:
        author = "ditekSHen"
        description = "Detects KdcSponge"
        hash1 = "e391c2d3e8e4860e061f69b894cf2b1ba578a3e91de610410e7e9fa87c07304c"
    strings:
        $x1 = "\\share\\kdcdll\\user641.pdb" ascii
        $x2 = "5ADSelf@tech*7890" fullword wide
        $kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
        $kdc2 = "KerbHashPasswordEx3" ascii wide nocase
        $kdc3 = "KerbFreeKey" ascii wide nocase
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $r2 = "KDC Service" fullword ascii
        $s1 = "download//symbols//%S//%S//%S" fullword wide
        $s2 = "c:\\windows\\system32\\kdcsvc.dll" fullword wide nocase
        $s3 = /WinHttp(Send|Receive)(Request|Response) failed (0x%.8X)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (
            (1 of ($x*) and 2 of them) or (all of ($kdc*) and (1 of ($x*) or all of ($r*) or 2 of ($s*))) or (8 of them) or
            (
                pe.exports("MainFun") and 
                pe.exports("NetApiBufferFree") and 
                pe.exports("BeaEngineRevision") and 
                pe.exports("BeaEngineVersion") and 
                pe.exports("Disasm") and 
                pe.exports("DllRegisterServer") and 
                pe.exports("DsGetDcName") and
                2 of them
            )
        )
}

rule MALWARE_Win_Chinotto {
    meta:
        author = "ditekSHen"
        description = "Detects Chinotto"
    strings:
        $x1 = "xxxchinotto" ascii wide
        $x2 = "\\Chinotto.pdb" ascii wide
        $x3 = { 50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31
                0d 0a 41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e
                67 3a 20 67 7a 69 70 2c 20 64 65 66 6c 61 74 65
                0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f
                7a 69 6c 6c 61 2f 34 2e 30 28 63 6f 6d 70 61 74
                69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20
                57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20
                53 56 31 29 0d 0a 41 63 63 65 70 74 3a 20 69 6d
                61 67 65 2f 67 69 66 2c 20 69 6d 61 67 65 2f 78
                2d 78 62 69 74 6d 61 70 2c 20 69 6d 61 67 65 2f
                6a 70 65 67 2c 20 69 6d 61 67 65 2f 70 6a 70 65
                67 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78
                2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68
                2c 20 2a 0d 0a 41 63 63 65 70 74 2d 4c 61 6e 67
                75 61 67 65 3a 20 65 6e 2d 75 73 0d 0a 43 6f 6e
                74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69
                70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 62
                6f 75 6e 64 61 72 79 3d 25 73 0d 0a 48 6f 73 74
                3a 20 25 73 3a 25 64 0d 0a 43 6f 6e 74 65 6e 74
                2d 4c 65 6e 67 74 68 3a 20 25 64 0d 0a 43 6f 6e
                6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c
                69 76 65 0d 0a 43 61 63 68 65 2d 43 6f 6e 74 72
                6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 0a 0d 0a
                00 00 00 00 48 54 54 50 2f 31 2e 31 20 32 30 30
                20 4f 4b 00 0d 0a 0d 0a 00 00 00 00 65 72 72 6f
                72 3c 2f 62 3e }
        $s1 = "Run /v xxxzexs /t REG_SZ /d %s /f" ascii wide
        $s2 = "ShellExecute Error, ret" ascii wide
        $s3 = "Run app succeed" ascii
        $s4 = "cleartemp:" fullword ascii
        $s5 = "wakeup:" fullword ascii
        $s6 = "updir:" fullword ascii
        $s7 = "regstart:" fullword ascii
        $s8 = "chdec:" fullword ascii
        $s9 = "cmd:" fullword ascii
        $s10 = "error</b>" fullword ascii
        $c1 = "Host: %s:%d" ascii wide
        $c2 = "Mozilla/4.0(compatible; MSIE 6.0; Windows NT 5.1; SV1)" ascii wide
        $c3 = "Mozilla/5.0(Windows NT 10.0; Win64; x64)AppleWebKit/537.36(KHTML, like Gecko)Chrome/78.0.3904.108 Safari/537.36" ascii wide
        $c4 = "id=%s&type=hello&direction=send" ascii wide
        $c5 = "id=%s&type=command&direction=receive" ascii wide
        $c6 = "id=%s&type=file&direction=" ascii wide
        $c7 = "id=%s&type=result&direction=" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and (2 of ($s*) or 2 of ($c*))) or 4 of ($c*) or 5 of ($s*))
}

rule MALWARE_Win_Tardigrade {
    meta:
        author = "ditekSHen"
        description = "Detects Tardigrade"
        hash1 = "c0976a1fbc3dd938f1d2996a888d0b3a516b432a2c38d788831553d81e2f5858"
        hash2 = "966b2c7c72a28310acd58bb23af4d3c893b2afca264b2d9c0ec42db815c77487"
        hash3 = "88be5da274df704dc7fd9882c661a0afdd35f1ce0a7145e30f51c292abd2a86b"
        hash4 = "cf88926b7d5a5ebbd563d0241aaf83718b77cec56da66bdf234295cc5a91c5fe"
        hash5 = "4afd9f0dde092daeac3f3e6ffb0aee06682b3dba6005d2bd1a914eefd5cc6a30"
    strings:
        $x1 = "cmd.exe /c echo kOJAdtQoDcMuogIZIl>\"%s\"&exit" fullword ascii
        $x2 = "cmd.exe /c echo HBnBcZPeUevCDQmKGzXxYJHqpzRAbRCQCihOxiLi>\"%s\"&exit" fullword ascii
        $x3 = "cmd.exe /c set kpUUCjoLWLZvJFc=3167 & reg add HKCU\\SOFTWARE\\EQwIobTRgsJ /v PDMXPmqSYnUx /t REG_DWORD /d 10080 & exit" fullword ascii
        //$x4 = "DEMOBLABLA" fullword ascii
        $s1 = "ReplaceFileA" ascii
        $s2 = "FlushFileBuffers" ascii
        $s3 = "WaitNamedPipeA" ascii
        $s4 = "ImpersonateNamedPipeClient" ascii
        $s5 = "RegFlushKey" ascii
        $s6 = /cmd\.exe \/c (echo|set)/ ascii
        $s7 = ">\"%s\"&exit" ascii
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and (1 of ($x*) or 6 of ($s*)) and 
        (
            pe.exports("DllGetClassObject") and 
            pe.exports("DllMain") and 
            pe.exports("DllRegisterServer") and 
            pe.exports("DllUnregisterServer") and 
            pe.exports("InitHelperDll") and 
            pe.exports("StartW")
        )
}

rule MALWARE_Win_ClipBanker02 {
    meta:
        author = "ditekSHen"
        description = "Detects ClipBanker infostealer"
    strings:
        $x1 = "\\Allcome\\Source code\\Clipper\\" ascii nocase
        $x2 = "\\cleaper\\Release\\cleaper.pdb" ascii nocase
        $v1_1 = "&username=" fullword ascii
        $v1_2 = "/card.php?data=" fullword ascii
        $v1_3 = "/Create /tn MicrosoftDriver /sc MINUTE /tr" fullword ascii
        $v1_4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" fullword ascii
        $v1_5 = "/API/Clipper/ykesqk0o.php?cf6zrlhn=" fullword ascii
        $v1_6 = "&di7ztth6=" fullword ascii
        $v1_7 = "/API/Clipper/hr627gzk.php?v6etwxo5=" fullword ascii
        $v2_1 = "bitcoincash:" fullword ascii
        $v2_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii
        $re1 = "^[0-9]{16}$" fullword ascii
        $re2 = "^[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" fullword ascii
        $re3 = "^\\d{2}\\D\\d{2}" fullword ascii
        $re4 = "^[0-9]{3}" fullword ascii
        $re5 = "([\\W]?[0-9]{4}[\\W]?[0-9]{4}[\\W]?[0-9]{4}[\\W]?[0-9]{4}[\\W]?)" fullword ascii
        $re6 = "(\\d{2}\\D\\d{2})" fullword ascii
        $re7 = "(\\d{3})" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (5 of ($v1*) or all of ($v2*))) or (3 of ($re*) and (2 of ($v1*) or 2 of ($v2*))))
}

rule MALWARE_Win_BadJoke {
    meta:
        author = "ditekSHen"
        description = "Detects BadJoke / Witch"
    strings:
        $s1 = "msdownld.tmp" fullword ascii
        $s2 = "UPDFILE%lu" fullword ascii
        $s3 = "Command.com /c %s" fullword ascii
        $s4 = "launch.cmd" fullword ascii
        $s5 = "virus.vbs" fullword ascii
        $s6 = "virus.py" fullword ascii
        $m1 = "Message from Google Virus" ascii
        $m2 = "you cannot get rid of this virus" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($m*) or all of ($s*) or (1 of ($m*) and 2 of ($s*)))
}

rule MALWARE_Win_Heracles {
    meta:
        author = "ditekSHen"
        description = "Detects Heracles infostealer"
    strings:
        $x1 = "aHR0cHM6Ly9uYWNrZXIudG9hbnNlY3UuY29tL3VwbG9hZHM/a2V5PX" wide
        $b1 = "XEdvb2dsZVxDaHJvbWVc" wide
        $b2 = "XEJyYXZlU29mdHdhcmVcQnJhdmUtQnJvd3Nlcl" wide
        $b3 = "XENvY0NvY1xCcm93c2VyX" wide
        $b4 = "VXNlciBEYXRh" wide
        $b5 = "RGVmYXVsdA" wide
        $b6 = "UHJvZmlsZQ" wide
        $b7 = "Q29va2llcw" wide
        $b8 = "TG9naW4gRGF0YQ" wide
        $b9 = "TG9jYWwgU3RhdGU" wide
        $b10 = "bG9jYWxzdGF0ZQ" wide
        $b11 = "bG9naW5kYXRh" wide
        $s1 = "encrypted_key" fullword wide
        $s2 = "<GetIpInfoAsync>d__" ascii
        $s3 = "<reqHTML>5__" ascii
        $s4 = "<idHardware>5__" ascii
        $s5 = "<profilePaths>5__" ascii
        $s6 = "<cookieFile>5__" ascii
        $s7 = "<loginDataFile>5__" ascii
        $s8 = "<localStateFile>5__" ascii
        $s9 = "<postData>5__" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or 8 of ($s*) or (4 of ($b*) and 4 of ($s*)))
}

rule MALWARE_Win_OnlyLogger {
    meta:
        author = "ditekSHen"
        description = "Detects OnlyLogger loader variants"
    strings:
        $s1 = { 45 6c 65 76 61 74 65 64 00 00 00 00 4e 4f 54 20 65 6c 65 76 61 74 65 64 }
        $s2 = "\" /f & erase \"" ascii
        $s3 = "/c taskkill /im \"" ascii
        $s4 = "KILLME" fullword ascii
        $s5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $gn = ".php?pub=" ascii
        $ip = /\/1[a-z0-9A-Z]{4,5}/ fullword ascii
        $h1 = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1" fullword ascii
        $h2 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8" fullword ascii
        $h3 = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1" fullword ascii
        $h4 = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" fullword ascii
        $h5 = "Content-Type: application/x-www-form-urlencoded" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (#ip > 5 and ($gn or 3 of ($s*) or all of ($h*))) or (all of ($h*) and 3 of ($s*)))
}

rule MALWARE_Win_BlackByteGo {
    meta:
        author = "ditekSHen"
        description = "Detects BlackByte ransomware Go variants"
    strings:
        $x1 = "BlackByteGO/_cgo_gotypes.go" fullword ascii
        //$x2 = "_cgo_dummy_export" fullword ascii
        $x3 = "BlackByteGO/" ascii nocase
        $s1 = ".Disconnect" ascii
        $s2 = ".OpenService" ascii
        $s3 = ".ListServices" ascii
        $s4 = ".Start" ascii
        $s5 = ".Encrypt" ascii
        $s6 = ".Decrypt" ascii
        $s7 = ".MustFindProc" ascii
        $s8 = ".QuoRem" ascii
        $s9 = "C:\\Windows\\regedit.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or all of ($s*))
        //uint16(0) == 0x5a4d and (1 of ($x*) or all of ($s*) or (1 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Win_Vulturi {
    meta:
        author = "ditekSHen"
        description = "Detects Vulturi infostealer"
    strings:
        $x1 = "Vulturi_" ascii wide
        $x2 = "VulturiProject" fullword ascii
        $s1 = { 5b 00 2d 00 5d 00 20 00 53 00 65 00 72 00 76 00
               65 00 72 00 20 00 ?? ?? 20 00 69 00 73 00 20 00
               6f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 2e 00
               2e 00 2e 00 00 ?? 5b 00 2b 00 5d 00 20 00 53 00
               65 00 72 00 76 00 65 00 72 00 20 00 00 ?? ?? 00
               69 00 73 00 20 00 6f 00 6e 00 6c 00 69 00 6e 00
               65 00 }
        $s2 = "Writing is not alowed" wide
        $s3 = "System\\ProcessList.txt" fullword wide
        $s4 = "[X] GetSSL ::" fullword wide
        $s5 = "Failed to steal " wide
        $s6 = "StealerStub" fullword ascii
        $s7 = "/C chcp 65001 && netsh" wide
        $n1 = "fetch_options" fullword wide
        $n2 = "send_report" fullword wide
        $n3 = "?username=" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and any of them) or all of ($n*) or 5 of ($s*) or (1 of ($n*) and 3 of ($s*)))
}

rule MALWARE_Win_Tofsee {
    meta:
        author = "ditekSHen"
        description = "Detects Tofsee"
    strings:
        $s1 = "n%systemroot%\\system32\\cmd.exe" fullword wide
        $s2 = "loader_id" fullword ascii
        $s3 = "start_srv" fullword ascii
        $s4 = "lid_file_upd" fullword ascii
        $s5 = "localcfg" fullword ascii
        $s6 = "Incorrect respons" fullword ascii
        $s7 = "mx connect error" fullword ascii
        $s8 = "Error sending command (sent = %d/%d)" fullword ascii
        $s9 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule MALWARE_Win_Khonsari {
    meta:
        author = "ditekSHen"
        description = "Detects Khonsari ransomware"
    strings:
        $x1 = ".khonsari" fullword wide nocase
        $s1 = "Encrypt" fullword ascii
        $s2 = "CreateEncryptor" fullword ascii
        $s3 = "GenerateKey" fullword ascii
        $s4 = "277e5e6a-4da6-4138-97fa-3fecbdad0176" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 2 of ($s*)) or (all of ($s*)))
}

rule MALWARE_Win_Quantum {
    meta:
        author = "ditekSHen"
        description = "Detects Quantum locker / ransomware"
    strings:
        $x1 = "\\t<title>Quantum</title>" ascii wide
        $x2 = "Quantum Locker.<br><br>" ascii wide
        $s1 = "ERROR" fullword wide
        $s2 = ".log" fullword wide
        $s3 = "SLOW" fullword wide
        $s4 = "Create" fullword wide
        $s5 = "Integrity" fullword wide
        $s6 = "Disabled" fullword wide
        $s7 = "Deny" fullword wide
        $s8 = "FAST" fullword wide
        $s9 = "Mandatory" fullword wide
        $s10 = "plugin.dll" fullword ascii
        $s11 = "NetGetDCName" fullword ascii
        $s12 = "NetShareEnum" fullword ascii
        $s13 = "NetGetJoinInformation" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($x*) or 9 of ($s*) or (pe.number_of_exports == 2 and pe.exports("RunW") and pe.exports("runW") and 5 of ($s*)))) or all of ($x*)
}

rule MALWARE_Win_TigerRAT {
    meta:
        author = "ditekSHen"
        description = "Detects TigerRAT"
    strings:
        $m1 = ".?AVModuleKeyLogger@@" fullword ascii
        $m2 = ".?AVModulePortForwarder@@" fullword ascii
        $m3 = ".?AVModuleScreenCapture@@" fullword ascii
        $m4 = ".?AVModuleShell@@" fullword ascii
        $s1 = "\\x9891-009942-xnopcopie.dat" fullword wide
        $s2 = "(%02d : %02d-%02d %02d:%02d:%02d)--- %s[Clipboard]" fullword ascii
        $s3 = "[%02d : %02d-%02d %02d:%02d:%02d]--- %s[Title]" fullword ascii
        $s4 = "del \"%s\"%s \"%s\" goto " ascii
        $s5 = "[<<]" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (all of ($m*) and 1 of ($s*)) or (2 of ($m*) and 2 of ($s*)))
}

rule MALWARE_Win_Owowa {
    meta:
        author = "ditekSHen"
        description = "Detects Owowa"
    strings:
        $u1 = "jFuLIXpzRdateYHoVwMlfc" fullword ascii wide
        $u2 = "Fb8v91c6tHiKsWzrulCeqO" fullword ascii wide
        $u3 = "dEUM3jZXaDiob8BrqSy2PQO1" fullword ascii wide
        $s1 = "powershell.exe" fullword wide
        $s2 = "<RSAKeyValue><Modulus>" wide
        $s3 = "HealthMailbox" fullword wide
        $s4 = "6801b573-4cdb-4307-8d4a-3d1e2842f09f" ascii
        $s5 = "<PreSend_RequestContent>b__" ascii
        $s6 = "ClearHeaders" fullword ascii
        $s7 = "get_UserHostAddress" fullword ascii
        $s8 = "ExtenderControlDesigner" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($u*) or (2 of ($u*) and 3 of ($s*)) or 6 of ($s*))
}