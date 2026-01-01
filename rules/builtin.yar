/*
    内置 Yara 规则 - 常见恶意软件特征检测
    用于 Sysinternals 工具集
*/

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumping tool"
        author = "Security Tool"
        severity = "critical"
        reference = "https://github.com/gentilkiwi/mimikatz"
    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "kerberos::list" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "lsadump::sam" ascii wide nocase
        $s6 = "sekurlsa::logonpasswords" ascii wide nocase
        $s7 = "gentilkiwi" ascii wide nocase
    condition:
        2 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon payload"
        author = "Security Tool"
        severity = "critical"
        reference = "https://www.cobaltstrike.com/"
    strings:
        $s1 = "beacon.dll" ascii wide nocase
        $s2 = "beacon.x64.dll" ascii wide nocase
        $s3 = "%s as %s\\%s: %d" ascii wide
        $s4 = "could not spawn" ascii wide
        $s5 = "could not open process token" ascii wide
        $s6 = "ReflectiveLoader" ascii wide
        $s7 = ".sleeptime" ascii wide
        $s8 = ".jitter" ascii wide
        $beacon = { 69 68 69 68 69 6B 69 6B }
    condition:
        3 of them
}

rule Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        author = "Security Tool"
        severity = "critical"
        reference = "https://www.metasploit.com/"
    strings:
        $s1 = "meterpreter" ascii wide nocase
        $s2 = "metasploit" ascii wide nocase
        $s3 = "stdapi_" ascii wide
        $s4 = "priv_" ascii wide
        $s5 = "ext_server" ascii wide
        $s6 = "metsrv.dll" ascii wide nocase
        $s7 = "reverse_tcp" ascii wide nocase
    condition:
        2 of them
}

rule PowerShell_Encoded_Command {
    meta:
        description = "PowerShell encoded/obfuscated command"
        author = "Security Tool"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encoded" ascii wide nocase
        $enc3 = "-e " ascii wide nocase
        $enc4 = "FromBase64String" ascii wide nocase
        $enc5 = "[Convert]::" ascii wide nocase
        $bypass1 = "-exec bypass" ascii wide nocase
        $bypass2 = "-executionpolicy bypass" ascii wide nocase
        $bypass3 = "Set-ExecutionPolicy" ascii wide nocase
        $hidden = "-w hidden" ascii wide nocase
        $noprofile = "-nop" ascii wide nocase
    condition:
        ($ps1 or $ps2) and (2 of ($enc*) or 2 of ($bypass*) or $hidden or $noprofile)
}

rule Suspicious_Shellcode {
    meta:
        description = "Suspicious shellcode patterns"
        author = "Security Tool"
        severity = "critical"
    strings:
        $sc1 = { FC E8 }           // cld; call
        $sc2 = { 60 89 E5 }        // pushad; mov ebp, esp
        $sc3 = { E8 00 00 00 00 }  // call $+5 (get EIP)
        $sc4 = { 64 A1 30 00 00 00 }  // mov eax, fs:[0x30] (PEB access)
        $sc5 = { 64 8B 0D 30 00 00 00 }  // mov ecx, fs:[0x30]
        $sc6 = { 31 C0 64 8B 40 30 }  // xor eax,eax; mov eax, fs:[eax+0x30]
        $sc7 = { EB ?? 5? }        // jmp short; pop reg (GetPC)
    condition:
        2 of them
}

rule Webshell_Generic {
    meta:
        description = "Generic webshell patterns"
        author = "Security Tool"
        severity = "high"
    strings:
        $php1 = "<?php" ascii nocase
        $php2 = "eval(" ascii nocase
        $php3 = "base64_decode(" ascii nocase
        $php4 = "system(" ascii nocase
        $php5 = "shell_exec(" ascii nocase
        $php6 = "passthru(" ascii nocase
        $php7 = "exec(" ascii nocase
        $asp1 = "<%@ " ascii nocase
        $asp2 = "Request(" ascii nocase
        $asp3 = "Execute(" ascii nocase
        $jsp1 = "Runtime.getRuntime()" ascii nocase
        $jsp2 = "ProcessBuilder" ascii nocase
    condition:
        ($php1 and 2 of ($php*)) or ($asp1 and $asp2 and $asp3) or (any of ($jsp*))
}

rule Ransomware_Indicators {
    meta:
        description = "Ransomware indicators"
        author = "Security Tool"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = "decrypt" ascii wide nocase
        $ransom4 = "ransom" ascii wide nocase
        $ransom5 = ".onion" ascii wide nocase
        $ransom6 = "pay" ascii wide nocase
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".encrypted" ascii wide nocase
        $ext3 = ".crypted" ascii wide nocase
        $shadow = "vssadmin" ascii wide nocase
        $shadow2 = "wmic shadowcopy" ascii wide nocase
    condition:
        3 of ($ransom*) or (any of ($ext*) and any of ($shadow*))
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookEx" ascii wide
        $api3 = "GetKeyboardState" ascii wide
        $api4 = "GetKeyState" ascii wide
        $api5 = "RegisterHotKey" ascii wide
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase
        $hook = "WH_KEYBOARD" ascii wide
    condition:
        3 of ($api*) or any of ($log*) or $hook
}

rule Credential_Stealer {
    meta:
        description = "Credential stealing indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $browser1 = "Login Data" ascii wide
        $browser2 = "logins.json" ascii wide
        $browser3 = "cookies.sqlite" ascii wide
        $browser4 = "Chrome" ascii wide
        $browser5 = "Firefox" ascii wide
        $browser6 = "Edge" ascii wide
        $cred1 = "CredEnumerate" ascii wide
        $cred2 = "CryptUnprotectData" ascii wide
        $cred3 = "vaultcli" ascii wide
        $mail1 = "outlook" ascii wide nocase
        $mail2 = "thunderbird" ascii wide nocase
    condition:
        (2 of ($browser*) and any of ($cred*)) or (any of ($mail*) and any of ($cred*))
}

rule Suspicious_Network_Indicators {
    meta:
        description = "Suspicious network indicators"
        author = "Security Tool"
        severity = "medium"
    strings:
        $socket1 = "WSAStartup" ascii wide
        $socket2 = "socket" ascii wide
        $socket3 = "connect" ascii wide
        $socket4 = "bind" ascii wide
        $http1 = "HttpSendRequest" ascii wide
        $http2 = "InternetOpen" ascii wide
        $http3 = "URLDownloadToFile" ascii wide
        $dns1 = "DnsQuery" ascii wide
        $dns2 = "gethostbyname" ascii wide
        $port1 = ":4444" ascii wide
        $port2 = ":5555" ascii wide
        $port3 = ":1234" ascii wide
        $port4 = ":31337" ascii wide
    condition:
        (3 of ($socket*) and any of ($port*)) or (2 of ($http*)) or any of ($port*) or any of ($dns*)
}

rule Process_Injection_Indicators {
    meta:
        description = "Process injection indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "RtlCreateUserThread" ascii wide
        $api6 = "QueueUserAPC" ascii wide
        $api7 = "SetThreadContext" ascii wide
        $api8 = "NtUnmapViewOfSection" ascii wide
    condition:
        3 of them
}

rule Persistence_Registry {
    meta:
        description = "Registry persistence indicators"
        author = "Security Tool"
        severity = "medium"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $reg3 = "Winlogon\\Shell" ascii wide nocase
        $reg4 = "Winlogon\\Userinit" ascii wide nocase
        $reg5 = "Explorer\\Shell Folders" ascii wide nocase
        $reg6 = "Image File Execution Options" ascii wide nocase
        $reg7 = "AppInit_DLLs" ascii wide nocase
        $reg8 = "Services\\" ascii wide nocase
    condition:
        2 of them
}

rule UAC_Bypass_Indicators {
    meta:
        description = "UAC bypass indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $fodhelper = "fodhelper" ascii wide nocase
        $eventvwr = "eventvwr" ascii wide nocase
        $sdclt = "sdclt" ascii wide nocase
        $cmstp = "cmstp" ascii wide nocase
        $computerdefaults = "computerdefaults" ascii wide nocase
        $slui = "slui" ascii wide nocase
        $env1 = "ms-settings" ascii wide nocase
        $env2 = "shell\\open\\command" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_Strings_Generic {
    meta:
        description = "Generic suspicious strings"
        author = "Security Tool"
        severity = "low"
    strings:
        $cmd1 = "cmd.exe /c" ascii wide nocase
        $cmd2 = "command.com" ascii wide nocase
        $del1 = "del /f" ascii wide nocase
        $del2 = "rmdir /s" ascii wide nocase
        $net1 = "net user" ascii wide nocase
        $net2 = "net localgroup" ascii wide nocase
        $task = "schtasks" ascii wide nocase
        $wmi = "wmic" ascii wide nocase
        $reg = "reg add" ascii wide nocase
    condition:
        3 of them
}
