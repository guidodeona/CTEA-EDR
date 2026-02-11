
rule Suspicious_Strings : MALWARE
{
    meta:
        description = "Detects common suspicious strings in memory or files"
        author = "CTEA Auto-Generated"
        date = "2023-10-27"
    
    strings:
        // Shellcode patterns
        $s1 = "cmd.exe" ascii wide
        $s2 = "powershell.exe" ascii wide
        $s3 = "CreateRemoteThread" ascii
        $s4 = "VirtualAllocEx" ascii
        $s5 = "WriteProcessMemory" ascii
        
        // Common malware strings
        $m1 = "mimikatz" nocase ascii wide
        $m2 = "metasploit" nocase ascii wide
        $m3 = "keylogger" nocase ascii wide

    condition:
        // Trigger if 2 or more shellcode strings OR any malware string is found
        (2 of ($s*)) or (any of ($m*))
}

rule UPX_Packed : SUSPICIOUS
{
    meta:
        description = "Detects UPX packed executables"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
    condition:
        $upx1 and $upx2
}
