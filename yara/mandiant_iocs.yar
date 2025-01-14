rule ZIPLINE_Backdoor
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects the shared library used by the ZIPLINE Backdoor"
        reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    strings:
        // This file should not exist on a non-compromised instance
        $1 = /[rwx-]{10}.*libsecure\.so\.1/ fullword
    condition:
        all of them
}

rule PHASEJAM_Backdoor
{
    meta:
        author = "Rich Warren"
        date = "2025-01-14"
        description = "Detects artifacts related to the PHASEJAM Backdoor"
        reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    strings:
        $1 = "getComponent.cgi.bak" ascii
        $2 = "remotedebug.bak" ascii
        $3 = "restAuth.cgi.bak"
    condition:
        any of them
}

rule SPAWN_Malware_Family
{
    meta:
        author = "Rich Warren"
        date = "2025-01-14"
        description = "Detects artifacts related to the SPAWN Malware Family"
        reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    strings:
        $1 = "libupgrade.so" ascii
        $2 = "libsocks5.so" ascii
        $3 = "libsshd.so" ascii
        $4 = "liblogblock.so" ascii
    condition:
        any of them
}