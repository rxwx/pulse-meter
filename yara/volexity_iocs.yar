rule Modified_CompCheckResult_CGI
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects compcheckresult.cgi modified since 2024-01-01"
        reference = "https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/"
    strings:
        // TODO: this heuristic is not great in regex - could do it in Python instead
        // Could maybe improve it by checking the timestamp capture group against other timestamps?
        // -rwxr-xr-x  1 root root    769 Dec  5  2022 compcheckmsjava.thtml
        // -rwxr-xr-x  1 root root   6381 Jan 15 19:08 compcheckresult.cgi
        $a = /[rwx-]{10}.*Jan\s+(0[1-9]|[12][0-9]|3[01])\s([01][0-9]|2[0-3]):([0-5][0-9])\scompcheckresult\.cgi/ fullword
    condition:
        $a
}

rule Modified_LastServerUsed_CGI
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects modified lastauthserverused.js modified since 2024-01-01"
        reference = "https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/"
    strings:
        // -rwxr-xr-x  1 root root  93721 Dec  5  2022 jquery.min_07a014da4a846aecdd7cb376f857efebac4cd0f69fa59409e0b2f62e9a090667.js
        // -rwxr-xr-x  1 root root   4107 Jan 15 19:08 lastauthserverused.js
        $a = /[rwx-]{10}.*Jan\s+(0[1-9]|[12][0-9]|3[01])\s([01][0-9]|2[0-3]):([0-5][0-9])\slastauthserverused\.js/ fullword
    condition:
        $a
}

rule Modified_DSLogConfig_PM
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects modified DSLogConfig.pm modified since 2024-01-01"
        reference = "https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/"
    strings:
        // -rwxr-xr-x  1 root root  93721 Dec  5  2022 jquery.min_07a014da4a846aecdd7cb376f857efebac4cd0f69fa59409e0b2f62e9a090667.js
        // -rwxr-xr-x  1 root root   4107 Jan 15 19:08 lastauthserverused.js
        $a = /[rwx-]{10}.*Jan\s+(0[1-9]|[12][0-9]|3[01])\s([01][0-9]|2[0-3]):([0-5][0-9])\sDSLogConfig\.pm/ fullword
    condition:
        $a
}

rule Modified_CAV_Server
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects modified cav-0.1-py3.6.egg modified since 2024-01-01"
        reference = "https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/"
    strings:
        // drwxr-xr-x   4 root root    4096 Dec  5  2022 cachecontrol
        // -rwxr-xr-x   1 root root   71818 Jan 15 19:10 cav-0.1-py3.6.egg
        $a = /[rwx-]{10}.*Jan\s+(0[1-9]|[12][0-9]|3[01])\s([01][0-9]|2[0-3]):([0-5][0-9])\scav-0\.1-py3\.6\.egg/ fullword
    condition:
        $a
}

rule SessionServer_Webshell_Tool
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects the sessionserver.sh script which is used to deploy a webshell and evade detection from ICT"
        reference = "https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/"
    strings:
        // This file should not exist on a non-compromised instance
        // -rw-r--r-- 1 root root    5 Jan 15 19:08 sessionserver.sh
        $script = /[rwx-]{10}.*sessionserver\.(sh|pl)/ fullword
        $dir = "/home/etc/sql/dsserver" ascii nocase
    condition:
        all of them
}