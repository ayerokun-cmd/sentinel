// Example YARA rules. Used only when the optional `yara-python` package is installed.
// Add your own .yar files to this folder.

rule PowerShell_Download_And_Run
{
    meta:
        description = "PowerShell that downloads and runs code in one line"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $run1 = "IEX" nocase fullword
        $run2 = "Invoke-Expression" nocase
        $hide = "-WindowStyle Hidden" nocase
    condition:
        filesize < 1MB and any of ($dl*) and (any of ($run*) or $hide)
}

rule Encoded_PowerShell_Command
{
    meta:
        description = "PowerShell launched with a base64 encoded command"
    strings:
        $a = /powershell(\.exe)?\s+[^\n]{0,40}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        filesize < 1MB and $a
}

rule Shell_Script_Curl_Pipe
{
    meta:
        description = "Script that pipes a remote download straight into a shell"
    strings:
        $a = /(curl|wget)[^\n|]{0,200}\|\s*(ba|z)?sh/
    condition:
        filesize < 1MB and $a
}
