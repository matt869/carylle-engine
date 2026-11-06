// Baseline detection rules. A starting point: add curated feeds to this directory.
// meta.severity feeds the server's scorer: critical | high | medium | low.

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file, used by the purple team harness"
        severity = "high"
        attack = "T1204.002"
    strings:
        // Hex rather than the literal string, so scanners do not flag this rule file.
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24
                   45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 }
    condition:
        $eicar and filesize < 1KB
}

rule Webshell_PHP_Exec_From_Request
{
    meta:
        description = "PHP that passes request input to a code or command execution function"
        severity = "high"
        attack = "T1505.003"
    strings:
        $php = "<?php" nocase
        $exec1 = /(eval|assert|system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $exec2 = /(eval|assert)\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $php and any of ($exec*)
}

rule Script_Reverse_Shell
{
    meta:
        description = "Script containing a classic reverse shell one-liner"
        severity = "high"
        attack = "T1059.004"
    strings:
        $a = /bash\s+-i\s+>&\s*\/dev\/tcp\// nocase
        $b = "/bin/sh -i" nocase
        $c = /nc(at)?\s+(-[a-z]+\s+)*-e\s+\/bin\/(ba)?sh/ nocase
        $d = /socket\.socket\(.{0,120}dup2\(/ nocase
    condition:
        filesize < 1MB and any of them
}

rule Cryptominer_Config
{
    meta:
        description = "Mining pool protocol or common miner configuration keys"
        severity = "medium"
        attack = "T1496"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
        $c = "\"randomx\"" nocase
        $d = "xmrig" nocase
        $e = "\"donate-level\"" nocase
    condition:
        filesize < 5MB and (($a or $b) or 2 of ($c, $d, $e))
}

rule Ransom_Note_Text
{
    meta:
        description = "Text typical of a ransom note"
        severity = "high"
        attack = "T1486"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "decrypt your files" nocase
        $d = "bitcoin" nocase
        $e = ".onion" nocase
    condition:
        filesize < 256KB and ($a or $b or $c) and ($d or $e)
}
