rule Suspicious_File_Types
{
    strings:
        $1 = ".exe"
        $2 = ".scr"
        $3 = ".zip"
        $4 = ".rar"
        $5 = ".7z"
    condition:
        any of them
}