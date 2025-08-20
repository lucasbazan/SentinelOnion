rule Leaked_Credentials
{
    strings:
        $combo = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,4}:[^ \n\r]{4,}/
    condition:
        $combo
}

rule Sensitive_Keywords
{
    strings:
        $1 = "passport"
        $2 = "ssn"
        $3 = "credit card"
        $4 = "login"
        $5 = "dump"
    condition:
        any of them
}