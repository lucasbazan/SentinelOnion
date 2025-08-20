rule Brazilian_CPF
{
    strings:
        $cpf = /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/
    condition:
        $cpf
}

rule Brazilian_RG
{
    strings:
        $rg = /\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b/
    condition:
        $rg
}

rule US_SSN
{
    strings:
        $ssn = /\b\d{3}-\d{2}-\d{4}\b/
    condition:
        $ssn
}

rule US_DriverLicense
{
    strings:
        $dl1 = /\b[A-Z]{1}\d{7}\b/
        $dl2 = /\b\d{9}\b/
    condition:
        any of them
}

rule Email_Address
{
    strings:
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/
    condition:
        $email
}

rule Phone_Number
{
    strings:
        $phone = /\+?\d{1,3}?[-. (]?\d{2,4}[-. )]?\d{3,4}[-. ]?\d{4}/
    condition:
        $phone
}
