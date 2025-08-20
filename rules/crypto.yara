rule Bitcoin_Address
{
    strings:
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        $btc
}

rule Ethereum_Address
{
    strings:
        $eth = /0x[a-fA-F0-9]{40}/
    condition:
        $eth
}