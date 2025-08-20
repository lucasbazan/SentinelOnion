rule DarkMarket_Terms
{
    strings:
        $1 = "marketplace"
        $2 = "vendor"
        $3 = "escrow"
        $4 = "pills"
        $5 = "weapons"
    condition:
        any of them
}