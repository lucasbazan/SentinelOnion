rule Onion_Links
{
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/
    condition:
        $onion
}

rule I2P_Links
{
    strings:
        $i2p = /[a-z0-9]{16,64}\.i2p/
    condition:
        $i2p
}