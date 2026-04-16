rule TEST_RULE
{
    meta:
        description = "A test rule that does nothing lol"
        severity    = "info"
        category    = "Useless"
        mitre       = "T1234"
    strings:
        $str1 = "Hello" ascii
        $str2 = "World" ascii
    condition:
        any of them
}