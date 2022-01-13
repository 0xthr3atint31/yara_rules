import "pe"

rule crime_extortion : stop_ransom_loader {
    meta:
        description = "Detection of Stop Ransomware loader"
        author = "0xthreatintel"
        reference = "Blog on Stop Ransomware Analysis"
        date = "2021-11-01"
    strings:
        $c1 = { 8B 45 AC C1 F8 05 8B 4D AC 83 E1 1F C1 E1 06 03 0C 85 80 48 BB 02 89 4D 9C 8B 55 9C 8B 45 98 8B 08 89 0A 8B 55 9C 8B 45 A4 8A 08 88 4A 04 68 A0 0F 00 00 8B 55 9C 83 C2 0C 52 FF 15 40 11 40 00 85 C0 75 08 }
        $c2 = { 8B F7 83 E6 1F 8B C7 C1 F8 05 C1 E6 06 03 34 85 20 20 4B 00 8B 45 F8 8B 00 89 06 8B 45 FC 8A 00 88 46 04 68 A0 0F 00 00 8D 46 0C 50 FF 15 EC 30 4A 00 85 C0 0F 84 BC 00 00 00 }
        $s1 = ".?AVtype_info@@" fullword ascii
        $s2 = ".?AVexception@std@@" fullword ascii
        $s3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
        $s4 = "abcdefghijklmnopqrstuvwxyz"fullword ascii
    condition:
    (
        uint16(0) == 0x5a4d and filesize < 900KB and 1 of ($c*) and 3 of ($s*)
    )
}
