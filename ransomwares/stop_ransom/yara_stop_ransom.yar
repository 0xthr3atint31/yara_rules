import "pe"

rule crime_extortion : stop_ransomware {
    meta:
        description = "Detection of Stop Ransomware"
        author = "0xthreatintel"
        reference = "Blog on Analysis of Stop Ransomware"
        date = "2021-10-30"
    strings:
        $d1 = "C:\\Build-OpenSSL-VC-32/lib/engines" fullword wide
        $d2 = "e:\\doc\\my work (c++)\\_git\\encryption\\encryptionwinapi\\Salsa20.inl" fullword wide
        $u1= "https://api.2ip.ua/geo.json" fullword ascii
        $u2 = "You need to read the OpenSSL FAQ, http://www.openssl.org/support/faq.html" fullword ascii
        $u3 = "ns1.kriston.ug" fullword ascii
        $u4 = "ns2.chalekin.ug" fullword ascii
        $u5 = "ns3.unalelath.ug" fullword ascii
        $u6 = "ns4.andromath.ug" fullword ascii
        $s1 = "%8sVersion: %lu (0x%lx)\n" fullword ascii
        $s2 = "SunMonTueWedThuFriSat" fullword ascii
        $c1 = { 55 8B EC 64 A1 00 00 00 00 6A FF 68 50 A8 4C 00 50 B8 90 28 00 00 64 89 25 00 00 00 00 E8 8E 28 02 00 53 56 57 68 FF 27 00 00 8D 85 69 D7 FF FF C6 85 68 D7 FF FF 00 6A 00 50 E8 D1 E4 01 00 83 C4 0C 6A 00 6A 00 6A 00 6A 00 68 7C FF 4F 00 FF 15 B0 C3 4C 00 8B F8 C7 45 A8 07 00 00 00 6A 1B 33 C0 C7 45 A4 00 00 00 00 68 B4 FF 4F 00 8D 4D 94 66 89 45 94 E8 86 8C 00 00 6A 00 6A 00 C7 45 FC 00 00 00 00 8D 45 94 83 7D A8 08 6A 00 0F 43 45 94 6A 00 50 57 FF 15 AC C3 4C 00 8B F0 85 F6 75 07 }
        $c2 = { 55 8B EC B8 10 10 00 00 E8 53 D4 01 00 8D 45 FC C7 45 FC 00 00 00 00 50 68 3F 00 0F 00 6A 00 68 90 02 50 00 68 01 00 00 80 FF 15 28 C0 4C 00 85 C0 74 06 }
        $c3 = { 55 8B EC 51 8D 45 FC 50 68 D4 FC 4C 00 6A 00 FF 15 90 C2 4C 00 85 C0 74 17 }
        $c4 = { 55 8B EC 6A FF 68 B8 A7 4C 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 30 01 00 00 53 56 57 C7 45 FC 00 00 00 00 33 DB 33 FF 89 5D E4 33 F6 89 7D E8 89 75 EC 68 C0 FE 4F 00 68 88 FE 4F 00 C6 45 FC 01 E8 53 48 01 00 83 C4 08 89 45 F0 85 C0 }
        $c5 = { 56 8B 74 24 08 33 D2 85 F6 74 3B }
        $c6 = { 55 8B EC 81 EC BC 00 00 00 53 8B 5D 08 8B C1 89 45 CC 57 8B 7D 0C 85 DB 74 04 }
        $c7 = { 55 8B EC 6A FF 64 A1 00 00 00 00 68 A8 A9 4C 00 50 B8 A0 A0 00 00 64 89 25 00 00 00 00 E8 5E 1A 02 00 53 56 57 89 8D 7C FF FF FF C7 85 58 FF FF FF 00 00 00 00 C7 45 FC 00 00 00 00 8D 45 08 83 7D 1C 08 68 10 01 50 00 0F 43 45 08 50 E8 70 3E 01 00 83 C4 08 85 C0 74 0C }
    condition:
    (
        uint16(0) == 0x5a4d and filesize < 1140KB and 1 of ($d*) and 4 of ($u*) and 1 of ($s*) and 3 of ($c*)
    )
}
