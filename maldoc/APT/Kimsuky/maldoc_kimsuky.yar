import "pe"

rule crime_WireFraud : APT_Kimsuky_maldoc {
    meta:
        description = "Detection of Kimsuky malicious document"
        author = "0xthreatintel"
        reference = "https://twitter.com/0xthreatintel/status/1496250296250830851"
        date = "2022-02-23"
    strings:
        $m1 = { 50 4B 03 04 14 00 00 00 }
        $h1 = { 63 75 73 74 6F 6D 58 6D 6C 2F 69 74 65 6D 50 72 6F 70 73 31 2E 78 6D 6C }
        $h2 = { 68 74 74 70 3A 2F 2F 6D 73 2D 77 6F 72 6B 2E 63 6F 6D 2D 69 6E 66 6F 2E 73 74 6F 72 65 2F 64 6D 73 2F 30 32 30 33 2E 64 6F 74 6D }
        $h3 = { 68 74 74 70 3A 2F 2F 73 63 68 65 6D 61 73 2E 6F 70 65 6E 78 6D 6C 66 6F 72 6D 61 74 73 2E 6F 72 67 2F 70 61 63 6B 61 67 65 2F 32 30 30 36 2F 72 65 6C 61 74 69 6F 6E 73 68 69 70 73 }
        $h4 = { 77 6F 72 64 2F 67 6C 6F 73 73 61 72 79 2F }
        $h5 = { 64 6F 63 50 72 6F 70 73 2F }
    condition:
    (
        $m1 and filesize < 111KB and 3 of ($h*)
    )
}
