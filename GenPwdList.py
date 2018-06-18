import os

def ATT_WIFI(Last4Digits):
    if not (type(Last4Digits) is str) or len(Last4Digits) != 4: print "\nError: Expecting 4 Digits as str\n"
    if not (type(Last4Digits) is str) or len(Last4Digits) != 4: return False
    GenNumbers = ""; i = 1
    for a in range(10):
        for b in range(10):
            for c in range(10):
                for d in range(10):
                    Digits8 = (a, Last4Digits[0], b, Last4Digits[1], c, Last4Digits[3], d, Last4Digits[2])
                    GenNumber = "%s%s%s%s%s%s%s%s" % Digits8; GenNumbers += GenNumber + "\n"
    print; print "Appending GenNumbers >> ATT_WIFI_%s.txt" % Last4Digits
    if not os.path.isfile("wordlists/ATT_WIFI_%s.txt" % Last4Digits):
        ATT_file = open("wordlists/ATT_WIFI_%s.txt" % Last4Digits, "w"); ATT_file.write(GenNumbers); ATT_file.close()
    print; print "Randomizing ATT_WIFI_%s.txt" % Last4Digits
    os.system("cd wordlists && shuf ATT_WIFI_%s.txt > ATT_WIFI_%s_Rand.txt && rm ATT_WIFI_%s.txt && mv ATT_WIFI_%s_Rand.txt ATT_WIFI_%s.txt && cd .." % tuple([Last4Digits] * 5))
    print; print "All Done!"
    print


def ArrisRouter(Generic):
    GenHexNumbers = ""; i = 1
    HexRange = "0123456789ABCDEF"
    for a in HexRange:
        for b in HexRange:
            for c in HexRange:
                for d in HexRange:
                    HexCombo = a + b + c + d
                    GenHex = "%s%s%s" % (Generic[:7], HexCombo, Generic[-2:])
                    GenHexNumbers += GenHex + "\n"
    print; print "Appending GenNumbers >> %s.txt" % Generic
    if not os.path.isfile("wordlists/%s.txt" % Generic):
        Arris_file = open("wordlists/%s.txt" % Generic, "w"); Arris_file.write(GenHexNumbers); Arris_file.close()
    print; print "Randomizing %s.txt" % Generic
    os.system("cd wordlists && shuf %s.txt > %s_Rand.txt && rm %s.txt && mv %s_Rand.txt %s.txt && cd .." % tuple([Generic] * 5))
    print; print "All Done!"
    print


def WIFIXXXXXX(BSSID, ESSID):
    if "WIFI" not in ESSID: return False
    if len(ESSID) != 10 or len(BSSID) != 17: print "\nError: Expected WIFIXXXXXX (10 Chars)"
    if len(ESSID) != 10 or len(BSSID) != 17: return False
    os.system("wlan4xx %s %s wordlists/%s.txt" % (ESSID, BSSID, ESSID))


if __name__ == "__main__":
    ATT_WIFI(raw_input("\nEnter Last 4 Digits: ATT-WIFI-"))
