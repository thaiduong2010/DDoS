import os
import sys
import httpx
from colorama import Fore, init
init(autoreset=True)

fr = Fore.RED
fg = Fore.GREEN
fy = Fore.YELLOW
fw = Fore.WHITE
fre = Fore.RESET

list = [
'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
'https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt',
'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
'http://worm.rip/http.txt',
'https://proxyspace.pro/http.txt',
'https://proxy-spider.com/api/proxies.example.txt1',
'http://193.200.78.26:8000/http?key=free',
]  
         

if __name__ == "__main__":
    file = "proxy.txt"
    
    try:
        if os.path.isfile(file):
            os.system('cls' if os.name == 'nt' else 'clear')
            os.remove(file)
            print("{}File {} removed!\n{}Refreshing proxies...\n".format(fr, file, fy, file))
            with open(file, 'a') as data:
                for proxy in list:
                    data.write(httpx.get(proxy).text)
                    print(" -| Scraped from {}{}".format(fg, proxy))
        else:
            os.system('cls' if os.name == 'nt' else 'clear')
            with open(file, 'a') as data:
                for proxy in list:
                    data.write(httpx.get(proxy).text)
                    print(" -| Scraped from: {}{}".format(fg, proxy))
    
        with open(file, 'r') as count:
            total = sum(1 for line in count)
        print("\n{}( {}{} {}) {}Proxies refreshed.". format(fw, fy, total, fw, fg))
    
    except IndexError:
        sys.exit(1)
        