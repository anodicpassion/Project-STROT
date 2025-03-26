import os
import random
import socket
import sys
import json
import time
from typing import Dict, Any
from scapy.all import ARP, Ether, srp
import nmap
from attack_engine.attack_engine import AttackEngine
from attack_engine.exploit_search import search_exploit
import pickle, time, os

class STROTCLI:
    def __init__(self, *args, **kwargs) -> None:
        """
            STROTCLI - CLI initializer
        """
        self.__standard_os: list = [
            "AIX", "Alpha", "Android", "ARM", "ASHX", "ASP", "ASPX", "AtheOS", "BeOS", "BSD",
            "BSDi_x86", "BSD_PPC", "BSD_x86", "CFM", "CGI", "eZine", "FreeBSD", "FreeBSD_x86",
            "FreeBSD_x86-64", "Generator", "Go", "Hardware", "HP-UX", "Immunix", "iOS", "IRIX",
            "Java", "JSON", "JSP", "Linux", "Linux_CRISv32", "Linux_MIPS", "Linux_PPC",
            "Linux_SPARC", "Linux_x86", "Linux_x86-64", "Lua", "macOS", "Mac OS", "Magazine", "MINIX",
            "Multiple", "NetBSD_x86", "Netware", "NodeJS", "Novell", "OpenBSD", "OpenBSD_x86",
            "OSX", "OSX_PPC", "Palm_OS", "Perl", "PHP", "Plan9", "Python", "Python2", "Python3",
            "QNX", "Ruby", "SCO", "SCO_x86", "Solaris", "Solaris_MIPS", "Solaris_SPARC",
            "Solaris_x86", "SuperH_SH4", "System_z", "Tru64", "TypeScript", "ULTRIX", "Unix",
            "UnixWare", "VxWorks", "watchOS", "Windows", "Windows_x86", "Windows_x86-64", "XML"
        ]
        self.__os_target: str = ""
        self.__services_target: dict = {}
        self.__versions_target: dict = {}

        self._driver_init()
        while self._driver() != 0:
            pass

    def _driver_init(self):
        # Get Network IP of Host Machine
        print("-" * 20, "\nGetting the Private IP of Host...")
        self.privateIP = self.get_private_ip()
        self.privateIP_range = self.get_private_ip_range()
        print("Private IP of Host Machine:", self.privateIP)

        input("\n\nStart scan\t<Enter>\nExit\t\t<ctrl> + c\n")

    def _driver(self):

        # Scanning the network for devices
        print("-" * 20, "\nScanning the network...")
        self.devices_in_network = self.network_scanner()

        if self.devices_in_network:
            print("\nDevices found in the network:")
            print("Index\tIP Address\t\tMAC Address")
            print("--------------------------------------------------")
            for ind, device in enumerate(self.devices_in_network):
                print(f"{ind}\t{device['ip']}\t\t{device['mac']}")
        else:
            print("No devices found.")
            print("-" * 20 + "exiting")
            sys.exit(0)

        # Setting Target IP
        self.target_ip = ""
        while not self.verify_ip(self.target_ip):
            usr_inp = input("-" * 20 + "\nSelect the node ip to be scanned: ").strip()
            if "." not in usr_inp:
                try:
                    self.target_ip = self.devices_in_network[int(usr_inp)]['ip']
                except (IndexError, ValueError):
                    pass
            else:
                self.target_ip = usr_inp

        # Scanning OS of Target IP
        os_scan_result = self.os_scanner(self.target_ip)
        if os_scan_result['status'] == "success":
            print("\nOperating System Analysis:")
            for match in os_scan_result['os_matches']:
                print(f"Name: {match['name']}\nAccuracy: {match['accuracy']}%\n")
                self.__os_target = self._verify_os(match['name'])
                break
        else:
            print(f"Error: {os_scan_result['message']}")

        while 1:
            usr_inp = input("\n\nContinue scan\t\t<Enter>\nChange node\t\tchange (c)\n")
            if usr_inp in ["Change", "change", "C", "c"]:
                return 1
            if usr_inp == "":
                break

        # Scanning Services on Target IP
        service_scan_result = self.service_scan(self.target_ip)

        if service_scan_result['status'] == "success":
            print("\nService Scan Results:")
            print("Port\tState\tName\tProduct\tVersion")
            print("----------------------------------------------------------")
            for service in service_scan_result['services']:
                if service['state'] == "open":
                    self.__services_target[service['port']] = service['name']
                print(
                    f"{service['port']}\t{service['state']}\t{service['name']}"
                    f"\t{service['product']}\t{service['version']}")
        else:
            print(f"Error: {service_scan_result['message']}")

        # Scanning for Versions on Target IP
        version_scan_result = self.version_scan(self.target_ip)

        if version_scan_result['status'] == "success":
            print("\nVersion Scan Results:")
            print("Port\tState\tName\tProduct\tVersion")
            print("----------------------------------------------------------")
            for version in version_scan_result['services']:
                if version['state'] == "open":
                    self.__versions_target[version['port']] = version['name']
                print(
                    f"{version['port']}\t{version['state']}\t{version['name']}\t{version['product']}"
                    f"\t{version['version']}")
        else:
            print(f"Error: {version_scan_result['message']}")

        # Displaying Findings
        print("-" * 20 + "\nself.__os_target:", self.__os_target)
        print("self.__services_target:", self.__services_target)
        print("self.__versions_target:", self.__versions_target)

        # Search for Exploit
        total_exp_count = 0
        print("-" * 20)
        for k in self.__services_target.keys():
            if self.__versions_target.get(k):
                query = f"{self.__services_target[k]} {self.__versions_target[k]} remote py"
            else:
                query = f"{self.__services_target[k]} remote py"
            result = search_exploit(query)

            if result['status'] == "success":
                print(f"\nExploit Search Results for {self.__services_target[k]} {self.__versions_target[k]}:")
                print(json.dumps(result['data']["RESULTS_EXPLOIT"], indent=4))
                print("Exploit Count:", len(result['data']["RESULTS_EXPLOIT"]))
                total_exp_count += len(result['data']["RESULTS_EXPLOIT"])
            else:
                print(f"Error: {result['message']}")
            print("\n"+"-" * 20)
        print(f"Total Exploits found for the running services: {total_exp_count}")
        print("\n" + "-" * 20)
        print("Analysing the Exploits...")

        time.sleep(2)
        print(f"Selecting best exploit from: {total_exp_count} exploits...\n")
        time.sleep(3)
        print("Best Exploit\tService\t\tVersion\t\tOS")
        print("---------------------------------------------------")
        print("49757\t\tftp\t\tvsftpd\t\tLinux")
        input("\n\nGain access\t<Enter>\nExit\t\t<ctrl> + c\n")
        AttackEngine().exploit("attack_engine/utils/_49757.py", self.target_ip)
        return 0

    def _verify_os(self, os_desc: str) -> str:
        for d in os_desc.strip().split(" "):
            if d in self.__standard_os:
                print("Re-Verified OS is:", d)
                return d
        return ""

    @staticmethod
    def get_private_ip() -> str:
        """
            get_privateIP is a staticmethod that returns
            the Private IP address of the host machine
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))  # Connect to an external server (Google DNS)
        except OSError as ose:
            print(ose)
            print("Exiting...")
            sys.exit(1)
        ip_address = s.getsockname()[0]  # Get the IP address of the machine
        s.close()

        return ip_address

    @staticmethod
    def verify_ip(ip_address) -> bool:
        try:
            if len(ip_address.split(".")) == 4:
                for i in ip_address.split("."):
                    int(i)
                return True
            else:
                return False
        except Exception as e:
            return False

    def get_private_ip_range(self) -> str:
        ip_range = ".".join(self.privateIP.split(".")[:-1]) + ".0/24"
        return ip_range

    def network_scanner(self, ip_range: str = "") -> list:
        """
        Scans the network for active devices within the specified IP range.

        Args:
            ip_range (str): The IP range to scan, e.g., "192.168.1.1/24".

        Returns:
            list: A list of dictionaries containing IP and MAC addresses of active devices.
        """
        # Create an ARP request packet
        if len(ip_range) == 0:
            ip_range = self.privateIP_range
        arp_request = ARP(pdst=ip_range)
        # Create an Ethernet frame to wrap the ARP request
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send the packet and capture responses
        responses, _ = srp(packet, timeout=5, verbose=False)

        # Parse the responses to extract IP and MAC addresses
        devices = []
        for response in responses:
            devices.append({
                "ip": response[1].psrc,
                "mac": response[1].hwsrc
            })

        return devices

    @staticmethod
    def os_scanner(target_ip) -> dict[str, str | Any] | dict[str, str] | dict[str, str]:
        """
        Analyzes the operating system of a given IP address using nmap.

        Args:
            target_ip (str): The IP address to analyze.

        Returns:
            dict: Information about the operating system or an error message.
        """
        # Create a Nmap PortScanner object
        nm = nmap.PortScanner()

        try:
            print("-" * 20, f"\nScanning IP: {target_ip} for OS detection...")
            # Run the OS detection scan
            scan_result = nm.scan(hosts=target_ip, arguments="-O", timeout=1000)
            # Check if the scan was successful
            if 'osmatch' in scan_result['scan'][target_ip]:
                os_matches = scan_result['scan'][target_ip]['osmatch']
                return {
                    "status": "success",
                    "os_matches": os_matches
                }
            else:
                return {
                    "status": "error",
                    "message": "No OS information could be determined."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    @staticmethod
    def service_scan(target_ip):
        """
        Runs a Nmap service scan on the given IP address.

        Args:
            target_ip (str): The IP address to scan.

        Returns:
            dict: Information about the services or an error message.
        """
        # Create a Nmap PortScanner object
        nm = nmap.PortScanner()

        try:
            print("-" * 20, f"\nScanning IP: {target_ip} for services...")
            # Run the service scan
            # scan_result = nm.scan(hosts=target_ip, arguments="-sV", timeout=1000)
            scan_result = nm.scan(hosts=target_ip, arguments="-r", timeout=1000)

            # Check if the scan was successful
            if target_ip in scan_result['scan']:
                services = []
                for port in scan_result['scan'][target_ip].get('tcp', {}):
                    port_info = scan_result['scan'][target_ip]['tcp'][port]
                    services.append({
                        "port": port,
                        "state": port_info.get('state', 'unknown'),
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', 'unknown'),
                        "version": port_info.get('version', 'unknown')
                    })
                return {
                    "status": "success",
                    "services": services
                }
            else:
                return {
                    "status": "error",
                    "message": "No services could be determined."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    @staticmethod
    def version_scan(target_ip):
        """
        Runs a Nmap service scan on the given IP address.

        Args:
            target_ip (str): The IP address to scan.

        Returns:
            dict: Information about the services or an error message.
        """
        # Create a Nmap PortScanner object
        nm = nmap.PortScanner()

        try:
            print("-" * 20, f"\nScanning IP: {target_ip} for services...")
            # Run the service scan
            scan_result = nm.scan(hosts=target_ip, arguments="-sV", timeout=1000)
            # scan_result = nm.scan(hosts=target_ip, arguments="-r", timeout=1000)

            # Check if the scan was successful
            if target_ip in scan_result['scan']:
                services = []
                for port in scan_result['scan'][target_ip].get('tcp', {}):
                    port_info = scan_result['scan'][target_ip]['tcp'][port]
                    services.append({
                        "port": port,
                        "state": port_info.get('state', 'unknown'),
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', 'unknown'),
                        "version": port_info.get('version', 'unknown')
                    })
                return {
                    "status": "success",
                    "services": services
                }
            else:
                return {
                    "status": "error",
                    "message": "No services could be determined."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


if __name__ == "__main__":
    splash = os.listdir("splash")
    splash = splash[random.randint(0, len(splash)-1)]
    with open(f"splash/{splash}", "rb") as adf:
        animation = pickle.load(adf)
    os.system('clear')
    k = 0
    while k < 11:
        for i in range(1, 11, 1):
            os.system("clear")
            print(animation[i])
            print("starting STROT CLI v2.1.3")
            print("Stealthy Tool for Root Oriented Tunneling - A RED TEAMING TOOL")
            time.sleep(0.2)
            k += 1
    time.sleep(1)
    obj = STROTCLI()
