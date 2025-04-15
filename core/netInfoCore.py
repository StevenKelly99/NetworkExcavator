from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether, IPv6 
from collections import defaultdict  
from concurrent.futures import ThreadPoolExecutor

def osDetector(ttl=None, window_size=None, **_):
    """
    Detects the OS based on the TTL and TCP window size.
    """
    ttlList = {
        255: "Cisco Router",  
        128: "Windows",       
        64: "Linux",          
    }

    sizeList = {
        4128: "Cisco Router",
        8192: "Windows",
        65535: "MacOS",
        5840: "Linux",
        5720: "Google's Linux"
    }

    if ttl in ttlList: # Try to detect OS using TTL first, then window size
        return ttlList[ttl]
    if window_size in sizeList:
        return sizeList[window_size]
    return "Unknown"  # If no match

def processPacket(pkt):
    """
    Extracts information from a packet including: IPs, MACs, ports, protocol
    Returns a dictionary with the extracted data.
    """
    if not (IP in pkt or IPv6 in pkt): # Skip packets that aren't IP
        return None

    ip = pkt[IP] if IP in pkt else pkt[IPv6]
    src_ip, dst_ip = ip.src, ip.dst
    ttl = getattr(ip, 'ttl', None)  # Time-to-Live
    ip_id = getattr(ip, 'id', None)  # Identification field
    df_flag = int(getattr(getattr(ip, 'flags', 0), 'DF', False)) 

    # Extract source and destination ports from TCP or UDP
    sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else None
    dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else None
    conv_key = (src_ip, dst_ip, sport, dport)

    # Extract TCP-specific values
    window_size = mss = None
    if TCP in pkt:
        window_size = pkt[TCP].window
        # Extract MSS value from TCP options
        mss = next((v for k, v in pkt[TCP].options if k == 'MSS'), None)

    # Attempt OS detection based on TTL and window size
    os_info = osDetector(ttl, window_size, mss=mss, ip_id=ip_id, df_flag=df_flag) if ttl else "Unknown"

    return {
        "conv_key": conv_key,  # IPs and ports used to identify a session
        "mac": (pkt[Ether].src, pkt[Ether].dst) if Ether in pkt else None,  # MAC addresses
        "proto": TCP in pkt and "TCP" or UDP in pkt and "UDP" or ICMP in pkt and "ICMP",  # Protocol used
        "os": (src_ip, os_info),  # Detected OS
        "ports": (sport, dport) if sport and dport else None  # Ports involved
    }

def infoExtractor(pcap_file):
    """
    Main function that takes a PCAP file and extracts information: MAC addresses, Ports, Protocols, and Operating Systems
    Uses multithreading to process packets in parallel.
    """
    packets = rdpcap(pcap_file)  # Read all packets from the PCAP file

    conversations = defaultdict(lambda: { # Conversations are grouped by src_ip, dst_ip, sport, dport
        "MAC Addresses": set(),
        "Ports": set(),
        "Protocols": set(),
        "OS": {} 
    })

    with ThreadPoolExecutor(max_workers=8) as executor: # Process packets in parallel using a thread pool
        for data in executor.map(processPacket, packets):
            if not data:
                continue  # Skip if packet isn't IPv4/IPv6
            c = conversations[data["conv_key"]] 

            if data["mac"]: # Update MAC addresses
                c["MAC Addresses"].update(data["mac"])

            if data["proto"]: # Update protocol (TCP/UDP/ICMP)
                c["Protocols"].add(data["proto"])
            
            if data["os"]: # Update OS fingerprint
                c["OS"][data["os"][0]] = data["os"][1]

            if data["ports"]: # Ports
                c["Ports"].update(data["ports"])

    return conversations  # Returns dictionary of conversation metadata
