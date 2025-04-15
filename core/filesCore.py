import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from scapy.all import rdpcap, TCP, IP, IPv6, Raw

FILE_EXTS = [
    b".jpg", b".jpeg", b".png", b".gif", b".bmp", b".tiff", b".webp", b".ico", b".heic", b".svg", # Images
    b".pdf", b".doc", b".docx", b".xls", b".xlsx", b".ppt", b".pptx", b".odt", b".ods", b".odp", b".rtf", b".txt", # Documents
    b".zip", b".rar", b".7z", b".tar", b".gz", b".bz2", b".xz", b".iso", b".lz", b".zst", # Archives
    b".exe", b".msi", b".bat", b".sh", b".py", b".pl", b".js", b".jar", b".apk", b".com", b".bin", b".dll", b".so", # Scripts
    b".mp3", b".wav", b".ogg", b".flac", b".aac", b".wma", b".m4a", # Audio
    b".mp4", b".avi", b".mkv", b".mov", b".flv", b".wmv", b".webm", # Video
    b".ttf", b".otf", b".woff", b".woff2", # Fonts
    b".html", b".htm", b".css", b".js", b".json", b".xml", b".php", b".asp", b".jsp", # Web
    b".log", b".cfg", b".ini", b".db", b".sqlite", b".bak", b".tmp" # Misc
]

def isValid(name):
    """
    Validates filename. Allows only alphanumeric characters, underscores, dashes, and dots.
    """
    return re.match(rb"^[\w\-.]+$", name.encode() if isinstance(name, str) else name)

def extractNames(data):
    """
    Extracts possible filenames from the given raw data.
    Looks for 'Content-Disposition' headers with a filename and scans for known file extensions
    """
    names = set()

    # Extract filenames from HTTP headers
    for match in re.findall(br'Content-Disposition:.*?filename="(.+?)"', data, re.I):
        try:
            if isValid(match):
                names.add(match.decode(errors="ignore"))
        except:
            continue

    for ext in FILE_EXTS: # Scan raw data for known file extensions and extract possible filenames
        start = 0
        while (idx := data.find(ext, start)) != -1:
            start = idx + 1  # Move past current match for next iteration
            # Get a chunk of data before the extension to guess the filename
            chunk = data[max(0, idx - 100): idx + len(ext)]
            # Split on path separators to isolate the filename
            part = re.split(br"[\\/]", chunk)[-1]
            try:
                if isValid(part):
                    names.add(part.decode(errors="ignore"))
            except:
                continue

    return names

def extractTCPData(pkt):
    """
    Extracts relevant TCP stream from a PCAP if it contains IP, TCP, and Raw payload.
    """
    if (IP in pkt or IPv6 in pkt) and TCP in pkt and pkt.haslayer(Raw):
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        return (ip.src, ip.dst, pkt[TCP].sport, pkt[TCP].dport), pkt[TCP].seq, bytes(pkt[TCP].payload)

def parsePcapForFiles(path):
    """
    Parses a PCAP file, reassembles TCP streams, and extracts potential file names found in the data.
    Uses a thread pool for speed. Reconstructs TCP streams by sequence numbers. Searches for filenames in the reassembled streams.
    """
    packets = rdpcap(path) # Load packets from the PCAP file

    with ThreadPoolExecutor() as ex: # Process packets concurrently to extract TCP stream info
        results = filter(None, ex.map(extractTCPData, packets))

    streams = defaultdict(dict)
    for streamID, seq, payload in results:
        streams[streamID][seq] = payload

    
    files = { # Extract filenames from the reassembled payloads for each stream
        tuple(sorted([streamID[0], streamID[1]])) + (name,)
        for streamID, seqNum in streams.items()
        for name in extractNames(b"".join(seqNum[k] for k in sorted(seqNum)))
    }

    return list(files)  # Return list of tuples