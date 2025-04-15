import os
import subprocess
from io import BytesIO
from PIL import Image
from scapy.all import rdpcap, TCP, IP, IPv6
from collections import defaultdict

EXTRACTED_IMAGES_DIR = os.path.join( "artifacts", "images")
TSHARK_TEMP_DIR = os.path.join("artifacts", "tshark_dump")

os.makedirs(EXTRACTED_IMAGES_DIR, exist_ok=True)
os.makedirs(TSHARK_TEMP_DIR, exist_ok=True)

EXTENSION_MAP = {
    'jpeg': 'jpg', 'jpg': 'jpg', 'png': 'png', 'gif': 'gif', 'bmp': 'bmp', 'ico': 'ico', 'x-icon': 'ico', 'webp': 'webp',
    'tiff': 'tiff', 'tif': 'tiff', 'svg': 'svg', 'jfif': 'jpg', 'pjpeg': 'jpg', 'pjp': 'jpg', 'avif': 'avif', 'apng': 'png', 
    'heic': 'heic', 'heif': 'heic', 'emf': 'emf', 'wmf': 'wmf',
}

IMAGE_SIGNATURES = {
    b'\xff\xd8\xff': b'\xff\xd9',                             # JPEG
    b'\x89PNG\r\n\x1a\n': b'IEND\xaeB`\x82',                  # PNG
    b'GIF89a': b'\x00;',                                      # GIF89a
    b'GIF87a': b'\x00;',                                      # GIF87a
    b'BM': None,                                              # BMP (no clear EOF)
    b'RIFF': None,                                            # WEBP starts with RIFF
    b'\x00\x00\x01\x00': None,                                # ICO
    b'II*\x00': None,                                         # TIFF (little endian)
    b'MM\x00*': None,                                         # TIFF (big endian)
    b'\x00\x00\x01\x00': None,                                # CUR / ICO
    b'\x00\x00\x02\x00': None,                                # TGA?
    b'<?xml': None,                                           # SVG (if not compressed)
    b'ftypavif': None,                                        # AVIF (box-based)
    b'ftypheic': None,                                        # HEIC
    b'ftypheix': None,                                        # HEIF variant
    b'ftypmsf1': None,                                        # HEIF from MS
}

def extractTCPStreams(pcap_file):
    """
    Extracts and reassembles TCP streams from a PCAP file.
    """
    packets = rdpcap(pcap_file)  # Read from the PCAP file
    streams = defaultdict(dict)  # Groups payloads by connection and sequence

    for pkt in packets:
        if (IP in pkt or IPv6 in pkt) and TCP in pkt and pkt[TCP].payload:
            ip = pkt[IP] if IP in pkt else pkt[IPv6]
            tcp = pkt[TCP]
            key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            streams[key][tcp.seq] = bytes(tcp.payload)

    return {
        key: b''.join(streams[key][seq] for seq in sorted(streams[key]))
        for key in streams
    }

def imagesFromBinaryStream(data, http_image_pixels_set, count):
    """
    Scans binary data for known image signatures to extract and save valid images.
    Returns updated image count.
    """
    for sig_start in IMAGE_SIGNATURES:  # Loop through all known image signatures
        pos = 0
        while (start := data.find(sig_start, pos)) != -1:
            end = start + 10_000_000  # Try reading up to 10 MB past the signature
            candidate = data[start:end] 
            try: # Attempt to load the candidate image as an image
                with Image.open(BytesIO(candidate)) as img:
                    img.load()
                    img_pixels = img.convert("RGB").tobytes()

                    if img_pixels in http_image_pixels_set: # Skip image if its pixel data matches any from the HTTP-exported set
                        pos = start + len(candidate)
                        continue

                    ext = EXTENSION_MAP.get(img.format.lower(), 'bin') # Determine file extension based on image format (fallback to .bin)
                    filename = f"image_{count + 1}.{ext}"
                    img.save(os.path.join(EXTRACTED_IMAGES_DIR, filename))  # Save image to folder
                    count += 1
                pos = start + len(candidate)
            except:
                pos = start + 1 # If image loading fails, skip to the next byte
    return count

def extractImages(pcap_file):
    """
    Extracts images from a PCAP file using both HTTP object export via tshark and scapy scanning of TCP streams.
    """
    for folder in [TSHARK_TEMP_DIR, EXTRACTED_IMAGES_DIR]:  # Clean directories for next use
        for f in os.listdir(folder):
            try:
                os.remove(os.path.join(folder, f))
            except:
                pass 

    http_image_pixels_set = set() 
    count = 0  # Counter for saved images

    try: # Use tshark to export HTTP objects
        subprocess.run([
            "tshark",
            "-r", pcap_file,
            "--export-objects", f"http,{TSHARK_TEMP_DIR}"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        return 0  # If tshark fails, return 0 images extracted

    for fname in os.listdir(TSHARK_TEMP_DIR): 
        path = os.path.join(TSHARK_TEMP_DIR, fname)
        try:
            with open(path, "rb") as f:
                raw = f.read()
                with Image.open(BytesIO(raw)) as img:
                    img.load()
                    ext = EXTENSION_MAP.get(img.format.lower(), 'bin')
                    out_name = f"image_{count + 1}.{ext}"
                    img.save(os.path.join(EXTRACTED_IMAGES_DIR, out_name))
                    img_pixels = img.convert("RGB").tobytes()
                    http_image_pixels_set.add(img_pixels) 
                    count += 1
        except:
            continue  # Skip invalid images

    tcp_streams = extractTCPStreams(pcap_file) # Reassemble TCP streams and look for raw image data
    for stream_data in tcp_streams.values():
        count = imagesFromBinaryStream(stream_data, http_image_pixels_set, count)

    return count  # Total number of images saved
