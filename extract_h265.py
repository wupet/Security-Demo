#!/usr/bin/env python3
import sys
from collections import Counter
from scapy.all import rdpcap, UDP, Raw

NAL_START = b'\x00\x00\x00\x01'

def parse_rtp(payload):
    if len(payload) < 12 or (payload[0] & 0xC0) != 0x80:
        return None
    cc = payload[0] & 0xF
    extension = (payload[0] >> 4) & 0x1
    seq = int.from_bytes(payload[2:4], 'big')
    ts = int.from_bytes(payload[4:8], 'big')
    ssrc = int.from_bytes(payload[8:12], 'big')
    pt = payload[1] & 0x7F
    marker = (payload[1] >> 7) & 0x1
    
    hl = 12 + cc * 4
    if extension:
        if len(payload) < hl + 4: return None
        ext_len = int.from_bytes(payload[hl+2:hl+4], 'big')
        hl += 4 + ext_len * 4
    
    if len(payload) <= hl: return None
    return (seq, ts, ssrc, pt, marker, payload[hl:])


def extract(pcap_file, output_file, target_ssrc=None):
    print(f"[*] Loading {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    rtp = []
    for pkt in packets:
        if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            continue
        r = parse_rtp(bytes(pkt[Raw]))
        if r: rtp.append(r)
    
    print(f"[*] Found {len(rtp)} RTP packets")
    
    ssrcs = Counter(p[2] for p in rtp)
    print(f"[*] SSRCs: " + ", ".join(f"0x{s:08x}({c})" for s,c in ssrcs.most_common()))
    
    if target_ssrc is None:
        target_ssrc = ssrcs.most_common(1)[0][0]
    print(f"[*] Using SSRC 0x{target_ssrc:08x}")
    
    stream = sorted([p for p in rtp if p[2] == target_ssrc], key=lambda x: x[0])
    print(f"[*] Stream has {len(stream)} packets")
    
    # Handle sequence number wrap
    fu_data = bytearray()
    fu_nal_header = None
    nalus = 0
    nal_types_seen = Counter()
    
    with open(output_file, 'wb') as f:
        for seq, ts, ssrc, pt, marker, data in stream:
            if len(data) < 2:
                continue
            
            # HEVC NAL header (2 bytes)
            nal_type = (data[0] >> 1) & 0x3F
            
            if nal_type <= 47:
                # Single NAL unit
                f.write(NAL_START + data)
                nalus += 1
                nal_types_seen[nal_type] += 1
                # Discard any pending FU
                fu_data = bytearray()
                fu_nal_header = None
            
            elif nal_type == 48:
                # Aggregation packet - skip 2-byte PayloadHdr
                offset = 2
                while offset + 2 <= len(data):
                    nalu_size = int.from_bytes(data[offset:offset+2], 'big')
                    offset += 2
                    if offset + nalu_size > len(data) or nalu_size == 0:
                        break
                    nalu_data = data[offset:offset+nalu_size]
                    f.write(NAL_START + nalu_data)
                    if len(nalu_data) >= 1:
                        nt = (nalu_data[0] >> 1) & 0x3F
                        nal_types_seen[nt] += 1
                    offset += nalu_size
                    nalus += 1
            
            elif nal_type == 49:
                # Fragmentation Unit
                if len(data) < 3:
                    continue
                fu_header = data[2]
                start = (fu_header >> 7) & 0x1
                end = (fu_header >> 6) & 0x1
                fu_nal_type = fu_header & 0x3F
                
                if start:
                    # Reconstruct NAL header: keep F bit and LayerId/TID from PayloadHdr, replace NAL type
                    nb1 = (data[0] & 0x81) | (fu_nal_type << 1)
                    nb2 = data[1]
                    fu_data = bytearray([nb1, nb2])
                    fu_data.extend(data[3:])
                    fu_nal_header = fu_nal_type
                elif fu_nal_header is not None:
                    fu_data.extend(data[3:])
                
                if end and fu_data and fu_nal_header is not None:
                    f.write(NAL_START + bytes(fu_data))
                    nal_types_seen[fu_nal_header] += 1
                    nalus += 1
                    fu_data = bytearray()
                    fu_nal_header = None
    
    print(f"[+] Wrote {nalus} NAL units")
    print(f"[+] NAL types seen: " + ", ".join(f"type{t}({c})" for t,c in nal_types_seen.most_common()))
    
    # Check for essential parameter sets
    has_vps = 32 in nal_types_seen
    has_sps = 33 in nal_types_seen
    has_pps = 34 in nal_types_seen
    print(f"[+] VPS(32): {'YES' if has_vps else 'MISSING'}, "
          f"SPS(33): {'YES' if has_sps else 'MISSING'}, "
          f"PPS(34): {'YES' if has_pps else 'MISSING'}")
    
    if not (has_vps and has_sps and has_pps):
        print("[!] WARNING: Missing parameter sets. The video stream began before capture.")
        print("[!] Decoding may fail. You need a capture that includes the stream start.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_h265_v2.py <pcap> <out.h265> [ssrc_hex]")
        sys.exit(1)
    pcap = sys.argv[1]
    out = sys.argv[2]
    ssrc = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    extract(pcap, out, ssrc)