from __future__ import annotations
import struct
from typing import Any
from dns_engine import QTYPE_NAMES, parse_question

def _udp_dns_payload(frame: bytes) -> tuple[bytes, str] | None:
    """Return an outbound plain-DNS payload from an Ethernet frame."""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack('!H', frame[12:14])[0]
    offset = 14
    if ether_type == 33024 and len(frame) >= 18:
        ether_type = struct.unpack('!H', frame[16:18])[0]
        offset = 18
    if ether_type == 2048:
        if len(frame) < offset + 20:
            return None
        header_length = (frame[offset] & 15) * 4
        if header_length < 20 or len(frame) < offset + header_length:
            return None
        protocol = frame[offset + 9]
        payload_offset = offset + header_length
    elif ether_type == 34525:
        if len(frame) < offset + 40:
            return None
        protocol = frame[offset + 6]
        payload_offset = offset + 40
    else:
        return None
    if protocol == 17:
        if len(frame) < payload_offset + 8:
            return None
        source_port, destination_port, udp_length = struct.unpack('!HHH', frame[payload_offset:payload_offset + 6])
        if destination_port != 53 or udp_length < 8:
            return None
        end = min(len(frame), payload_offset + udp_length)
        return (frame[payload_offset + 8:end], 'udp')
    if protocol == 6:
        if len(frame) < payload_offset + 20:
            return None
        source_port, destination_port = struct.unpack('!HH', frame[payload_offset:payload_offset + 4])
        if destination_port != 53:
            return None
        tcp_header_length = (frame[payload_offset + 12] >> 4) * 4
        dns_offset = payload_offset + tcp_header_length
        if tcp_header_length < 20 or len(frame) < dns_offset + 2:
            return None
        dns_length = struct.unpack('!H', frame[dns_offset:dns_offset + 2])[0]
        if dns_length < 12 or len(frame) < dns_offset + 2 + dns_length:
            return None
        return (frame[dns_offset + 2:dns_offset + 2 + dns_length], 'tcp')
    return None

def extract_dns_query(frame: bytes) -> dict[str, Any] | None:
    """Extract a valid outbound DNS question without inspecting HTTPS content."""
    extracted = _udp_dns_payload(frame)
    if not extracted:
        return None
    payload, transport = extracted
    try:
        question = parse_question(payload)
    except ValueError:
        return None
    return {'domain': question.domain, 'qtype': question.qtype, 'qtypeName': QTYPE_NAMES.get(question.qtype, f'TYPE{question.qtype}'), 'transport': transport}
