from __future__ import annotations

import ftplib
import socket

SNMP_STANDARD_PORT = 161
SNMP_COMMUNITIES = ("public", "private")


def ftp_allows_anonymous(host_ip: str, port: int, timeout_seconds: float) -> bool:
    client = ftplib.FTP()
    try:
        client.connect(host=host_ip, port=port, timeout=timeout_seconds)
        response = client.login(user="anonymous", passwd="")
        return str(response).startswith("230")
    except (OSError, ftplib.all_errors):
        return False
    finally:
        try:
            client.quit()
        except (OSError, ftplib.all_errors):
            client.close()


def redis_allows_unauthenticated_commands(host_ip: str, port: int, timeout_seconds: float) -> bool:
    try:
        with socket.create_connection((host_ip, port), timeout=timeout_seconds) as client:
            client.sendall(b"*1\r\n$4\r\nPING\r\n")
            pong = client.recv(256)
            client.sendall(b"*1\r\n$4\r\nINFO\r\n")
            info = client.recv(512)
    except OSError:
        return False
    return pong.startswith(b"+PONG") and (info.startswith(b"$") or b"redis_version" in info)


def snmp_default_community(host_ip: str, port: int, timeout_seconds: float) -> str:
    for community in SNMP_COMMUNITIES:
        if _snmp_responds(host_ip, port, community, timeout_seconds):
            return community
    return ""


def _snmp_responds(host_ip: str, port: int, community: str, timeout_seconds: float) -> bool:
    request = _build_snmp_get_request(community)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout_seconds)
        try:
            client.sendto(request, (host_ip, port))
            response, _ = client.recvfrom(1024)
        except OSError:
            return False
    return response.startswith(b"\x30") and community.encode("ascii", errors="ignore") in response


def _build_snmp_get_request(community: str) -> bytes:
    oid = bytes.fromhex("2b06010201010100")
    version = _ber_wrap(0x02, b"\x00")
    community_field = _ber_wrap(0x04, community.encode("ascii", errors="ignore"))
    request_id = _ber_wrap(0x02, b"\x01")
    error_status = _ber_wrap(0x02, b"\x00")
    error_index = _ber_wrap(0x02, b"\x00")
    null_value = b"\x05\x00"
    varbind = _ber_wrap(0x30, _ber_wrap(0x06, oid) + null_value)
    varbind_list = _ber_wrap(0x30, varbind)
    pdu = _ber_wrap(0xA0, request_id + error_status + error_index + varbind_list)
    return _ber_wrap(0x30, version + community_field + pdu)


def _ber_wrap(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(payload)) + payload


def _ber_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes(2, byteorder="big").lstrip(b"\x00")
    return bytes([0x80 | len(encoded)]) + encoded
