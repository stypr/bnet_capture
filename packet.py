#!/usr/bin/python -u

"""
packet.py

Broodwar IP capture, not stable.

2021.07.02 by stypr (https://harold.kim/)
"""

import os
import sys
import locale
import binascii
import subprocess
import pyshark

def read_from(s, start):
    """ (bytes, bytes) -> bytes

    Read from a given character.

    >>> read_from(b"test12341", b"1")
    2341
    """
    return start.join(s.split(start)[1:])

def read_until(s, until=b"\x00"):
    """ (bytes) -> bytes

    Read until a given character
    """
    return s.split(until)[0]


def trace_room(device_interface):
    """ (str) -> NoneType


    Trace StarCraft room information
    """
    user_list = {}
    user_host = None
    capture = pyshark.LiveCapture(interface=device_interface)

    for packet in capture.sniff_continuously():
        try:
            # skip host
            _key = packet.ip.src
            if _key.startswith("158.115."):
                if (packet.udp.payload.startswith("08:01:12:") and
                    packet.udp.payload[12:14] == "01"):
                    
                    payload = packet.udp.payload.replace(":", "")
                    payload = binascii.unhexlify(payload).split(b",")
                    # Remove all from the user list when a new packet arrives
                    if len(payload) == 16:
                        user_host = payload[11].split(b"\r")[0].decode()
                        user_list = {}
                continue


            if packet.udp.dstport == "6112":
                payload = packet.udp.payload.replace(":", "")
                payload = binascii.unhexlify(payload)

                # Magic Header
                if payload.startswith(b"\x08\x01\x12"):
                    _packet_header = payload[:0x15]
                    _packet_content = payload[0x15:]
                    _packet_header_type = payload[0x3]

                    _packet_is_info = _packet_header_type == 0xa6
                    _packet_is_chat = _packet_header[0x14] == 0x4c
                    _packet_is_ping = _packet_header_type == 0x11


                    # 유저 정보 파싱
                    if _packet_is_info:
                        # print(_packet_content)
                        _packet_user = _packet_content[0x2]
                        _packet_battle_tag = read_until(_packet_content[0x6:], b"\x00")
                        _packet_nickname = read_from(read_from(_packet_content, _packet_battle_tag), b"??")
                        _packet_nickname = read_until(_packet_nickname[0x62:], b"\x00")
                        print("ID:", _packet_user, "/ BTag:", _packet_battle_tag.decode(), "/ Nickname:", _packet_nickname.decode())

                    # 채팅 내용 파싱
                    if _packet_is_chat:
                        _packet_chat_user = payload[0x12]
                        _packet_chat_content = read_until(_packet_content, b"\x00").decode()
                        print("ID:", _packet_chat_user, "/ Data:", _packet_chat_content)

                    # TODO: 퇴장내용파싱, 방장확인, 보내는 패킷 알아보기 (여러 서버로 보내는 것 같음.)

                """
                    # insert info
                    _data = f"{nickname}:{battle_tag}"
                    if (user_list.get(_key) and
                    _data not in user_list[_key]):
                        user_list[_key].append(_data)
                    else:
                        user_list[_key] = [_data]

                    # print_status(user_list, user_host)
                """

        except AttributeError:
            # Not UDP
            continue

if __name__ == "__main__":
    # Need NPF device ID for getting traffic
    # _encoding = locale.getpreferredencoding()
    # cmd = ["C:\\Program Files\Wireshark\\tshark.exe", "-D"]
    # p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    # p.wait()
    # print(p.stdout.read().decode(_encoding).strip())
    #  os.popen("")c
    
    DEVICE_ID = "\\Device\\NPF_{8A1296EE-A0F9-49ED-877F-5E050B5629BB}"
    trace_room(DEVICE_ID)
