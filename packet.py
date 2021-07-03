"""
packet.py

Broodwar IP capture, not stable.

2021.07.02 by stypr (https://harold.kim/)
"""

import os
import binascii
import pyshark

def print_status(user_list, user_host):
    """ (dict) -> NoneType

    Display current status
    """
    os.system("cls")
    print(f"지금 방장은 {user_host} 입니다.\n")
    for key, val in user_list.items():
        print(f"- {key}")
        for _val in val:
            _val = _val.split(":")
            print(f"    - Nick: {_val[0]}")
            print(f"    - BTag: {_val[1]}")
            print("")

def parse_info_packet(payload):
    """ (bytes) -> list of str

    Parse info packet and get Battle Tag and Nickname
    """
    battle_tag = payload[0x1b:]
    battle_tag = battle_tag.split(b"\x00")[0]
    nickname = payload[0xe3:]
    nickname = nickname.split(b"\x00")[0]
    battle_tag = battle_tag.decode()
    nickname = nickname.decode()
    return (battle_tag, nickname)

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
                if packet.udp.payload.startswith("08:01:12:a6:03"):
                    # unhexlify and parse
                    payload = packet.udp.payload.replace(":", "")
                    payload = binascii.unhexlify(payload)
                    battle_tag, nickname = parse_info_packet(payload)

                    # insert info
                    _data = f"{nickname}:{battle_tag}"
                    if (user_list.get(_key) and
                    _data not in user_list[_key]):
                        user_list[_key].append(_data)
                    else:
                        user_list[_key] = [_data]

                    print_status(user_list, user_host)

        except AttributeError:
            # Not UDP
            continue

if __name__ == "__main__":
    # Need NPF device ID for getting traffic
    # `tshark -D`
    DEVICE_ID = "\\Device\\NPF_{8A1296EE-A0F9-49ED-877F-5E050B5629BB}"
    trace_room(DEVICE_ID)
