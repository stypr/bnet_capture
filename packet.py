"""
packet.py

Broodwar IP capture, not stable.

2021.07.02 by stypr (https://harold.kim/)
"""

import binascii
import pyshark
import os

def trace_room(device_interface):
    """ (str) -> NoneType


    Trace StarCraft room information
    """
    user_list = {}
    capture = pyshark.LiveCapture(interface=device_interface)

    for packet in capture.sniff_continuously(): 
        try:
            if packet.udp.dstport == "6112":
                if packet.udp.payload.startswith("08:01:12:a6:03"):
                    # unhexlify
                    _parsed_payload = packet.udp.payload.replace(":", "")
                    _parsed_payload = binascii.unhexlify(_parsed_payload)

                    # parse...
                    _battle_tag = _parsed_payload[0x1b:]
                    _battle_tag = _battle_tag.split(b"\x00")[0]
                    _nickname = _parsed_payload[0xe3:]
                    _nickname = _nickname.split(b"\x00")[0]
                    _battle_tag = _battle_tag.decode()
                    _nickname = _nickname.decode()

                    # insert info
                    # skip host
                    _key = packet.ip.src
                    if _key.startswith("158.115."):
                        continue
                    _data = f"{_nickname}:{_battle_tag}"
                    if user_list.get(_key):
                        if _data not in user_list[_key]:
                            user_list[_key].append(_data)
                    else:
                        user_list[_key] = [_data]

                    os.system("cls")
                    for k, v in user_list.items():
                        print(f"- {k}")
                        for i in v:
                            _i = i.split(":")
                            print(f"    - Nick: {_i[0]}")
                            print(f"    - BTag: {_i[1]}")
                            print("")
        except AttributeError:
            # Not UDP
            continue

if __name__ == "__main__":
    # Need NPF device ID for getting traffic
    DEVICE_ID = "\\Device\\NPF_{8A1296EE-A0F9-49ED-877F-5E050B5629BB}"
    trace_room(DEVICE_ID)
