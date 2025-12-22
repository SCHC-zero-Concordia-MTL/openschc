import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from scapy.all import *

import gen_rulemanager as RM
from protocol import SCHCProtocol
from scapy_connection import *
from gen_utils import dprint, sanitize_value
from compr_parser import Unparser
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

import pprint
import binascii
import socket
import ipaddress
import configparser
import os
import sys

import cbor2 as cbor

config_ini = configparser.ConfigParser()
config_path = os.path.join(os.getcwd(), "resources", "network.ini")
success = config_ini.read(config_path)

if not success:
    print(f"Could not successfully read the config file on path {config_path}")
    sys.exit(1)

bridge_service_ip = config_ini["Network"].get("bridge_service_ip")
bridge_service_port = config_ini["Network"].getint("bridge_service_port")
schc_gateway_ip = config_ini["Network"].get("schc_gateway_ip")
schc_gateway_port = config_ini["Network"].getint("schc_gateway_port")

schc_gateway_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
schc_gateway_sock.bind((schc_gateway_ip, schc_gateway_port))

# Create a Rule Manager and upload the rules.
rm = RM.RuleManager()
rm.Add(file="ipv6_udp.bin.json")
rm.Print()

unparser = Unparser()

def processPkt(pkt):
    """ called when scapy receives a packet, since this function takes only one argument,
    schc_machine and scheduler must be specified as a global variable.
    """
    scheduler.run(session=schc_machine)
    print(pkt.sniffed_on, pkt.summary())

    # look for a tunneled SCHC pkt
    if pkt.getlayer(Ether) != None: #HE tunnel do not have Ethernet
        e_type = pkt.getlayer(Ether).type
        # if IPV4
        if e_type == 0x0800:
            ip_proto = pkt.getlayer(IP).proto
            if ip_proto == 17:
                udp_sport = pkt.getlayer(UDP).sport
                src_ip = pkt.getlayer(IP).src
                if False:#udp_dport == socket_port: # tunnel SCHC msg to be decompressed
                    print ("tunneled SCHC msg")                    
                    schc_pkt, addr = tunnel.recvfrom(2000)
                    other_end = "udp:"+addr[0]+":"+str(addr[1])
                    print("other end =", other_end)
                    uncomp_pkt = schc_machine.schc_recv(device_id=other_end, schc_packet=schc_pkt)                  
                    if uncomp_pkt != None:
                        uncomp_pkt[1].show()
                        send(uncomp_pkt[1], iface="lo")
                # IF it's a packet from connector.py
                elif udp_sport == bridge_service_port and src_ip == bridge_service_ip:
                    print("Received from connector.py")
                    schc_msg = bytes(pkt.getlayer(UDP).payload)
                    print (binascii.hexlify(schc_msg))
                    msg = cbor.loads(schc_msg)
                    print("msg(dict) =", msg)

                    # msg parts:
                    # 1: technology (1=lorawan) 
                    # 2: devEUI
                    # 3: 59?
                    # 4: payload (schc_packet)
                    # -1: 12?
                    # -2: 28?

                    other_end =""
                    techno = msg[1]
                    if techno == 1:
                        # build DeviceID="lorawan:DEUI"
                        other_end += "lorawan:"
                        other_end +=  binascii.hexlify(msg[2]).decode("utf-8")
                        
                        # Decompress packet
                        print(other_end)
                        print(">decompressing packet...")
                        uncomp_pkt = schc_machine.schc_recv(schc_packet=msg[4], device_id=other_end)
                        print ("--->", uncomp_pkt)
                        if uncomp_pkt != None:
                            print("--- uncomp_pkt[1].show() ---")
                            ipv6udp_packet = uncomp_pkt[1]
                            ipv6udp_packet.show()
                            print(">sending..")
                            send(ipv6udp_packet, iface="lo", verbose=True)
                            # print(">sending 2..")
                            # print(ipv6udp_packet.fields.keys())

                    else:
                        print ("unknown technology")

                    print ("other_end = ", other_end)
                    
        # IF IPv6:
        elif e_type == 0x86dd:
                ip_nh = pkt.getlayer(IPv6).nh
                if ip_nh == 17:
                    src_ip = pkt.getlayer(IPv6).src
                    src_port = pkt.getlayer(UDP).sport
                    if ipaddress.IPv6Address(src_ip) == ipaddress.IPv6Address("::1") and src_port == 22222:
                        pkt.getlayer(IPv6).dst = "::1"
                        pkt.getlayer(UDP).dport = 33333
                    print("Not in tunnel")
                    print (">> GOT IPv6 Packet:\n", binascii.hexlify(bytes(pkt)[14:]))
                    # compress and send (to L2 send())
                    schc_machine.schc_send(bytes(pkt)[14:], verbose=True)
    else:
        print ("tunnel")
        print (">> GOT IPv6 Packet:\n", binascii.hexlify(bytes(pkt)))
        schc_machine.schc_send(bytes(pkt), verbose =True)

# Start SCHC Machine
POSITION = T_POSITION_CORE

'''
socket_port = 0x5C4C
tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tunnel.bind(("0.0.0.0", socket_port))

bridge_service_ip = "127.0.0.1"
bridge_service_port = 12345

schc_gateway_ip = "127.0.0.1"
schc_gateway_port = 33033
schc_gateway_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
schc_gateway_sock.bind((schc_gateway_ip, schc_gateway_port))
'''
lower_layer = ScapyLowerLayer(position=POSITION, socket=schc_gateway_sock, other_end=None)
system = ScapySystem()
scheduler = system.get_scheduler()
schc_machine = SCHCProtocol(
    system=system,           # define the scheduler
    layer2=lower_layer,      # how to send messages
    role=POSITION,           # DEVICE or CORE
    verbose = True)         
schc_machine.set_rulemanager(rm)

sniff(prn=processPkt, iface=["lo"], filter= f"inbound and (dst host {schc_gateway_ip} or dst host ::1) and udp and dst port {schc_gateway_port}") #iface=["he-ipv6", "ens3", "lo"]) # , filter="udp port 5683 or udp port 7002"