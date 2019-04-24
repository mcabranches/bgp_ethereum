from netfilterqueue import NetfilterQueue
import socket
from scapy.all import *
import os
import pyshark
import threading
import queue
import netaddr
from web3 import Web3, HTTPProvider
from eth_account import Account


#Code for what to do after receiving a invalid update should go here
def handle_invalid_update(invalid_update_dict):
    print("Invalid update received")
    print(invalid_update_dict)

#Checks if an AS is using the IANA smart contracts
#It is used to determine if we consider update messages completely or partially validated
def check_ASMembership(AS):
    member=IANA.functions.ASNList(int(AS)).call()
    if member == '0x0000000000000000000000000000000000000000':
        return False
    else:
        return True

#Checks AS anounced prefixes in the IANA smart contract
def check_as_prefix(_prefix, _length, _AS):
    print("Checking prefix ...")
    prefix = netaddr.IPAddress(_prefix)
    length =_length
    AS = _AS
    ownPrefix=IANA.functions.IANA_prefixCheck(int(prefix), int(length), int(AS)).call()
    return ownPrefix

#Checks AS anounced paths in the IANA smart contract
def check_path(path_array):
    validPath = True
    print('Cheking path array: ' + str(path_array))
    index = 0
    while(index < len(path_array) - 1):
        hasLink = IANA.functions.link_validateLink(int(path_array[index]), int(path_array[index + 1])).call()
        validPath = validPath and hasLink
        index += 1
    return validPath

#Creates a dict with structured data from BGP messages
def create_pkt_dict(pkt):
    fname='file.pcap'
    wrpcap(fname, pkt, append=False)
    cap = pyshark.FileCapture(fname, decode_as={'tcp.port==179':'bgp'})
    bgp_pkt_dict = {}
    bgp_pkt_dict['pkt'] = 0
    for cur_pkt in cap:
            for layer in cur_pkt.layers:
                if layer.layer_name == "bgp":
                    #save_packet
                    if bgp_pkt_dict['pkt'] == 0:
                        bgp_pkt_dict['pkt'] = cur_pkt
                        bgp_pkt_dict['bgp_layers']=[]
                        bgp_pkt_dict['bgp_layers'].append(layer)
                    else:
                        bgp_pkt_dict['bgp_layers'].append(layer)
            cap.close()
            if bgp_pkt_dict['pkt'] == 0:
                return 0
            else:
                return bgp_pkt_dict

#This thread is awaken whenever a packet arrives at the BGP port of the host captured
#by NF_QUEUE
#We are only saving and processing BGP UPDATE messages
def process_bgp_pkt():
    while True:
        process_packet_event.wait()
        pkt_dict=bgp_pkt_q.get()
        bgp_layers=pkt_dict['bgp_layers']
        bgp_update = False
        bgp_update_list=[] #save all bgp update info from an update msg
        bgp_layer_dict={} #save all info from each update
        bgp_update_messages={} #save info in a dict with peer as key
        pkt=pkt_dict['pkt']
        for bgp_layer in bgp_layers:
            bgp_layer_dict={} #save all info from each update

            if bgp_layer.get('type') == '2': #only save updates
                bgp_update = True

                for field in bgp_layer.field_names:
                    bgp_layer_dict[field] = bgp_layer.get(field)

                bgp_update_list.append(bgp_layer_dict)

        if bgp_update == True:
            bgp_update_messages[pkt.ip.addr] = bgp_update_list
            validate_update_message(bgp_update_messages)

#Invokes the functions to validate the BGP UPDATE messages
#It also applies some logic to determine if a the update was valid or invalid
#and also if it was possible to do a complete validation (All ASs were members of IANA contrac)
#or a partial validation (not All ASs was members of IANA contract)
def validate_update_message(bgp_update_messages):
    is_as_prefix_valid = False
    is_path_array_valid = False
    peer = list(bgp_update_messages.keys())[0]
    print('Received update message from peer ' + peer)
    for bgp_update_msg in bgp_update_messages[peer]:
        try:
            path_array = bgp_update_msg['update_path_attribute_as_path_segment'].split(':')[1:][0].split(' ')[1:]
            AS = path_array[len(path_array) - 1]
            member=check_ASMembership(AS)
            if member == False:
                print("This update message was partialy verified")
                verified = False
            else:
                print("This update message was verified at IANA contract")
                verified = True
            #will it always be the same of peer address?
            next_hop = bgp_update_msg['update_path_attribute_next_hop']
            prefix = bgp_update_msg['nlri_prefix']
            length = bgp_update_msg['prefix_length']
            is_as_prefix_valid=check_as_prefix(prefix, length, AS)
            valid = is_as_prefix_valid
            if (len(path_array) > 1):
                is_path_array_valid=check_path(path_array)
                valid = (is_as_prefix_valid and is_path_array_valid)
            if (valid == False):
                invalid_update = {}
                invalid_update['peer'] = peer
                invalid_update['AS'] = AS
                invalid_update['next_hop'] = next_hop
                invalid_update['prefix'] = prefix
                invalid_update['length'] = length
                handle_invalid_update(invalid_update)
            else:
                print("Received valid update")
        except:
            pass
            #print('Attribute not found in dict')
    #change it to return invalid update
    #return valid

#Gets the packet and sends it to bgpd. Also wakes the thread to process the packet
def get_packet(pkt):
    #don't wait to forward the pkt
    pkt.accept()
    spkt=IP(pkt.get_payload())
    pkt_dict=create_pkt_dict(spkt)
    if pkt_dict != 0:
        bgp_pkt_q.put(pkt_dict)
        process_packet_event.set()
        process_packet_event.clear()

#Ethereum stuff
infura_provider = HTTPProvider('https://ropsten.infura.io')
web3=Web3(infura_provider)
#IANA contract with prefix/AS ownership and valid AS links
IANA_addr = Web3.toChecksumAddress('0x9555dbc92b1b2479f82268a5388cd1323eddd1e5')
IANA_abi='[{"constant":false,"inputs":[{"name":"myASN","type":"uint32"},{"name":"destinationASN","type":"uint32"}],"name":"link_addLink","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"startingPrefixIndex","type":"uint256"},{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"}],"name":"prefix_getContainingPrefixAndParent","outputs":[{"name":"","type":"uint256"},{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"ASN","type":"uint32"},{"name":"ASNOwner","type":"address"}],"name":"IANA_getSignatureMessage","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":false,"inputs":[{"name":"owner","type":"address"}],"name":"IANA_addOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"},{"name":"newOwnerAS","type":"uint32"},{"name":"sigV","type":"uint8"},{"name":"sigR","type":"bytes32"},{"name":"sigS","type":"bytes32"}],"name":"prefix_addPrefix","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"}],"name":"prefix_removePrefix","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"ASN","type":"uint32"},{"name":"ASNOwner","type":"address"},{"name":"sigV","type":"uint8"},{"name":"sigR","type":"bytes32"},{"name":"sigS","type":"bytes32"}],"name":"IANA_removeASN","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"},{"name":"asNumber","type":"uint256"}],"name":"IANA_prefixCheck","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"ASN","type":"uint32"}],"name":"IANA_getASNOwner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"ownerList","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"prefixes","outputs":[{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"},{"name":"owningAS","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint32"}],"name":"ASNList","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"myASN","type":"uint32"},{"name":"destinationASN","type":"uint32"}],"name":"link_removeLink","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"AS1","type":"uint32"},{"name":"AS2","type":"uint32"}],"name":"link_validateLink","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"owner","type":"address"}],"name":"IANA_removeOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"A","type":"uint8"},{"name":"B","type":"uint8"},{"name":"C","type":"uint8"},{"name":"D","type":"uint8"},{"name":"M","type":"uint8"},{"name":"_asNumber","type":"uint256"}],"name":"prefixCheck","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"ASN","type":"uint32"},{"name":"ASNOwner","type":"address"},{"name":"sigV","type":"uint8"},{"name":"sigR","type":"bytes32"},{"name":"sigS","type":"bytes32"}],"name":"IANA_addASN","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"},{"name":"ASN","type":"uint32"},{"name":"ASNOwner","type":"address"}],"name":"IANA_getPrefixSignatureMessage","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":true,"inputs":[{"name":"ip1","type":"uint32"},{"name":"mask1","type":"uint8"},{"name":"ip2","type":"uint32"},{"name":"mask2","type":"uint8"}],"name":"prefix_comparePrefix","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":true,"inputs":[{"name":"startingPrefixIndex","type":"uint256"},{"name":"ip","type":"uint32"},{"name":"mask","type":"uint8"}],"name":"prefix_getContainingPrefix","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]'
#CheckASPrefix_abi='[{"constant":false,"inputs":[{"name":"_prefix","type":"uint8[5][10]"},{"name":"_asNumber","type":"uint256"}],"name":"prefixAdd","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"A","type":"uint8"},{"name":"_asNumber","type":"uint256"}],"name":"prefixCheck","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"check","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"},{"name":"","type":"uint256"}],"name":"prefix","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]'
#CheckASPrefix=web3.eth.contract(address=CheckASPrefix_addr, abi=CheckASPrefix_abi)
IANA = web3.eth.contract(address=IANA_addr, abi=IANA_abi)
#IDS stuff
#pkt_q = queue.Queue()
bgp_pkt_q = queue.Queue()
process_packet_event = threading.Event()
process_bgp_pkt_t = threading.Thread(target=process_bgp_pkt)
process_bgp_pkt_t.start()
os.system('iptables -I INPUT -p tcp --dport 179 -j NFQUEUE --queue-num 1')
nfqueue = NetfilterQueue()
nfqueue.bind(1, get_packet)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    print('BGP IDS Started ...')
    nfqueue.run_socket(s)
except KeyboardInterrupt:
   print('Removing iptables rules ...')
   os.system('iptables -F INPUT')
