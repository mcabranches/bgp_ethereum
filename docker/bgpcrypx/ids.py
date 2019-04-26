from netfilterqueue import NetfilterQueue
import socket
from scapy.all import *
import os
import time
import pyshark
import threading
import queue
import netaddr
from web3 import Web3, HTTPProvider
from eth_account import Account

#Author Marcelo de Abranches (made0661@colorado.edu)


#Policy agent - currently it configures a higher local preference for routes that were completely validated
def policy_agent(valid_update_dict):
    print('Installing local preference for checked path')
    myPeer = valid_update_dict['peer']
    prefix = valid_update_dict['prefix']
    length = valid_update_dict['length']
    #command_accept_all= 'vtysh -c "config terminal" -c "access-list 1 permit 0.0.0.0 255.255.255.255" -c "router bgp 1" -c "neighbor 9.0.0.2 route-map PERMIT-ALL in" -c "route-map PERMIT-ALL permit 10" -c "match ip address 1" -c "exit" -c "exit" -c "clear ip bgp 9.0.0.2 soft"'
    #command_accept_all= 'vtysh -c "config terminal" -c "access-list 1 permit 0.0.0.0 255.255.255.255" -c "router bgp 1" -c "neighbor 9.0.0.2 route-map LOCAL-PREF-CHECKED-150 out" -c "route-map LOCAL-PREF-CHECKED-150 permit 20" -c "match ip address 1" -c "exit" -c "exit" -c "clear ip bgp 9.0.0.2 soft"'
    #command_accept_all= 'vtysh -c "clear ip bgp 9.0.0.2 soft"'
    #print(generate_local_pref_command(myAS, myPeer, prefix, length))
    apply_policy1, apply_policy2, reload_bgp = generate_local_pref_command(myAS, myPeer, prefix, length)
    print(apply_policy1)
    print(apply_policy2)
    print(reload_bgp)
    os.system(apply_policy1)
    os.system(apply_policy2)
    os.system(reload_bgp)
    return 0

#Generates the local pref command to be sent to Quagga
def generate_local_pref_command(myAS, myPeer, prefix, length):
    #probably we will also need to cotrol the sequence number of the policies
    prefix_list_name = myPeer.replace('.','-')
    local_pref_name = 'LP-' + prefix_list_name + '-CKD-150'
    ip_list_seq = random.randint(1,100)
    print("111")
    #apply_policy1 ='vtysh -c "config terminal" -c "ip prefix-list ' + prefix_list_name + ' seq 5 permit ' + prefix + '/' + length + '" -c "router bgp ' + myAS + '" -c "neighbor ' + myPeer + ' route-map ' + local_pref_name + ' in" -c "route-map ' + local_pref_name + ' permit 10" -c "match ip address prefix-list ' + prefix_list_name + '" -c "set local-preference 150" -c "exit" -c "exit" -c "clear ip bgp ' + myPeer + ' soft"'
    apply_policy1 ='vtysh -c "config terminal" -c "ip prefix-list ' + prefix_list_name + ' seq ' + str(ip_list_seq) + ' permit ' + prefix + '/' + length + '" -c "router bgp ' + myAS + '" -c "neighbor ' + myPeer + ' route-map ' + local_pref_name + ' in" -c "route-map ' + local_pref_name + ' permit 10" -c "match ip address prefix-list ' + prefix_list_name + '" -c "set local-preference 150"'
    print('222')
    #policy 2 is needed to avoid updates being rejected if they do not match conditions at the route-map
    #apply_policy2 = 'vtysh -c "config terminal" -c "access-list 1 permit 0.0.0.0 255.255.255.255" -c "router bgp' + myAS + '" -c "neighbor ' + myPeer + ' route-map ' + local_pref_name + 'in" -c "route-map ' + local_pref_name + 'permit 20" -c "match ip address 1" -c "exit" -c "exit" -c "clear ip bgp ' + myPeer + 'soft"'
    apply_policy2 = 'vtysh -c "config terminal" -c "access-list 1 permit 0.0.0.0 255.255.255.255" -c "router bgp ' + myAS + '" -c "neighbor ' + myPeer + ' route-map ' + local_pref_name + ' out" -c "route-map ' + local_pref_name + ' permit 20" -c "match ip address 1"'
    reload_bgp = 'vtysh -c "clear ip bgp ' + myPeer + ' soft"'
    ip_list_seq += 1
    print(ip_list_seq)
    return apply_policy1, apply_policy2, reload_bgp



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
    ownPrefix = IANA.functions.IANA_prefixCheck(int(prefix), int(length), int(AS)).call()
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
            update_dict = {}
            update_dict['peer'] = peer
            update_dict['AS'] = AS
            update_dict['next_hop'] = next_hop
            update_dict['prefix'] = prefix
            update_dict['length'] = length
            if (len(path_array) > 1):
                is_path_array_valid=check_path(path_array)
                valid = (is_as_prefix_valid and is_path_array_valid)
            if (valid == False):
                handle_invalid_update(update_dict)
            else:
                cur_hash = hash(update_dict['peer'] + update_dict['AS'] + update_dict['prefix'] + update_dict['length'])
                #This will avoid unnecessary policy_agent calls
                if cur_hash not in policy_hash_list:
                    print("Received valid update, calling policy agent")
                    policy_hash_list.append(cur_hash)
                    policy_agent(update_dict)
                else:
                    print("Policy exists for this update message. Will not call policy agent")
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

#Policy agent configs (put as env variable)
myAS='1'
policy_hash_list=[] #This is used to know if a policy has already been applied
ip_list_seq = 1
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
