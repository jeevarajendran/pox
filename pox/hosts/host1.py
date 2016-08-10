#!/usr/bin/python

import thread
import time
import socket, sys
from struct import *

# Define a function for the thread
def interest_thread( interface):
  #print "Started interest thread"
  src = "\xFE\xED\xFA\xCE\xBE\xEF"
  dst = "\xFE\xED\xFA\xCE\xBE\xEF"
  eth_type = "\x7A\x05"
  print("Hi User .. You can send an Interest at any time. Just Enter the interest in ther terminal")
  while True:
    input_data = raw_input("")
    payload = "Interest:"+input_data+",To:S1"
    s.send(src + dst + eth_type + payload)


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
  return b


def data_thread( interface):

  #print "Started data thread"
  while True:
    packet = s.recvfrom(65565)

    original_packet = packet
    # packet string from tuple
    packet = packet[0]
    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    data = packet[eth_length:]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
    #    packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
      # print(" IP Packet :", eth_protocol)
      '''
      Do Nothing
      '''
      # some other IP packet like IGMP

    else:
      # ICN Packet
      if eth_protocol == 1402:
        if original_packet[1][1] == 3:
          #print ('****** Protocol other than TCP/UDP/ICMP ***** : ', eth_protocol)
          #print ('Received packet : ', packet)
          #print ('Length of packet : ', len(packet))
          #print ('Eth_header : ', eth_header)
          #print ('eth : ', eth)
          #print ('Data : ', data)
          #print ('Original packet : ', original_packet)
          if "Data:" not in data:
              if "Interest:" in data:
                  data_split = data.split(",")
                  interest_part = data_split[0]
                  seen_part = data_split[1]
                  if seen_part == "To:H1" :
                    print("\n")
                    print("Received Interest :", interest_part)
                    src = "\xFE\xED\xFA\xCE\xBE\xEF"
                    dst = "\xFE\xED\xFA\xCE\xBE\xEF"
                    eth_type = "\x7A\x05"
                    payload = interest_part + ",Data: Hi This is Host 1  I got your request How are you?,To:S1"
                    s.send(src + dst + eth_type + payload)
                    print("------ Sent Data back to the face -----")
                    print("\n")
                  else:
                    # Host : I sent this INTEREST packet or i dont know about it: Doing Nothing"
                    ''' Do nothing '''
          else:
              data_split = data.split(",")
              interest_part = data_split[0]
              data_part = data_split[1]
              seen_part = data_split[2]
              if seen_part == "To:H1":
                print("\n")
                print(data_part)
                print("\n")
              else:
                # Host : I sent this DATA packet : Doing Nothing"
                ''' Do nothing '''
      '''
      else:
        print ('****** Protocol other than TCP/UDP/ICMP ***** : ', eth_protocol)
        print ('Received packet : ', packet)
        print ('Length of packet : ', len(packet))
        print ('Eth_header : ', eth_header)
        print ('eth : ', eth)
        print ('Data : ', data)
        print ('Original packet : ', original_packet)
      '''

# Create two threads as follows
try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
  s.bind(("eth0",0))
  thread.start_new_thread( interest_thread, (s, ) )
  thread.start_new_thread( data_thread, (s, ) )

  src = "\xFE\xED\xFA\xCE\xBE\xEF"
  dst = "\xFE\xED\xFA\xCE\xBE\xEF"
  eth_type = "\x7A\x05"
  print("Content Announcement")
  #input_data = raw_input("")
  payload = "Content:/test/host1,To:S1"
  s.send(src + dst + eth_type + payload)
except:
  print "Error: unable to start thread"

while 1:
  pass