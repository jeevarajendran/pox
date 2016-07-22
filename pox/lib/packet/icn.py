# Copyright 2011 James McCauley
# Copyright 2008 (C) Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.

#======================================================================
#
#                          ICN Header Format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                             Name                              |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#======================================================================

import struct
import time
from packet_utils import *
from tcp import *
from udp import *
from icmp import *
from igmp import *

from packet_base import packet_base

from pox.lib.addresses import IPAddr, IP_ANY, IP_BROADCAST

class icn(packet_base):
    "ICN packet struct"

    MIN_LEN = 20

    IPv4 = 4
    ICMP_PROTOCOL = 1
    TCP_PROTOCOL  = 6
    UDP_PROTOCOL  = 17
    IGMP_PROTOCOL = 2

    DF_FLAG = 0x02
    MF_FLAG = 0x01

    ip_id = int(time.time())

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev
        self.name = "test"

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "String form of the packet"

        return s

    def parse(self, raw):
        print "please parse the packet"

    def checksum(self):
        data = struct.pack('!B', self.name )
        return checksum(data, 0)


    def hdr(self, payload):
        #self.iplen = self.hl * 4 + len(payload)
        #self.csum = self.checksum()
        return struct.pack('!B', self.name )
