# Copyright 2012 James McCauley
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

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.namelibopenflow_01 as of
from pox.lib.packet import *

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    log.debug("OF_TUTORIAL : Tutorial is initialized with connection")
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.name_table = {'/test/contentstorematch':4,'/test/pitmatch':3,'/test/fibmatch':2,
                       '/test/nomatch':1}

    self.content_dict = {'/test/data1':"Sample_data_1",'/test/data2':"Sample_data_2",'/test/data3':"Sample_data_3",
                         '/test/data4': "Sample_data_4",'/test/controllerhasdata':"Data_for_controller_has_data"}

    self.init_content_store()

  def init_content_store(self):
    print("\n\n\n")
    print(" %%%%%%%%%%%%%% initContentStore Function")
    for k,v in self.content_dict.iteritems():
      print(" %%%%%%%%%%%%%%%% Inside loop")
      #match=of.ofp_match(interest_name=k)
      msg=of.ofp_add_cs_entry()

      msg.interest_name=k+"$"
      msg.data=v
      #msg.data_length=len(v)
      #msg.idle_timeout = 66
      #msg.hard_timeout = 66
      print("\n\n")
      print(" %%%%%%%%%%%%%% Gonna send content add message : msg", msg.show())
      print("\n\n")
      self.connection.send(msg)

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    log.debug("OF_TUTORIAL : Message being sent on the connection : %s " % msg)
    # Send message to switch
    self.connection.send(msg)
    log.debug("OF_TUTORIAL : Message sent to the switch")
    log.debug("OF_TUTORIAL : --------------------------")

  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    log.debug("OF_TUTORIAL : In Act like Hub Function , Resending the packet")
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """
    # DELETE THIS LINE TO START WORKING ON THIS #
    log.debug("OF_TUTORIAL : ACT LIKE SWITCH function")

    #Jeeva : event.data or packet.raw will give the data payload
    interest = packet.raw
    interest_name = interest.split(":")[1]
    print("OF_TUTORIAL : Interest name : ", interest_name)
    print("OF_TUTORIAL : Name Dictionary :", self.name_table)

    #Check in controller cache first
    if interest_name in self.content_dict:
      print("Controller has the data for the requested interest")
      msg=of.ofp_data_from_controller_cache()
      msg.interest_name = interest_name+"$"
      msg.data = self.content_dict[interest_name]
      self.connection.send(msg)
    else: #Check in Name Table
      port = self.name_table[interest_name]
      print("OF_TUTORIAL : Port to send :", port)

      #Jeeva : push a flow mod message


      print("OF_TUTORIAL : Sending Flow Mod message")
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 77
      msg.hard_timeout = 77
      msg.actions.append(of.ofp_action_output(port=port))
      #msg.data = event.ofp
      self.connection.send(msg)
      print("OF_TUTORIAL : Sent Flow Mod message")


      print("OF_TUTORIAL : Gonna resend the packet in the corressponding port through switch")
      self.resend_packet(packet, port) #Jeeva : Change from packet to packet_in later

  def _handle_CsFull (self, event):
    """
    Handles packet in messages from the switch.
    """
    print(" ********* Handling CSFull Event ********************")
    msg= of.ofp_clear_cs()
    self.connection.send(msg)
    print(" ********* Sent Content Store Clear message ***************")

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    log.debug("OF_TUTORIAL : Got a PacketIn Event from : %s" % event.source)
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print("OF_TUTORIAL : Packet In Message : " , event.data)
    print("OF_TUTORIAL : Packet In Message : ", packet.msg)
    print("OF_TUTORIAL : Packet In Message : ", packet.payload)
    print("OF_TUTORIAL : Packet In Message : ", packet.raw)
    print("OF_TUTORIAL : Packet In Message : ", packet.src)
    print("OF_TUTORIAL : Packet In Message : ", packet.dst)
    print("OF_TUTORIAL : Packet In Message : ", packet.type)

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    log.debug("OF_TUTORIAL : Calling act like Switch function")
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  log.debug("OF_TUTORIAL : Launch Test")
  def start_switch (event):
    log.debug("OF_TUTORIAL : Controlling %s" % (event.connection,))
    log.debug("OF_TUTORIAL : event details : %s" % (event.source))
    Tutorial(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
