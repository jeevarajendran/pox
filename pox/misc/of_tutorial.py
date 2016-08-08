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

  name_table =  {'/test/contentstorematch':'4','/test/pitmatch':'3','/test/fibmatch':'2',
                       '/test/nomatch':'1'}

  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    log.debug(" OF_TUTORIAL : Tutorial is initialized with connection")
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.connected_switches = {291:"S1",1110:"S2"}
    self.switch_config = {291:{"H1":1,"S2":2},1110:{"S1":1,"H2":2}} #291 is dpid for S1, 1110 dpid for S2
    '''
    self.name_table = {'/test/contentstorematch':'4','/test/pitmatch':'3','/test/fibmatch':'2',
                       '/test/nomatch':'1'} #Jeeva : change 3 back to 999 for the hostmatch test to work
    '''

    self.content_dict = {'/test/data1':"Sample_data_1",'/test/data2':"Sample_data_2",'/test/data3':"Sample_data_3",
                         '/test/data4': "Sample_data_4",'/test/controllerhasdata':"Data_for_controller_has_data"}

    self.init_content_store()

  def init_content_store(self):
    #print("\n\n\n")
    #print(" OF_TUTORIAL : initContentStore Function")
    for k,v in self.content_dict.iteritems():
      #print(" %%%%%%%%%%%%%%%% Inside loop")
      #match=of.ofp_match(interest_name=k)
      msg=of.ofp_add_cs_entry()

      msg.interest_name=k+"$"
      msg.data=v
      #msg.data_length=len(v)
      #msg.idle_timeout = 66
      #msg.hard_timeout = 66
      #print("\n\n")
      #print(" %%%%%%%%%%%%%% Gonna send content add message : msg", msg.show())
      #print("\n\n")
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

    log.debug(" OF_TUTORIAL : Message being sent on the connection : %s " % msg)
    # Send message to switch
    self.connection.send(msg)
    log.debug(" OF_TUTORIAL : Message sent to the switch")
    log.debug(" OF_TUTORIAL : --------------------------")


  def resend_packet_face(self, packet_in, face):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_outputface(face=face)
    msg.actions.append(action)

    log.debug(" OF_TUTORIAL : Message being sent on the connection : %s " % msg)
    # Send message to switch
    self.connection.send(msg)
    log.debug(" OF_TUTORIAL : Message sent to the switch")
    log.debug(" OF_TUTORIAL : --------------------------")

  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    log.debug(" OF_TUTORIAL : In Act like Hub Function , Resending the packet")
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in,dpid):
    """
    Implement switch-like behavior.
    """
    # DELETE THIS LINE TO START WORKING ON THIS #
    log.debug(" OF_TUTORIAL : ACT LIKE SWITCH function")

    #Jeeva : event.data or packet.raw will give the data payload
    interest = packet.raw
    interest_name = interest.split(":")[1]
    #print("OF_TUTORIAL : Interest name : ", interest_name)
    #print("OF_TUTORIAL : Name Dictionary :", self.name_table)

    #Check in controller cache first
    if interest_name in self.content_dict:
      #print(" Controller has the data for the requested interest")
      msg=of.ofp_data_from_controller_cache()
      msg.interest_name = interest_name+"$"
      msg.data = self.content_dict[interest_name]
      self.connection.send(msg)
      #print(" Controller sent the data to Switch")
    else: #Check in Name Table
      #print(" Interest Name :", interest_name)
      if interest_name in self.name_table:
        dev = self.name_table[interest_name]
        #print("OF_TUTORIAL : Port to send :", port)

        face = None
        dev_list = self.switch_config[dpid]
        if dev in dev_list :
          face = dev_list[dev]

        #print ("Face for the switch to send out the information :", face)

        #Jeeva : push a flow mod message


        #print(" OF_TUTORIAL : Sending FIB Mod message")
        #msg = of.ofp_flow_mod()
        #print msg
        #msg.match = of.ofp_match.from_packet(packet)
        #print msg
        #msg.idle_timeout = 0
        #msg.hard_timeout = 0
        #msg.actions.append(of.ofp_action_outputface(face=face))
        #print msg
        #msg.data = event.ofp
        msg = of.ofp_fib_mod()
        msg.interest_name=interest_name
        msg.face=face
        self.connection.send(msg)
        #print("OF_TUTORIAL : Sent Fib mod message")

        #print(" OF_TUTORIAL : Gonna resend the packet in the corressponding port through switch")
        self.resend_packet_face(packet, face)  # Jeeva : Change from packet to packet_in later
      else:
        #print (" OF_TUTORIAL : This interest is not in the controller database :", interest_name)
        print (" Ask the switch to drop the packet")

    #if interest_name == "/test/hostfetch":


  def _handle_ContentAnnouncement(self, event):
    """
        Handles content announcement messages from the switch.
        """
    #print(" ********* Handling Content Announcement messages  *******************")
    packet = event.parsed.raw
    content_interest_name = (packet.split("Content:"))[1]
    #print content_interest_name
    self.name_table[content_interest_name] = self.connected_switches[event.dpid]
    #print(" ********* Added Content Announcement *******************")
    #print self.name_table
    #msg = of.ofp_clear_cs()
    #self.connection.send(msg)
    #print(" ********* Sent Content Store Clear message ***************")

  def _handle_CsFull (self, event):
    """
    Handles packet in messages from the switch.
    """
    #print(" ********* Handling CSFull Event  *******************")
    msg= of.ofp_clear_cs()
    self.connection.send(msg)
    #print(" ********* Sent Content Store Clear message ***************")

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    log.debug(" OF_TUTORIAL : Got a PacketIn Event from : %s" % event.source)
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    #print("OF_TUTORIAL : Packet In Message : " , event.data)
    #print("OF_TUTORIAL : Packet In Message : ", packet.msg)
    #print("OF_TUTORIAL : Packet In Message : ", packet.payload)
    #print("OF_TUTORIAL : Packet In Message : ", packet.raw)
    #print("OF_TUTORIAL : Packet In Message : ", packet.src)
    #print("OF_TUTORIAL : Packet In Message : ", packet.dst)
    #print("OF_TUTORIAL : Packet In Message : ", packet.type)

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    log.debug(" OF_TUTORIAL : Calling act like Switch function")
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in,event.dpid)

def launch ():
  """
  Starts the component
  """
  log.debug(" OF_TUTORIAL : Launch Test")
  def start_switch (event):
    log.debug(" OF_TUTORIAL : Controlling %s" % (event.connection,))
    #log.debug("OF_TUTORIAL : event details : %s" % (event.source))
    Tutorial(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
