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
import pox.openflow.libopenflow_01 as of

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
    self.name_table = {'demotest1':8888,'demotest2':9999,'icndemotest':2, 'newnewnew':3}


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

    """ # DELETE THIS LINE TO START WORKING ON THIS (AND THE ONE BELOW!) #

    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    self.mac_to_port ... <add or update entry>

    if the port associated with the destination MAC of the packet is known:
      # Send packet out the associated port
      self.resend_packet(packet_in, ...)

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      #msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      #msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)

    """
    # DELETE THIS LINE TO START WORKING ON THIS #
    log.debug("OF_TUTORIAL : ACT LIKE SWITCH function")
    #Jeeva : event.data or packet.raw will give the data payload
    interest = packet.raw
    name = interest.split(":")[1]
    print("Interest name : ", name)
    # self.name_table[name]='7777'
    print("Name Dictionary :", self.name_table)
    port = self.name_table[name]
    print("Port to send :", port)
    self.resend_packet(packet_in, port)

    '''
    self.mac_to_port[packet.src] = packet_in.in_port
    if packet.dst in self.mac_to_port:
      print("Packet sent to Control Plane")
      # Send the packet to the destination
      self.resend_packet(packet_in,self.mac_to_port[packet.dst])
      # Install a flow
      msg = of.ofp_flow_mod()
      msg.match.dl_dst = packet.dst
      msg.actions.append(of.ofp_action_output(port=self.mac_to_port[packet.dst]))
      self.connection.send(msg)
      print("Sent message to Switch")
    else:
      print("Send to ALL ports")
      self.resend_packet(packet_in, of.OFPP_ALL)
    '''

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
  log.debug("OF_TUTORIAL : Launch Test 2")
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    log.debug("OF_TUTORIAL : event details : %s" % (event.source))
    Tutorial(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
