# Copyright 2011,2012,2013 Colin Scott
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
Implementation of an OpenFlow name table
"""
#Jeeva : namelinopenflow_01 is used instead of libopenflow_01
#Jeeva : ofp_match class and its functions are modified in namelibopenflow_01 and which are used in this file
from namelibopenflow_01 import *
from pox.lib.revent import *

import time
import math


#1. FIB

# FibTable Entries:
#   match - ofp_match (1-tuple)
#   counters - hash from name -> count. May be stale
#   actions - ordered list of ofp_action_*s to apply for matching packets
class FibTableEntry (object):
  """
  Models a flow table entry, with a match, actions, and options/flags/counters.

  Note: The current time can either be specified explicitely with the optional
        'now' parameter or is taken from time.time()
  """

  def __init__ (self, priority=OFP_DEFAULT_PRIORITY, cookie=0, idle_timeout=0,
                hard_timeout=0, flags=0, match=ofp_match(), actions=[],
                buffer_id=None, now=None):
    """
    Initialize name table entry
    """
    if now is None: now = time.time()
    self.created = now
    self.last_touched = self.created
    self.byte_count = 0
    self.packet_count = 0
    self.priority = priority
    self.cookie = cookie
    self.idle_timeout = idle_timeout
    self.hard_timeout = hard_timeout
    self.flags = flags
    self.match = match
    self.actions = actions
    self.buffer_id = buffer_id
    #self.faces = {1:2,2:3,3:4}

  @staticmethod
  def from_flow_mod (flow_mod):
    return FibTableEntry(priority=flow_mod.priority,
                      cookie=flow_mod.cookie,
                      idle_timeout=flow_mod.idle_timeout,
                      hard_timeout=flow_mod.hard_timeout,
                      flags=flow_mod.flags,
                      match=flow_mod.match,
                      actions=flow_mod.actions,
                      buffer_id=flow_mod.buffer_id)

  def to_flow_mod (self, flags=None, **kw):
    if flags is None: flags = self.flags
    return ofp_flow_mod(priority=self.priority,
                        cookie=self.cookie,
                        match=self.match,
                        idle_timeout=self.idle_timeout,
                        hard_timeout=self.hard_timeout,
                        actions=self.actions,
                        buffer_id=self.buffer_id,
                        flags=flags, **kw)

  @property
  def effective_priority (self):
    """
    Exact matches effectively have an "infinite" priority
    """
    return self.priority if self.match.is_wildcarded else (1<<16) + 1

  def is_matched_by (self, match, priority=None, strict=False, out_port=None):
    """
    Tests whether a given match object matches this entry

    Used for, e.g., flow_mod updates

    If out_port is any value besides None, the the flow entry must contain an
    output action to the specified port.
    """
    match_a = lambda a: isinstance(a, ofp_action_output) and a.port == out_port
    port_matches = (out_port is None) or any(match_a(a) for a in self.actions)

    if strict:
      return port_matches and self.match == match and self.priority == priority
    else:
      return port_matches and match.matches_with_wildcards(self.match)

  def touch_packet (self, byte_count, now=None):
    """
    Updates information of this entry based on encountering a packet.

    Updates both the cumulative given byte counts of packets encountered and
    the expiration timer.
    """
    if now is None: now = time.time()
    self.byte_count += byte_count
    self.packet_count += 1
    self.last_touched = now

  def is_idle_timed_out (self, now=None):
    if now is None: now = time.time()
    if self.idle_timeout > 0:
      if (now - self.last_touched) > self.idle_timeout:
        return True
    return False

  def is_hard_timed_out (self, now=None):
    if now is None: now = time.time()
    if self.hard_timeout > 0:
      if (now - self.created) > self.hard_timeout:
        return True
    return False

  def is_expired (self, now=None):
    """
    Tests whether this flow entry is expired due to its idle or hard timeout
    """
    if now is None: now = time.time()
    return self.is_idle_timed_out(now) or self.is_hard_timed_out(now)

  def __str__ (self):
    return type(self).__name__ + "\n  " + self.show()

  def __repr__ (self):
    return "FibTableEntry(" + self.show() + ")"

  def show (self):
    outstr = ''
    outstr += "priority=%s, " % self.priority
    outstr += "cookie=%x, " % self.cookie
    outstr += "idle_timeout=%d, " % self.idle_timeout
    outstr += "hard_timeout=%d, " % self.hard_timeout
    outstr += "match=%s, " % self.match
    outstr += "actions=%s, " % repr(self.actions)
    outstr += "buffer_id=%s" % str(self.buffer_id)
    return outstr

  def flow_stats (self, now=None):
    if now is None: now = time.time()
    dur_nsec,dur_sec = math.modf(now - self.created)
    return ofp_flow_stats(match=self.match,
                          duration_sec=int(dur_sec),
                          duration_nsec=int(dur_nsec * 1e9),
                          priority=self.priority,
                          idle_timeout=self.idle_timeout,
                          hard_timeout=self.hard_timeout,
                          cookie=self.cookie,
                          packet_count=self.packet_count,
                          byte_count=self.byte_count,
                          actions=self.actions)

  def to_flow_removed (self, now=None, reason=None):
    #TODO: Rename flow_stats to to_flow_stats and refactor?
    if now is None: now = time.time()
    dur_nsec,dur_sec = math.modf(now - self.created)
    fr = ofp_flow_removed()
    fr.match = self.match
    fr.cookie = self.cookie
    fr.priority = self.priority
    fr.reason = reason
    fr.duration_sec = int(dur_sec)
    fr.duration_nsec = int(dur_nsec * 1e9)
    fr.idle_timeout = self.idle_timeout
    fr.hard_timeout = self.hard_timeout
    fr.packet_count = self.packet_count
    fr.byte_count = self.byte_count
    return fr


class FibTableModification (Event):
  def __init__ (self, added=[], removed=[], reason=None):
    print(" FIB MODIFICATION : init")
    Event.__init__(self)
    self.added = added
    self.removed = removed

    # Reason for modification.
    # Presently, this is only used for removals and is either one of OFPRR_x,
    # or None if it does not correlate to any of the items in the spec.
    self.reason = reason
    print(" FIB MODIFICATION : init End")




class FibTable (EventMixin):
  """
  General model of a name table.

  Maintains an ordered list of name flow entries, and finds matching entries for
  packets and other entries. Supports expiration of name flows.
  """
  _eventMixin_events = set([FibTableModification])

  def __init__ (self):
    EventMixin.__init__(self)

    # Table is a list of TableEntry sorted by descending effective_priority.
    self._table = []
    self.initFibTable()

  def initFibTable(self):
    print(" FIB : initFibTable function")

    match = ofp_match(interest_name="/test/fibmatch")
    entry = FibTableEntry(priority=5, match=match, actions=[ofp_action_output(port=1),ofp_action_output(port=2),
                                                             ofp_action_addpit(
                                                               interest_name="/test/fibmatch",ports=[1,2])])
    print (" FIB : Created FIB entry for prefix : /test/fibmatch")
    self.add_entry(entry)

  def _dirty (self):
    """
    Call when table changes
    """
    pass

  #Jeeva : properties of the table
  @property
  def entries (self):
    return self._table

  def __len__ (self):
    return len(self._table)

  def add_entry (self, entry):
    print(" FIB : Entry to be added :", entry)
    #print(" FIB : Fib table entry :", FibTableEntry)
    assert isinstance(entry, FibTableEntry)

    #self._table.append(entry)
    #self._table.sort(key=lambda e: e.effective_priority, reverse=True)

    # Use binary search to insert at correct place
    # This is faster even for modest table sizes, and way, way faster
    # as the tables grow larger.
    print(" FIB : add_entry")
    print(" ----------------------\n\n")

    priority = entry.effective_priority
    table = self._table
    low = 0
    high = len(table)
    while low < high:
        middle = (low + high) // 2
        if priority >= table[middle].effective_priority:
          high = middle
          continue
        low = middle + 1
    print(" FIB : Table before adding the new entry :", table)
    print("\n\n")
    table.insert(low, entry)

    self._dirty()

    print(" FIB : Table after adding the new entry :", table)
    print(" ----------------------\n\n")
    print(" FIB : add_entry : Gonna raiseEvent for FibTableModification, commented for now")
    #self.raiseEvent(FibTableModification(added=[entry]))

  def remove_entry (self, entry, reason=None):
    assert isinstance(entry, FibTableEntry)
    self._table.remove(entry)
    self._dirty()
    self.raiseEvent(FibTableModification(removed=[entry], reason=reason))

  def matching_entries (self, match, priority=0, strict=False, out_port=None):
    print(" FIB : matching_entries function : Entries for the given match")
    entry_match = lambda e: e.is_matched_by(match, priority, strict, out_port)
    return [ entry for entry in self._table if entry_match(entry) ]

  def flow_stats (self, match, out_port=None, now=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    return [ e.flow_stats(now) for e in mc_es ]

  def aggregate_stats (self, match, out_port=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    packet_count = 0
    byte_count = 0
    flow_count = 0
    for entry in mc_es:
      packet_count += entry.packet_count
      byte_count += entry.byte_count
      flow_count += 1
    return ofp_aggregate_stats(packet_count=packet_count,
                               byte_count=byte_count,
                               flow_count=flow_count)

  def _remove_specific_entries (self, flows, reason=None):
    #for entry in flows:
    #  self._table.remove(entry)
    #self._table = [entry for entry in self._table if entry not in flows]
    if not flows: return
    self._dirty()
    remove_flows = set(flows)
    i = 0
    while i < len(self._table):
      entry = self._table[i]
      if entry in remove_flows:
        del self._table[i]
        remove_flows.remove(entry)
        if not remove_flows: break
      else:
        i += 1
    assert len(remove_flows) == 0
    self.raiseEvent(FibTableModification(removed=flows, reason=reason))

  def remove_expired_entries (self, now=None):
    idle = []
    hard = []
    if now is None: now = time.time()
    for entry in self._table:
      if entry.is_idle_timed_out(now):
        idle.append(entry)
      elif entry.is_hard_timed_out(now):
        hard.append(entry)
    self._remove_specific_entries(idle, OFPRR_IDLE_TIMEOUT)
    self._remove_specific_entries(hard, OFPRR_HARD_TIMEOUT)

  def remove_matching_entries (self, match, priority=0, strict=False,
                               out_port=None, reason=None):
    print(" FIB : remove_matching_entries")
    remove_flows = self.matching_entries(match, priority, strict, out_port)
    self._remove_specific_entries(remove_flows, reason=reason)
    return remove_flows

  def entry_for_packet (self, packet, in_port):
    """
    Finds the flow table entry that matches the given packet.

    Returns the highest priority flow table entry that matches the given packet
    on the given in_port, or None if no matching entry is found.

    Jeeva:

      Call ofp_match.from_packet and create a packet match for the received packet
      from the entries that are already in the name table, find out the matching entry
      using the packet match created in the previous step
    """


    """
    Jeeva :
      What a table entry contains
      Especially what the actions that can be in a table entry
      How to create a table entry
    """

    print (" FIB : entry_for_packet funtion")

    packet_match = ofp_match.from_packet(packet, in_port, spec_frags = True)
    print (" FIB : Created a match with the given packet")

    print(" \n\n FIB : Table before checking for match with the packet:", self._table )
    print("\n")

    #Jeeva
    for entry in self._table:
      print(" FIB : checking the entry  :", entry , "\n")
      if entry.match.matches_with_wildcards(packet_match,
                                            consider_other_wildcards=False):
        return entry
    #Jeeva : No entry in the table
    return None

  def check_for_overlapping_entry (self, in_entry):
    """
    Tests if the input entry overlaps with another entry in this table.

    Returns true if there is an overlap, false otherwise. Since the table is
    sorted, there is only a need to check a certain portion of it.
    """
    #NOTE: Assumes that entries are sorted by decreasing effective_priority
    #NOTE: Ambiguous whether matching should be based on effective_priority
    #      or the regular priority.  Doing it based on effective_priority
    #      since that's what actually affects packet matching.
    #NOTE: We could improve performance by doing a binary search to find the
    #      right priority entries.

    priority = in_entry.effective_priority

    for e in self._table:
      if e.effective_priority < priority:
        break
      elif e.effective_priority > priority:
        continue
      else:
        if e.is_matched_by(in_entry.match) or in_entry.is_matched_by(e.match):
          return True

    return False


#2.PIT

class PitTableEntry(object):
  """
  Models a PIT table entry, with a Prefix and Ports

  Note: The current time can either be specified explicitely with the optional
        'now' parameter or is taken from time.time()
  """

  def __init__(self, priority=OFP_DEFAULT_PRIORITY, cookie=0, idle_timeout=0,
               hard_timeout=0, flags=0, match=ofp_match(), ports=[], now=None):
    """
    Initialize name table entry
    """
    if now is None: now = time.time()
    self.created = now
    self.last_touched = self.created
    self.byte_count = 0
    self.packet_count = 0
    self.priority = priority
    self.cookie = cookie
    self.idle_timeout = idle_timeout
    self.hard_timeout = hard_timeout
    self.flags = flags
    #self.match = match
    #self.actions = actions
    self.match = match
    self.ports = ports
    #self.buffer_id = buffer_id
    # self.faces = {1:2,2:3,3:4}

  @staticmethod
  def from_flow_mod(flow_mod):
    return PitTableEntry(priority=flow_mod.priority,
                          cookie=flow_mod.cookie,
                          idle_timeout=flow_mod.idle_timeout,
                          hard_timeout=flow_mod.hard_timeout,
                          flags=flow_mod.flags,
                          match=flow_mod.match,
                          ports=flow_mod.ports
                          )

  def to_flow_mod(self, flags=None, **kw):
    if flags is None: flags = self.flags
    return ofp_flow_mod(priority=self.priority,
                        cookie=self.cookie,
                        match=self.match,
                        idle_timeout=self.idle_timeout,
                        hard_timeout=self.hard_timeout,
                        ports=self.ports,
                        #buffer_id=self.buffer_id,
                        flags=flags, **kw)

  @property
  def effective_priority(self):
    """
    Exact matches effectively have an "infinite" priority
    """
    return self.priority if self.match.is_wildcarded else (1 << 16) + 1

  def is_matched_by(self, match, priority=None, strict=False, out_port=None):
    """
    Tests whether a given match object matches this entry

    Used for, e.g., flow_mod updates

    If out_port is any value besides None, the the flow entry must contain an
    output action to the specified port.
    """
    match_a = lambda a: isinstance(a, ofp_action_output) and a.port == out_port
    port_matches = (out_port is None) or any(match_a(a) for a in self.actions)

    if strict:
      return port_matches and self.match == match and self.priority == priority
    else:
      return port_matches and match.matches_with_wildcards(self.match)

  def touch_packet(self, byte_count, now=None):
    """
    Updates information of this entry based on encountering a packet.

    Updates both the cumulative given byte counts of packets encountered and
    the expiration timer.
    """
    if now is None: now = time.time()
    self.byte_count += byte_count
    self.packet_count += 1
    self.last_touched = now

  def is_idle_timed_out(self, now=None):
    if now is None: now = time.time()
    if self.idle_timeout > 0:
      if (now - self.last_touched) > self.idle_timeout:
        return True
    return False

  def is_hard_timed_out(self, now=None):
    if now is None: now = time.time()
    if self.hard_timeout > 0:
      if (now - self.created) > self.hard_timeout:
        return True
    return False

  def is_expired(self, now=None):
    """
    Tests whether this flow entry is expired due to its idle or hard timeout
    """
    if now is None: now = time.time()
    return self.is_idle_timed_out(now) or self.is_hard_timed_out(now)

  def __str__(self):
    return type(self).__name__ + "\n  " + self.show()

  def __repr__(self):
    return "PitTableEntry(" + self.show() + ")"

  def show(self):
    outstr = ''
    outstr += "priority=%s, " % self.priority
    outstr += "cookie=%x, " % self.cookie
    outstr += "idle_timeout=%d, " % self.idle_timeout
    outstr += "hard_timeout=%d, " % self.hard_timeout
    outstr += "match=%s, " % self.match
    outstr += "ports=%s, " % repr(self.ports)
    #outstr += "buffer_id=%s" % str(self.buffer_id)
    return outstr

  def flow_stats(self, now=None):
    if now is None: now = time.time()
    dur_nsec, dur_sec = math.modf(now - self.created)
    return ofp_flow_stats(match=self.match,
                          duration_sec=int(dur_sec),
                          duration_nsec=int(dur_nsec * 1e9),
                          priority=self.priority,
                          idle_timeout=self.idle_timeout,
                          hard_timeout=self.hard_timeout,
                          cookie=self.cookie,
                          packet_count=self.packet_count,
                          byte_count=self.byte_count,
                          actions=self.actions)

  def to_flow_removed(self, now=None, reason=None):
    # TODO: Rename flow_stats to to_flow_stats and refactor?
    if now is None: now = time.time()
    dur_nsec, dur_sec = math.modf(now - self.created)
    fr = ofp_flow_removed()
    fr.match = self.match
    fr.cookie = self.cookie
    fr.priority = self.priority
    fr.reason = reason
    fr.duration_sec = int(dur_sec)
    fr.duration_nsec = int(dur_nsec * 1e9)
    fr.idle_timeout = self.idle_timeout
    fr.hard_timeout = self.hard_timeout
    fr.packet_count = self.packet_count
    fr.byte_count = self.byte_count
    return fr

class PitTableModification (Event):
  def __init__ (self, added=[], removed=[], reason=None):
    print(" PIT MODIFICATION : init")
    Event.__init__(self)
    self.added = added
    self.removed = removed

    # Reason for modification.
    # Presently, this is only used for removals and is either one of OFPRR_x,
    # or None if it does not correlate to any of the items in the spec.
    self.reason = reason
    print(" PIT MODIFICATION : init End")

class PitTable(EventMixin):

  """
  General model of a name table.

  Maintains an ordered list of name flow entries, and finds matching entries for
  packets and other entries. Supports expiration of name flows.
  """
  _eventMixin_events = set([PitTableModification])


  def __init__(self):
    EventMixin.__init__(self)

    # Table is a list of TableEntry sorted by descending effective_priority.
    self._table = []
    self.initPitTable()

  def initPitTable(self):
    print(" PIT : initPitTable")

    #Entry 1 Commented now to check for the 2nd case PIT match
    '''
    entry = PitTableEntry(prefix="newnewnew", ports=[4])
    print (
        " PIT TABLE : Created a sample entry to match with the packet(newnewnew) : using the packet match itself as a "
        "hack ports : 1")
    self.add_entry(entry)
    '''

    #Entry 2
    match = ofp_match(interest_name="/test/pitmatch")
    entry = PitTableEntry(match=match, ports=[2, 3])
    print (
        " PIT : Created an entry in PIT table for the prefix: /test/pitmatch")
    self.add_entry(entry)

  def _dirty(self):
    """
    Call when table changes
    """
    pass

  # Jeeva : properties of the table
  @property
  def entries(self):
    return self._table

  def __len__(self):
    return len(self._table)

  def add_entry(self, entry):

    print(" PIT : Pit Entry to be added :", entry)
    print(" PIT : Pit table entry :", PitTableEntry)
    assert isinstance(entry, PitTableEntry)
    print(" PIT: add_pit_entry")
    print(" ----------------------\n\n")

    table = self._table
    low = 0
    high = len(table)

    '''
    while low < high:
      middle = (low + high) // 2
      if priority >= table[middle].effective_priority:
        high = middle
        continue
      low = middle + 1
    '''
    print(" PIT : Table before adding the new pit entry :", table)
    print("\n\n")
    table.insert(low, entry)

    self._dirty()

    print(" PIT : Table after adding the new pit entry :", table)
    print(" ----------------------\n\n")
    print(" PIT : add_pit_entry : Gonna raiseEvent for PitTableModification, commented for now : So no event")
    #self.raiseEvent(FibTableModification(added=[entry]))

  def remove_entry(self, entry, reason=None):
    assert isinstance(entry, PitTableEntry)
    self._table.remove(entry)
    self._dirty()
    self.raiseEvent(PitTableModification(removed=[entry], reason=reason))

  def matching_entries(self, match, priority=0, strict=False, out_port=None):
    print(" PIT : matching_entries function : Entries for the given match")
    entry_match = lambda e: e.is_matched_by(match, priority, strict, out_port)
    return [entry for entry in self._table if entry_match(entry)]

  def flow_stats(self, match, out_port=None, now=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    return [e.flow_stats(now) for e in mc_es]

  def aggregate_stats(self, match, out_port=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    packet_count = 0
    byte_count = 0
    flow_count = 0
    for entry in mc_es:
      packet_count += entry.packet_count
      byte_count += entry.byte_count
      flow_count += 1
    return ofp_aggregate_stats(packet_count=packet_count,
                               byte_count=byte_count,
                               flow_count=flow_count)

  def _remove_specific_entries(self, flows, reason=None):
    # for entry in flows:
    #  self._table.remove(entry)
    # self._table = [entry for entry in self._table if entry not in flows]
    if not flows: return
    self._dirty()
    remove_flows = set(flows)
    i = 0
    while i < len(self._table):
      entry = self._table[i]
      if entry in remove_flows:
        del self._table[i]
        remove_flows.remove(entry)
        if not remove_flows: break
      else:
        i += 1
    assert len(remove_flows) == 0
    self.raiseEvent(PitTableModification(removed=flows, reason=reason))

  def remove_expired_entries(self, now=None):
    idle = []
    hard = []
    if now is None: now = time.time()
    for entry in self._table:
      if entry.is_idle_timed_out(now):
        idle.append(entry)
      elif entry.is_hard_timed_out(now):
        hard.append(entry)
    self._remove_specific_entries(idle, OFPRR_IDLE_TIMEOUT)
    self._remove_specific_entries(hard, OFPRR_HARD_TIMEOUT)

  def remove_matching_entries(self, match, priority=0, strict=False,
                              out_port=None, reason=None):
    print(" PIT : remove_matching_entries")
    remove_flows = self.matching_entries(match, priority, strict, out_port)
    self._remove_specific_entries(remove_flows, reason=reason)
    return remove_flows

  def pit_entry_for_packet(self, packet, in_port):
    # Jeeva : Check for PIT
    print(" PIT : In pit_entry_for_packet function")
    packet_match = ofp_match.from_packet(packet, in_port, spec_frags=True)
    interest_name = packet_match.interest_name

    for entry in self._table:
      print(" PIT : checking each entry in the PIT table :", entry, "\n")
      if entry.match.interest_name == interest_name :
        print (" PIT : Entry Found: Adding the input port to the list")
        if in_port not in entry.ports :
          entry.ports.append(in_port)
        else:
          print(" PIT : in_port is already in the ports list")
        print (" PIT : Ports list :", entry.ports)
        return True

    return False

  def fetch_faces_from_pit_entry(self,interest_name):
    #Jeeva : check PIT and retirn the ports
    print(" PIT : In fetch_faces_from_pit_entry function")
    packet_match = ofp_match(interest_name=interest_name)
    interest_name = packet_match.interest_name

    for entry in self._table:
      print(" PIT : checking each entry in the PIT table :", entry, "\n")
      if entry.match.interest_name == interest_name:
        print (" PIT : Entry Found: Returning the ports")
        return entry.ports

    return None

  #Jeeva : This function may be useful later
  def entry_for_packet(self, packet, in_port):
    """
    Finds the flow table entry that matches the given packet.

    Returns the highest priority flow table entry that matches the given packet
    on the given in_port, or None if no matching entry is found.

    Jeeva:

      Call ofp_match.from_packet and create a packet match for the received packet
      from the entries that are already in the name table, find out the matching entry
      using the packet match created in the previous step
    """

    print (" PIT : entry_for_packet funtion")

    packet_match = ofp_match.from_packet(packet, in_port, spec_frags=True)

    print (" PIT : Created a match with the given packet")

    if (packet_match.interest_name == "newnewnew"):
      entry = FibTableEntry(priority=5, match=packet_match,
                             actions=[ofp_action_output(port=3), ofp_action_output(port=4)])
      print (
      " PIT : Created a sample entry to match with the packet(newnewnew) : using the packet match itself as a hack")
      self.add_entry(entry)
    else:
      print (" PIT : Sample Entry is not created")

    print(" \n\n PIT : Entire Table before checking for match with the packet:", self._table)
    print("\n\n")
    # for entry in self._table:
    # print(" NAME TABLE, match in self.table :", entry.match)

    # Jeeva : Add these lines later
    for entry in self._table:
      print(" PIT : checking each entry  :", entry, "\n")
      if entry.match.matches_with_wildcards(packet_match,
                                            consider_other_wildcards=False):
        return entry
    # Jeeva : No entry in the table
    return None  # Jeeva : Should return an entry

  def check_for_overlapping_entry(self, in_entry):
    """
    Tests if the input entry overlaps with another entry in this table.

    Returns true if there is an overlap, false otherwise. Since the table is
    sorted, there is only a need to check a certain portion of it.
    """
    # NOTE: Assumes that entries are sorted by decreasing effective_priority
    # NOTE: Ambiguous whether matching should be based on effective_priority
    #      or the regular priority.  Doing it based on effective_priority
    #      since that's what actually affects packet matching.
    # NOTE: We could improve performance by doing a binary search to find the
    #      right priority entries.

    #Jeeva : Check is the same match is entered twice in the table

    return False


#3. Content Store


class ContentStoreEntry(object):
  """
  Models a PIT table entry, with a Prefix and Ports

  Note: The current time can either be specified explicitely with the optional
        'now' parameter or is taken from time.time()
  """

  def __init__(self, priority=OFP_DEFAULT_PRIORITY, cookie=0, idle_timeout=0,
               hard_timeout=0, flags=0, match=ofp_match(), data="", now=None):
    """
    Initialize name table entry
    """
    if now is None: now = time.time()
    self.created = now
    self.last_touched = self.created
    self.byte_count = 0
    self.packet_count = 0
    self.priority = priority
    self.cookie = cookie
    self.idle_timeout = idle_timeout
    self.hard_timeout = hard_timeout
    self.flags = flags
    self.match = match
    self.data = data

  @staticmethod
  def from_flow_mod(flow_mod):
    return ContentStoreEntry(priority=flow_mod.priority,
                          cookie=flow_mod.cookie,
                          idle_timeout=flow_mod.idle_timeout,
                          hard_timeout=flow_mod.hard_timeout,
                          flags=flow_mod.flags,
                          match=flow_mod.match,
                          data=flow_mod.data
                          )

  def to_flow_mod(self, flags=None, **kw):
    if flags is None: flags = self.flags
    return ofp_flow_mod(priority=self.priority,
                        cookie=self.cookie,
                        match=self.match,
                        idle_timeout=self.idle_timeout,
                        hard_timeout=self.hard_timeout,
                        data=self.data,
                        flags=flags, **kw)

  @property
  def effective_priority(self):
    """
    Exact matches effectively have an "infinite" priority
    """
    return self.priority if self.match.is_wildcarded else (1 << 16) + 1

  def is_matched_by(self, match, priority=None, strict=False, out_port=None):
    """
    Tests whether a given match object matches this entry

    Used for, e.g., flow_mod updates

    If out_port is any value besides None, the the flow entry must contain an
    output action to the specified port.
    """
    match_a = lambda a: isinstance(a, ofp_action_output) and a.port == out_port
    port_matches = (out_port is None) or any(match_a(a) for a in self.actions)

    if strict:
      return port_matches and self.match == match and self.priority == priority
    else:
      return port_matches and match.matches_with_wildcards(self.match)

  def touch_packet(self, byte_count, now=None):
    """
    Updates information of this entry based on encountering a packet.

    Updates both the cumulative given byte counts of packets encountered and
    the expiration timer.
    """
    if now is None: now = time.time()
    self.byte_count += byte_count
    self.packet_count += 1
    self.last_touched = now

  def is_idle_timed_out(self, now=None):
    if now is None: now = time.time()
    if self.idle_timeout > 0:
      if (now - self.last_touched) > self.idle_timeout:
        return True
    return False

  def is_hard_timed_out(self, now=None):
    if now is None: now = time.time()
    if self.hard_timeout > 0:
      if (now - self.created) > self.hard_timeout:
        return True
    return False

  def is_expired(self, now=None):
    """
    Tests whether this flow entry is expired due to its idle or hard timeout
    """
    if now is None: now = time.time()
    return self.is_idle_timed_out(now) or self.is_hard_timed_out(now)

  def __str__(self):
    return type(self).__name__ + "\n  " + self.show()

  def __repr__(self):
    return "ContentStoreEntry(" + self.show() + ")"

  def show(self):
    outstr = ''
    outstr += "priority=%s, " % self.priority
    outstr += "cookie=%x, " % self.cookie
    outstr += "idle_timeout=%d, " % self.idle_timeout
    outstr += "hard_timeout=%d, " % self.hard_timeout
    outstr += "match=%s, " % self.match
    outstr += "data=%s, " % repr(self.data)
    return outstr

  def flow_stats(self, now=None):
    if now is None: now = time.time()
    dur_nsec, dur_sec = math.modf(now - self.created)
    return ofp_flow_stats(match=self.match,
                          duration_sec=int(dur_sec),
                          duration_nsec=int(dur_nsec * 1e9),
                          priority=self.priority,
                          idle_timeout=self.idle_timeout,
                          hard_timeout=self.hard_timeout,
                          cookie=self.cookie,
                          packet_count=self.packet_count,
                          byte_count=self.byte_count,
                          data=self.data)

  def to_flow_removed(self, now=None, reason=None):
    # TODO: Rename flow_stats to to_flow_stats and refactor?
    if now is None: now = time.time()
    dur_nsec, dur_sec = math.modf(now - self.created)
    fr = ofp_flow_removed()
    fr.match = self.match
    fr.cookie = self.cookie
    fr.priority = self.priority
    fr.reason = reason
    fr.duration_sec = int(dur_sec)
    fr.duration_nsec = int(dur_nsec * 1e9)
    fr.idle_timeout = self.idle_timeout
    fr.hard_timeout = self.hard_timeout
    fr.packet_count = self.packet_count
    fr.byte_count = self.byte_count
    return fr

class ContentStoreModification (Event):
  def __init__ (self, added=[], removed=[], reason=None):
    print(" Content Store MODIFICATION : init")
    Event.__init__(self)
    self.added = added
    self.removed = removed

    # Reason for modification.
    # Presently, this is only used for removals and is either one of OFPRR_x,
    # or None if it does not correlate to any of the items in the spec.
    self.reason = reason
    print(" Content Store MODIFICATION : init End")

class ContentStore(EventMixin):

  """
  General model of a name table.

  Maintains an ordered list of name flow entries, and finds matching entries for
  packets and other entries. Supports expiration of name flows.
  """
  _eventMixin_events = set([ContentStoreModification])


  def __init__(self):
    EventMixin.__init__(self)

    # Table is a list of TableEntry sorted by descending effective_priority.
    self._table = []
    self.initContentStore()

  def initContentStore(self):
    print("Content Store : initContent Store")

    #Entry 1
    match=ofp_match(interest_name="/test/contentstorematch")
    entry = ContentStoreEntry(match=match, data="$$$$ - Data for the prefix "
                                                                     "/test/contentstorematch - $$$$")
    print (" Content Store: Adding content store entry for the prefix : /test/contentstorematch")
    self.add_entry(entry)

    #Entry 2 - Commented for now to check CS flow for 1st test
    '''
    entry = ContentStoreEntry(prefix="/test/pitmatch", data="**** - Data for the prefix oldoldold - ****")
    print (" Content Store : Adding content store entry")
    self.add_entry(entry)
    '''


  def _dirty(self):
    """
    Call when table changes
    """
    pass

  # Jeeva : properties of the table
  @property
  def entries(self):
    return self._table

  def __len__(self):
    return len(self._table)

  def add_entry(self, entry):

    print(" Content Store : Content Store Entry to be added :", entry)
    print(" Content Store : Content Store entry :", ContentStoreEntry)
    assert isinstance(entry, ContentStoreEntry)
    print(" Content Store : add_content_store_entry")
    print(" ----------------------\n\n")

    table = self._table
    low = 0
    high = len(table)

    '''
    while low < high:
      middle = (low + high) // 2
      if priority >= table[middle].effective_priority:
        high = middle
        continue
      low = middle + 1
    '''
    print(" Content Store  : Table before adding the new content store entry :", table)
    print("\n\n")
    table.insert(low, entry)

    self._dirty()

    print(" Content Store  : Table after adding the new content store entry :", table)
    print(" ----------------------\n\n")
    print(" Content Store  : add_content_store_entry : Gonna raiseEvent for ContentStoreModification, commented for now"
          " : So no event")
    #self.raiseEvent(FibTableModification(added=[entry]))

  def remove_entry(self, entry, reason=None):
    assert isinstance(entry, PitTableEntry)
    self._table.remove(entry)
    self._dirty()
    self.raiseEvent(PitTableModification(removed=[entry], reason=reason))

  def matching_entries(self, match, priority=0, strict=False, out_port=None):
    print(" Content Store  : matching_entries function : Entries for the given match")
    entry_match = lambda e: e.is_matched_by(match, priority, strict, out_port)
    return [entry for entry in self._table if entry_match(entry)]

  def flow_stats(self, match, out_port=None, now=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    return [e.flow_stats(now) for e in mc_es]

  def aggregate_stats(self, match, out_port=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    packet_count = 0
    byte_count = 0
    flow_count = 0
    for entry in mc_es:
      packet_count += entry.packet_count
      byte_count += entry.byte_count
      flow_count += 1
    return ofp_aggregate_stats(packet_count=packet_count,
                               byte_count=byte_count,
                               flow_count=flow_count)

  def _remove_specific_entries(self, flows, reason=None):
    # for entry in flows:
    #  self._table.remove(entry)
    # self._table = [entry for entry in self._table if entry not in flows]
    if not flows: return
    self._dirty()
    remove_flows = set(flows)
    i = 0
    while i < len(self._table):
      entry = self._table[i]
      if entry in remove_flows:
        del self._table[i]
        remove_flows.remove(entry)
        if not remove_flows: break
      else:
        i += 1
    assert len(remove_flows) == 0
    self.raiseEvent(PitTableModification(removed=flows, reason=reason))

  def remove_expired_entries(self, now=None):
    idle = []
    hard = []
    if now is None: now = time.time()
    for entry in self._table:
      if entry.is_idle_timed_out(now):
        idle.append(entry)
      elif entry.is_hard_timed_out(now):
        hard.append(entry)
    self._remove_specific_entries(idle, OFPRR_IDLE_TIMEOUT)
    self._remove_specific_entries(hard, OFPRR_HARD_TIMEOUT)

  def remove_matching_entries(self, match, priority=0, strict=False,
                              out_port=None, reason=None):
    print(" Content Store : remove_matching_entries")
    remove_flows = self.matching_entries(match, priority, strict, out_port)
    self._remove_specific_entries(remove_flows, reason=reason)
    return remove_flows

  def content_store_entry_for_packet(self, packet, in_port):
    # Jeeva : Check for PIT
    print(" Content Store : In content_store_entry_for_packet function")
    packet_match = ofp_match.from_packet(packet, in_port, spec_frags=True)
    interest_name = packet_match.interest_name

    for entry in self._table:
      print(" Content Store : checking each entry in the content store table :", entry, "\n")
      if entry.match.interest_name == interest_name :
        print (" Content Store entry Found : Have to send the data to the corresponding requester , which is in_port")
        return True
    print (" No content store entry found : Have to check in PIT for pending interests now")
    return False

  #Jeeva : This function may be useful later
  def entry_for_packet(self, packet, in_port):
    """
    Finds the flow table entry that matches the given packet.

    Returns the highest priority flow table entry that matches the given packet
    on the given in_port, or None if no matching entry is found.

    Jeeva:

      Call ofp_match.from_packet and create a packet match for the received packet
      from the entries that are already in the name table, find out the matching entry
      using the packet match created in the previous step
    """

    print (" Content Store : entry_for_packet funtion")

    packet_match = ofp_match.from_packet(packet, in_port, spec_frags=True)

    print (" Content Store : Created a match with the given packet")

    if (packet_match.interest_name == "newnewnew"):
      entry = FibTableEntry(priority=5, match=packet_match,
                             actions=[ofp_action_output(port=3), ofp_action_output(port=4)])
      print (
      " Content Store : Created a sample entry to match with the packet(newnewnew) : using the packet match itself as a hack")
      self.add_entry(entry)
    else:
      print (" Content Store : Sample Entry is not created")

    print(" \n\n Content Store, Entire Table before checking for match with the packet:", self._table)
    print("\n\n")
    # for entry in self._table:
    # print(" NAME TABLE, match in self.table :", entry.match)

    # Jeeva : Add these lines later
    for entry in self._table:
      print(" Content Store, checking each entry  :", entry, "\n")
      if entry.match.matches_with_wildcards(packet_match,
                                            consider_other_wildcards=False):
        return entry
    # Jeeva : No entry in the table
    return None  # Jeeva : Should return an entry

  def check_for_overlapping_entry(self, in_entry):
    """
    Tests if the input entry overlaps with another entry in this table.

    Returns true if there is an overlap, false otherwise. Since the table is
    sorted, there is only a need to check a certain portion of it.
    """
    # NOTE: Assumes that entries are sorted by decreasing effective_priority
    # NOTE: Ambiguous whether matching should be based on effective_priority
    #      or the regular priority.  Doing it based on effective_priority
    #      since that's what actually affects packet matching.
    # NOTE: We could improve performance by doing a binary search to find the
    #      right priority entries.

    #Jeeva : Check is the same prefix is entered twice in the table

    return False


