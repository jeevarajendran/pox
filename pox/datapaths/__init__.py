# Copyright 2013 James McCauley
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
Lets you start a default instance of the datapath, for what it's worth.

Example:
./pox.py --no-openflow datapaths:softwareswitch --address=localhost
"""

from pox.lib.ioworker.workers import BackoffWorker
from pox.datapaths.switch import SoftwareSwitch, OFConnection, ICNSwitch
from pox.datapaths.switch2 import ICNSwitch2
from pox.datapaths.switch import ExpireMixin
from pox.datapaths.nx_switch import NXSoftwareSwitch
from pox.lib.util import dpid_to_str, str_to_dpid


class OpenFlowWorker (BackoffWorker):
  def __init__ (self, switch=None, **kw):
    print(" OpenFlowWorker ")
    self.switch = switch
    self.connection = None
    #print(" OpenFlowWorker Switch :", self.switch.dpid)
    #print(" OpenFlowWorker Connection :", self.connection)
    from pox.core import core
    self.log = core.getLogger("dp." + dpid_to_str(self.switch.dpid))
    super(OpenFlowWorker, self).__init__(switch=switch,**kw)
    self._info("Connecting to %s:%s", kw.get('addr'), kw.get('port'))
    print(" Connecting to %s:%s", kw.get('addr'), kw.get('port'))

  def _handle_close (self):
    super(OpenFlowWorker, self)._handle_close()

  def _handle_connect (self):
    print(" OpenFlowWorker : _handle_connect ")
    super(OpenFlowWorker, self)._handle_connect()
    self.connection = OFConnection(self)
    self.switch.set_connection(self.connection)
    self._info(" Connected to controller")
    print("\n\n\n")
    print(" ***** Connected to controller ******")
    print(" ------------------------------------")
    print("\n\n\n")

  def _error (self, *args, **kw):
    self.log.error(*args,**kw)
  def _warn (self, *args, **kw):
    self.log.warn(*args,**kw)
  def _info (self, *args, **kw):
    self.log.info(*args,**kw)
  def _debug (self, *args, **kw):
    self.log.debug(*args,**kw)


def do_launch (cls, address = '127.0.0.1', port = 6633, max_retry_delay = 16,
    dpid = None, extra_args = None, **kw):
  """
  Used for implementing custom switch launching functions

  cls is the class of the switch you want to add.

  Returns switch instance.
  """
  print(" DATAPATH : IN DO LAUNCH")
  if extra_args is not None:
    import ast
    extra_args = ast.literal_eval('{%s}' % (extra_args,))
    kw.update(extra_args)

  from pox.core import core
  if not core.hasComponent('datapaths'):
    core.register("datapaths", {})
  _switches = core.datapaths

  if dpid is None:
    for dpid in range(1,256):
      if dpid not in _switches: break
    if dpid in _switches:
      raise RuntimeError("Out of DPIDs")
  else:
    dpid = str_to_dpid(dpid)

  switch = cls(dpid=dpid, name="sw"+str(dpid), **kw)
  _switches[dpid] = switch

  port = int(port)
  max_retry_delay = int(max_retry_delay)

  def up (event):
    import pox.lib.ioworker
    global loop
    loop = pox.lib.ioworker.RecocoIOLoop()
    #loop.more_debugging = True
    loop.start()
    OpenFlowWorker.begin(loop=loop, addr=address, port=port,
        max_retry_delay=max_retry_delay, switch=switch)

  from pox.core import core

  core.addListenerByName("UpEvent", up)

  return switch


def softwareswitch (address='127.0.0.1', port = 6633, max_retry_delay = 16,
    dpid = None, extra = None, __INSTANCE__ = None):
  """
  Launches a SoftwareSwitch

  Not particularly useful, since SoftwareSwitch doesn't do much.
  """
  print(" DATAPATH : Software Switch Function")
  from pox.core import core
  print(" DATAPATH : Registering in core")
  core.register("datapaths", {})

  class ExpiringSwitch(ExpireMixin, SoftwareSwitch):
    pass

  print(" DATAPATH : Gonna call Do Launch")
  do_launch(ExpiringSwitch, address, port, max_retry_delay, dpid,
            extra_args = extra)

def icnswitch1 (address='127.0.0.1', port = 6633, max_retry_delay = 16,
    dpid = "123", extra = None, __INSTANCE__ = None):
  """
  Launches a ICNSwitch

  Not particularly useful, since ICNSwitch doesn't do much.
  """
  print(" DATAPATH : ICN Switch Function")
  from pox.core import core
  print(" DATAPATH : Registering in core")
  core.register("datapaths", {})

  class ExpiringSwitch(ExpireMixin, ICNSwitch):
    pass

  print(" DATAPATH : Gonna call Do Launch")
  do_launch(ExpiringSwitch, address, port, max_retry_delay, dpid,
            extra_args = extra)

def icnswitch2 (address='127.0.0.1', port = 6633, max_retry_delay = 16,
    dpid = "456", extra = None, __INSTANCE__ = None):
  """
  Launches a ICNSwitch

  Not particularly useful, since ICNSwitch doesn't do much.
  """
  print(" DATAPATH : ICN Switch Function")
  from pox.core import core
  print(" DATAPATH : Registering in core")
  core.register("datapaths", {})

  class ExpiringSwitch(ExpireMixin, ICNSwitch2):
    pass

  print(" DATAPATH : Gonna call Do Launch")
  do_launch(ExpiringSwitch, address, port, max_retry_delay, dpid,
            extra_args = extra)

