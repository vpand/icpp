'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

def usage():
    print('''Visual ICPP makes C++ script running in visual and debuggable mode.
connect(): connect to icpp debug server.
disconnect(): disconnect to icpp debug server.
pause(): pause current thread.
run(): run current thread from pausing.
stop(): stop running current script file.
setbp(addr): set breakpoint at the specified address.
delbp(addr): delete breakpoint at the specified address.
readmem(addr, bytes, format): read memory at the specified address, 
    the format can be: '1ix', '4ix', '8ix', 'str'.
stepi(): step into 1 instruction.
stepo(): step over 1 instruction.
lsthread(): list all the running threads.
lsobject(): list all the running objects.
switchthread(tid): switch the debuggee thread.''')

import os
from ctypes import cdll, c_uint64
from pathlib import Path

# vmpstudio plugin module handle
vsp = None

def init_apis():
    global vsp
    vsppath = '%s/VMPStudio/plugin/visualicpp.vsp' % (Path.home())
    if not os.path.exists(vsppath):
        print('You should make a link from $ICPP_ROOT/vmpstudio/visualicpp.vsp to %s.' % (vsppath))
        return
    vsp = cdll.LoadLibrary(vsppath)
    print('Initialized visual icpp python api, run icpp.usage() to see more help information.')

init_apis()

def connect():
    vsp.vi_connect()

def disconnect():
    vsp.vi_disconnect()

def pause():
    vsp.vi_pause()

def run():
    vsp.vi_run()
    
def stop():
    vsp.vi_stop()
    
def setbp(addr):
    vsp.vi_setbp(addr)
    
def delbp(addr):
    vsp.vi_delbp(addr)
    
def readmem(addr, bytes, format):
    vsp.vi_readmem(c_uint64(addr), bytes, format.encode('utf-8'))

def stepi(): 
    vsp.vi_stepi()
    
def stepo():
    vsp.vi_stepo()

def lsthread():
    vsp.vi_lsthread()

def lsobject():
    vsp.vi_lsobject()

def switchthread(tid):
    vsp.vi_switchthread(tid)
