'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

def version():
    print('v0.0.1')

def usage():
    print('''Visual ICPP makes C++ script running in visual and debuggable mode.
pause(): pause current thread.
run(): run current thread from pausing.
stop(): stop running current script file.
setbp(addr): set breakpoint at the specified address.
delbp(addr): delete breakpoint at the specified address.
readmem(addr, bytes, format): read memory at the specified address, 
    the format can be: '1ix', '4ix', '8ix', 'str'.
stepi(): step into 1 instruction.
stepo(): step over 1 instruction.''')

def pause():
    print('unimpl')

def run():
    print('unimpl')
    
def stop():
    print('unimpl')
    
def setbp(addr):
    print('unimpl')
    
def delbp(addr):
    print('unimpl')
    
def readmem(addr, bytes, format):
    print('unimpl')

def stepi(): 
    print('unimpl')
    
def stepo():
    print('unimpl')
