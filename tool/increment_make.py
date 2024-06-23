'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

'''
Prerequisites:
1. cmake uses the Makefile generator;
2. cmake, make and git are in your system PATH environment;
3. current directory is in your build root directory;

Why:
As project icpp depends on LLVM/Clang which has so many dependent files, some of 
the auto generated files will be renewed every time we build which makes building 
progress to be very slow, so I write this helper script to build the visualicpp/icpp 
project faster when developing.
'''

import os
import sys
import subprocess

cmake_projects = ['visualicpp', 'icpp']

def command(cmd, log = True):
    if log:
        print(cmd)
    retcode = subprocess.call(cmd, shell=True)
    if retcode != 0:
        sys.exit(retcode)

def full_make():
    projects = ''
    for p in cmake_projects:
        projects += p + ' '
    print('Parsing building commands...')
    command('cmake --build . -- %s -Bn > Makefile.sh' % (projects))
    magics = []
    for p in cmake_projects:
        magics.append('/%s.dir/' % (p))
    cmdcaches = []
    with open('Makefile.sh', 'r') as fp:
        lines = fp.readlines()
    for l in lines:
        cmd = l.strip()
        for m in magics:
            if cmd.find(m) > 0:
                cmdcaches.append(cmd)
                command(cmd, False)
                break
    with open('Makefile.sh', 'w') as fp:
        for c in cmdcaches:
            fp.write(c)
            fp.write('\n')
        print('Created building commands cache file Makefile.sh.')
    print('Finished building.')
    
def increment_make():
    gits = subprocess.Popen(['git', 'status'], stdout=subprocess.PIPE)
    gits.wait()
    lines = gits.stdout.readlines()
    modifiedfs = []
    src_exts = ['.c', '.cc', '.cpp']
    for l in lines:
        parts = l.decode('utf-8').strip().split('modified:')
        if len(parts) == 2:
            name = os.path.basename(parts[1]).strip()
            if name.endswith('.proto'):
                name = name.replace('.proto', '.pb.cc')
                modifiedfs.append(name)
            else:
                for ext in src_exts:
                    if name.endswith(ext):
                        modifiedfs.append(name)
                        break
    if len(modifiedfs) == 0:
        print('Everything is update to date, no need to build...')
        return
    if not os.path.exists('Makefile.sh'):
        # there's no commands cache file, using full_make instead
        full_make()
        return
    magics = []
    for p in cmake_projects:
        magics.append('/%s.dir/' % (p))
    with open('Makefile.sh', 'r') as fp:
        cmds = fp.readlines()
        for c in cmds:
            if c.find('/link.txt') > 0:
                for m in magics:
                    if c.find(m) > 0:
                        command(c)
                        break
                continue
            for n in modifiedfs:
                if c.find(n) > 0:
                    for m in magics:
                        if c.find(m) > 0:
                            # compile because modified
                            command(c, False)
                            break
                    break
    print('Finished building.')

def main(argv):
    if not os.path.exists('CMakeCache.txt') or not os.path.exists('Makefile'):
        print("There's no CMakeCache.txt, current directory isn't a cmake Makefile-build root directory.")
        return
    if len(argv) == 1:
        increment_make()
    elif argv[1] == 'full':
        full_make()
    else:
        global cmake_projects
        for arg in argv:
            for p in cmake_projects:
                # only increment make this specified project
                if arg == p:
                    cmake_projects = [p]
                    increment_make()
                    sys.exit(0)
        print('Usage: build %% %s [full|visualicpp|icpp]' % (argv[0]))

if __name__ == '__main__':
    main(sys.argv)
