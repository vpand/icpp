'''
* Interpreting C++, executing the source and executable like a script */
* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
* Copyright (c) vpand.com 2024. This file is released under LGPL2.
  See LICENSE in root directory for more details
'''

import os
import platform
import sys
import subprocess

thisdir = os.path.dirname(__file__)
if len(thisdir) == 0:
    thisdir = '.'

# you can use the following build command to generate clang-format:
# build % cmake --build . -- clang-format
clang_format = thisdir + '/build/third/llvm-project/llvm/bin/clang-format'
if platform.system() == 'Windows':
    # construct the right full path of clang-format.exe
    clang_format += '.exe'
if not os.path.exists(clang_format):
    clang_format = os.getenv('CLANG_FORMAT')
    if not clang_format or not os.path.exists(clang_format):
        # CLANG_FORMAT env is missing, make sure clang-format is in your system PATH environment.
        clang_format = 'clang-format'

src_exts = ['.c', '.cc', '.cpp', '.h', '.hpp']

def paths(path):
    path_collection = []
    for dirpath, dirnames, filenames in os.walk(path):
        for file in filenames:
            fullpath = os.path.join(dirpath, file)
            path_collection.append(fullpath)
    return path_collection

def is_modified(modifiedfs, path):
    # a None modifiedfs means formatting all the source files
    if modifiedfs is None:
        return True
    for m in modifiedfs:
        if path.endswith(m):
            return True
    return False
    
def do_format(path, modifiedfs):
    for p in paths(path):
        for ext in src_exts:
            if p.endswith(ext) and is_modified(modifiedfs, p):
                print('Formatting "%s" ...' % (p))
                subprocess.Popen([clang_format, '-i', '-style=LLVM', p]).wait()
                break

def main(argv):
    # make sure git is in your system PATH environment to run this script.
    gits = subprocess.Popen(['git', 'status', '--ignore-submodules'], stdout=subprocess.PIPE)
    gits.wait()
    lines = gits.stdout.readlines()
    modifiedfs = []
    for l in lines:        
        lstr = l.decode('utf-8').strip()
        parts = lstr.split('modified:')
        if len(parts) != 2:
            parts = lstr.split('new file:')
        if len(parts) == 2:
            # save the modified files
            modifiedfs.append(os.path.basename(parts[1]))
    if len(modifiedfs) == 0:
        print('Everything is up to date, nothing needs to be done')
        sys.exit(0)
    if len(argv) == 2:
        if argv[1] == 'all':
            # force to format all the source files
            modifiedfs = None
    for subdir in ['src', 'snippet', 'snippet-cppm', 'tool-icpp', 'test', 'vmpstudio']:
        do_format(thisdir + '/' + subdir, modifiedfs)
    print('Done.')
    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
