import os
import sys
import subprocess

thisdir = os.path.dirname(__file__)
if len(thisdir) == 0:
    thisdir = '.'

clang_format = thisdir + '/build/third/llvm-project/llvm/bin/clang-format'
if not os.path.exists(clang_format):
    clang_format = os.getenv('CLANG_FORMAT')
    if not clang_format or not os.path.exists(clang_format):
        print('CLANG_FORMAT env is missing.')
        sys.exit(-1)

src_exts = ['.c', '.cc', '.cpp', '.h', '.hpp']

def paths(path):
    path_collection = []
    for dirpath, dirnames, filenames in os.walk(path):
        for file in filenames:
            fullpath = os.path.join(dirpath, file)
            path_collection.append(fullpath)
    return path_collection
    
def do_format(path):
    for p in paths(path):
        for ext in src_exts:
            if p.endswith(ext):
                print('Formatting "%s" ...' % (p))
                subprocess.Popen([clang_format, '-i', '-style=LLVM', p]).wait()
                break

def main():
    do_format(thisdir + '/src')
    do_format(thisdir + '/script')
    print('Done.')

if __name__ == '__main__':
    main()
