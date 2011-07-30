#!/usr/bin/env python3

# Copyright (C) 2011  Thomas Reineking
#
# This file is part of the synkrotron application.
# 
# Synkrotron is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Synkrotron is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
A tool for synchronizing local and remote directories with client-side encryption support.
"""

import argparse
import bisect
from concurrent import futures
import configparser
import fnmatch
import hashlib
import inspect
import io
import os
import pickle
import signal
import stat
import subprocess
import sys


class Remote:
    """Provides access to a remote directory by handling mounting and encryption."""
    
    def __init__(self, name, location, sync_dir, *, key='', mount_point=''):
        """
        Create remote directory wrapper.
        
        name: a unique label referring to the directory
        location: location of the directory ("host:path" where "host:" is optional)
        sync_dir: path of the synchronization directory ("<local directory>/.synkrotron")
        key: encryption key (optional)
        mount_point: path where the remote directory should be mounted (optional, this is created dynamically and the last component must not exist before mounting)
        """
        self.name = name
        self.location = location
        if ':' in location:
            self.host, self.root = location.split(':')
        else:
            self.host = None
            self.root = location
        self.sync_dir = sync_dir
        self.key = key
        self.mount_point = mount_point
    
    def _sync_path(self, type):
        return os.path.join(self.sync_dir, self.name + '-' + type)
    
    def is_local(self):
        """Check whether the directory is located on a remote server."""
        return ':' not in self.location
    
    def mount(self):
        """Mount the directory and return the mount point."""
        path = self.location
        if not self.is_local(): # remote server -- mount with sshfs
            target = self._sync_path('sshfs')
            if not os.path.ismount(target):
                if not os.path.exists(target):
                    os.mkdir(target)
                if execute(['sshfs', '-o', 'idmap=user', path, target]) != 0:
                    raise Exception('unable to mount %s with sshfs' % path)
            path = target
        if self.key: # decrypt with encfs
            target = self._sync_path('encfs')
            self.encfs_source = path
            self.encfs_destination = target
            if not os.path.ismount(target):
                if not os.path.exists(target):
                    os.mkdir(target)
                if os.path.isfile(os.path.join(self.encfs_source, '.encfs6.xml')):
                    input = self.key
                else:
                    # manual encfs configuration; pretty ugly, but currently it's the only way for using custom options
                    input = 'x\n1\n192\n\n1\nno\nno\n\n0\n\n' + self.key
                if execute(['encfs', '--stdinpass', path, target], input=input) != 0:
                    raise Exception('unable to mount %s with encfs' % path)
            path = target
        if self.mount_point:
            if os.path.exists(self.mount_point):
                if os.path.islink(self.mount_point):
                    os.remove(self.mount_point)
                else:
                    raise Exception('mount point %s exists but is not a link' % self.mount_point)
            os.symlink(path, self.mount_point)
            path = self.mount_point
        self.mount_path = path
        return path
    
    def umount(self):
        """Unmount the directory and delete all created mount points."""
        if self.mount_point:
            os.remove(self.mount_point)
        if self.key:
            path = self._sync_path('encfs')
            if execute(['fusermount', '-u', path]) != 0:
                raise('unmounting encfs at %s failed' % path)
            else:
                os.rmdir(path)
        if not self.is_local():
            path = self._sync_path('sshfs')
            if execute(['fusermount', '-u', path]) != 0:
                raise('unmounting sshfs at %s failed' % path)
            else:
                os.rmdir(path)
        self.mount_path = None
    
    def reverse_mount(self):
        """
        Mount the local directory with encfs in reverse mode.
        
        The remote directory must be encrypted and mounted.
        This is used for efficiently comparing encrypted file contents in case the remote directory is mounted over a network connection.
        """
        self.encfs_reverse = self._sync_path('encfs-reverse')
        if not os.path.ismount(self.encfs_reverse):
            if not os.path.exists(self.encfs_reverse):
                os.mkdir(self.encfs_reverse)
            if not hasattr(self, 'encfs_source'):
                raise Exception('remote must be mounted with encfs')
            env = {'ENCFS6_CONFIG':os.path.join(self.encfs_source, '.encfs6.xml')}
            if execute(['encfs', '--stdinpass', '--reverse', os.path.dirname(self.sync_dir), self.encfs_reverse], input=self.key, env=env) != 0:
                raise Exception('unable to reverse mount %s with encfs' % self.encfs_reverse)
        return self.encfs_reverse
    
    def reverse_umount(self):
        """Unmount the local directory when it was mounted before in reverse mode."""
        if execute(['fusermount', '-u', self.encfs_reverse]) != 0:
            raise('unmounting encfs (reverse mode) at %s failed' % self.encfs_reverse)
        else:
            os.rmdir(self.encfs_reverse)
    
    def save_cache(self):
        """Write the encryption cache to disk."""
        if hasattr(self, '_cache'):
            with io.open(self._cache_file, 'wb') as f:
                pickle.dump(self._cache, f)
    
    def _load_cache(self):
        """Read the encryption cache from disk."""
        if not hasattr(self, '_cache'):
            self._cache_file = self._sync_path('cache-' + hashlib.md5(self.key.encode()).hexdigest())
            try:
                with io.open(self._cache_file, 'rb') as f:
                    self._cache = pickle.load(f)
            except:
                self._cache = (dict(), dict()) # encrypted->clear, clear->encrypted
    
    def decrypt_names(self, filenames):
        """Decrypt filenames in case key is set."""
        return self._map_names('decode', filenames)
    
    def encrypt_names(self, filenames):
        """Encrypt filenames in case key is set."""
        return self._map_names('encode', filenames)
    
    def _map_names(self, command, filenames):
        self._load_cache()
        cache_index = 0 if command == 'decrypt' else 1
        uncached = [fn for fn in filenames if fn not in self._cache[cache_index]]
        if uncached:
            input = '\n'.join(uncached)
            _, output = execute(['encfsctl', command, '--extpass=echo %s' % self.key, self.encfs_source], input=input, return_stdout=True)
            for fn, mapped in zip(uncached, str(output, 'utf_8').split('\n')):
                if fn[0] == '/':
                    mapped = '/' + mapped
                self._cache[cache_index][fn] = mapped
                self._cache[1 - cache_index][mapped] = fn
        return [self._cache[cache_index][fn] for fn in filenames]


class Repo:
    """
    Wrapper for collecting all files of a local or remote directory.
    
    Note that parts of this class are executed on the remote side and must therefore not reference any other parts of the code.
    """
    
    def __init__(self, source, *, follow_links=False, exclude=None, rel_path='.'):
        """
        Create a directory wrapper.
        
        source: either a Remote object or a path referring to a local directory
        follow_links: determines whether symbolic links are followed or not
        exclude: list or string of exclude patterns (optional, in case of a string, patterns are separated by ":")
        rel_path: relative path within the directory, all other files are ignored (optional)
        """
        self.source = source
        self.rel_path = rel_path
        self.follow_links = follow_links
        if exclude is None:
            self.exclude = []
        elif isinstance(exclude, str):
            self.exclude = exclude.split(':')
        else:
            self.exclude = exclude
        self.exclude = ['/.synkrotron'] + [pattern[:-1] if pattern[-1] == '/' and len(pattern) > 1 else pattern for pattern in self.exclude if pattern]
        if isinstance(self.source, str): # remote
            self.root = source
        else:
            self.root = source.mount_path
    
    def _remote_call(self, line):
        """
        Execute the given line of code on the remote machine and return the result.
        
        The whole class including all imports is transferred to the remote machine.
        """
        code = '\n'.join([l for l in inspect.getsource(sys.modules[__name__]).split('\n') if l.startswith('import ')])
        code += '\n' + inspect.getsource(Repo) + '\npickle.dump(%s, sys.stdout.buffer)' % line
        _, output = execute(['ssh', self.source.host, 'LC_CTYPE=en_US.utf-8 python3'], input=code, return_stdout=True)
        return pickle.loads(output)
    
    def collect(self):
        """Generate a dictionary of all files in the directory including their sizes and modification time stamps."""
        if not isinstance(self.source, str) and not self.source.is_local():
            return dict(self._collect_remote())
        else:
            return dict(self._collect_local())
        
    def _collect_local(self):
        def info(file):
            path = os.path.normpath(os.path.relpath(file, self.root))
            if self.follow_links:
                st = os.stat(file)
            else:
                st = os.lstat(file)
            type = 'x'
            if stat.S_ISDIR(st.st_mode):
                type = 'd'
            elif stat.S_ISREG(st.st_mode):
                type = 'f'
            if stat.S_ISLNK(st.st_mode): # not self.follow_links and 
                type = 'l'
            return path, (type, st.st_size, st.st_mtime)
        base = os.path.join(self.root, self.rel_path)
        if not os.path.exists(base):
            return
        yield info(base)
        for dir, dirnames, filenames in os.walk(base, followlinks=self.follow_links):
            for names in (dirnames, filenames):
                names.sort()
                rel_dir = os.path.relpath(dir, self.root)
                if self.exclude:
                    for ign in reversed(list(self._ignore_files(rel_dir, names))):
                        del names[bisect.bisect_left(names, ign)]
                for name in names:
                    try:
                        file = os.path.join(dir, name)
                        yield info(file)
                    except:
                        print('warning: ignoring file "%s" (unable to stat)' % os.path.normpath(file))
    
    def _collect_remote(self):
        def call(exclude, rel_path):
            return self._remote_call("Repo('''%s''',follow_links=%d,exclude=%s,rel_path='''%s''').collect()"
                                      % (self.source.root, self.follow_links, exclude, rel_path))
        if self.source.key:
            exclude_fixed = [exc for exc in self.exclude if '*' not in exc] # excludes without wildcards
            rel_path_encrypted, *exclude_encrypted = self.source.encrypt_names([self.rel_path] + exclude_fixed)
            exclude_encrypted.append('/.encfs6.xml')
            stats_encrypted = list(call(exclude_encrypted, rel_path_encrypted).items())
            stats_encrypted.sort(key=lambda s: len(s[0]))
            paths = self.source.decrypt_names([s[0] for s in stats_encrypted])
            stats = dict()
            excluded = set()
            for path, stat in zip(paths, stats_encrypted):
                skip = False
                for e in excluded:
                    if path.startswith(e):
                        skip = True
                        break
                if skip:
                    continue
                for _ in self._ignore_files(os.path.dirname(path), [os.path.basename(path)]):
                    excluded.add(path)
                    break
                else:
                    stats[path] = stat[1]
            return stats
        else:
            return call(self.exclude, self.rel_path)
    
    def _ignore_files(self, dir, filenames):
        for fn in filenames:
            path = os.path.normpath(os.path.join(dir, fn))
            for pattern in self.exclude:
                if pattern[0] == '/': # anchored: match the whole path starting from the repository root
                    if fnmatch.fnmatch(path, pattern[1:]):
                        yield fn
                        break
                else: # not anchored: only match the last component of the path
                    tmp_path, tail = os.path.split(path)
                    components = [tail]
                    for _ in range(pattern.count('/')):
                        tmp_path, tail = os.path.split(tmp_path)
                        components.append(tail)
                    if fnmatch.fnmatch('/'.join(reversed(components)), pattern):
                        yield fn
                        break
    
    def file_hash(self, file):
        """Compute a hash of the corresponding file content."""
        if not isinstance(self.source, str) and not self.source.is_local():
            if self.source.key:
                file = os.path.join(self.source.root, self.source.encrypt_names([file])[0])
            else:
                file = os.path.join(self.source.root, file)
            return self._remote_call("Repo._file_hash('''%s''')" % file)
        else:
            if not os.path.isabs(file):
                file = os.path.join(self.root, file)
            return Repo._file_hash(file)
    
    @staticmethod
    def _file_hash(file):
        md5 = hashlib.md5()
        with open(file, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
            return md5.digest()


class Diff:
    """Compare and copy files between two directories."""
    
    def __init__(self, repo_local, repo_remote, *, ignore_time=False, content=False, modify_window=0):
        """
        Create a Diff object and generate a list of all differing files.
        
        repo_local: Repo object representing the local directory
        repo_remote: Repo object representing the remote directory
        ignore_time: determines whether modification times are used during the comparison (default is False)
        content: determines whether file contents are used during the comparison (default is False)
        modify_window: the maximum allowed time difference between two files in order to be considered equal (default is 0)
        """
        if not isinstance(repo_local, Repo):
            raise TypeError()
        if not isinstance(repo_remote, Repo):
            raise TypeError()
        self.ignore_time = ignore_time
        self.content = content
        self.modify_window = modify_window
        self.repo_local = repo_local
        self.repo_remote = repo_remote
        self.list = []
        with futures.ThreadPoolExecutor(max_workers=2) as executor:
            stats_local, stats_remote = executor.map(Repo.collect, [repo_local, repo_remote])
        for file_local, stat_local in stats_local.items():
            if file_local in stats_remote:
                cmp = self._compare_stats(stat_local, stats_remote[file_local], file_local)
                if cmp:
                    self.list.append((file_local, cmp[0], cmp[1]))
            else:
                self.list.append((file_local, stat_local, 'push'))
        self.list.extend([(f, stats_remote[f], 'pull') for f in set(stats_remote.keys()).difference(stats_local.keys())])
        self.list.sort()
    
    def _compare_stats(self, stat_src, stat_dst, file):
        if stat_src[0] == stat_dst[0] == 'd':
            return None
        diff_size = stat_src[1] - stat_dst[1]
        diff_time = int(stat_src[2] - stat_dst[2])
        if diff_size or (not self.ignore_time and abs(diff_time) > self.modify_window):
            if diff_time < 0:
                return stat_dst, 'pull'
            else:
                return stat_src, 'push'
        elif self.content:
            if not isinstance(self.repo_remote.source, str) and not self.repo_remote.source.is_local() and self.repo_remote.source.key:
                file_encrypted = self.repo_remote.source.encrypt_names([file])[0]
                file_local = os.path.join(self.repo_remote.source.encfs_reverse, file_encrypted)
            else:
                file_local = file
            with futures.ThreadPoolExecutor(max_workers=2) as executor:
                hash_local = executor.submit(self.repo_local.file_hash, file_local)
                hash_remote = executor.submit(self.repo_remote.file_hash, file)
            if hash_local.result() != hash_remote.result():
                return (stat_src, stat_dst), 'content'
        return None
    
    def pull(self, *, simulate=False, delete=False, delta=None):
        """
        Pull differing files from the remote directory to the local directory using rsync.
        
        simulate: run rsync in simulation mode
        delete: delete files that exist locally but not on the remote side
        delta: copy all differing files to this path instead of copying them to the local directory
        """
        self._copy(operation='pull', simulate=simulate, delete=delete, delta=delta)
    
    def push(self, *, simulate=False, delete=False, delta=None):
        """
        Push differing files from the local directory to the remote directory using rsync.
        
        simulate: run rsync in simulation mode
        delete: delete files that exist on the remote side but not locally
        delta: copy all differing files to this path instead of copying them to the remote directory
        """
        self._copy(operation='push', simulate=simulate, delete=delete, delta=delta)
    
    def _copy(self, *, operation, simulate=False, delete=False, delta=None):
        """Copy files from src to dst using rsync."""
        if operation == 'push':
            src = self.repo_local.root
            dst = self.repo_remote.root
        else:
            src = self.repo_remote.root
            dst = self.repo_local.root
        rev_operation = 'pull' if operation == 'push' else 'push'
        if delete: # delete all files at the destination that do not exist at the source
            for f in reversed(self.list):
                if f[2] == rev_operation:
                    print('deleting ' + f[0])
                    if not simulate:
                        path = os.path.join(dst, f[0])
                        if os.path.isdir(path):
                            os.rmdir(path)
                        else:
                            os.remove(path)
        if self.content:
            for f in self.list:
                if f[2] == 'content':
                    print('deleting ' + f[0] + ' (different content)')
                    if not simulate:
                        os.remove(os.path.join(dst, f[0]))
        file_list = '\n'.join([f[0] for f in self.list if f[2] != rev_operation])
        options = []
        if simulate:
            options.append('--dry-run')
        if self.repo_local.follow_links:
            options.append('--copy-links')
        if delta:
            dst = delta
        execute(['rsync', '-ahuR', '--files-from=-', '--progress', '--partial-dir', '.rsync-partial'] + options + ['.', dst], cwd=src, input=file_list)
    
    @staticmethod
    def format_size(bytes):
        """Format file size."""
        units = ['T', 'G', 'M', 'K', '']
        while len(units) and bytes >= 1000:
            bytes /= 1024
            units.pop()
        return '%.1f %sB' % (round(bytes, 1), units[-1])
    
    def show(self):
        """Print all differing files and their sizes."""
        pull_count = pull_size = push_count = push_size = 0
        for file, stat, operation in self.list:
            if operation == 'push':
                if stat[0] == 'f':
                    push_size += stat[1]
                    print('--> %s (%s)' % (file, self.format_size(stat[1])))
                else:
                    print('--> %s' % file)
                push_count += 1
            elif operation == 'pull':
                if stat[0] == 'f':
                    pull_size += stat[1]
                    print('<-- %s (%s)' % (file, self.format_size(stat[1])))
                else:
                    print('<-- %s' % file)
                pull_count += 1
            else:
                print('<-> %s (%s/%s)' % (file, self.format_size(stat[0][1]), self.format_size(stat[1][1])))
        print('pull: %d objects (%s)' % (pull_count, self.format_size(pull_size)))
        print('push: %d objects (%s)' % (push_count, self.format_size(push_size)))


class Config:
    """Find relevant paths and read the configuration file."""
    
    _defaults = {'location':'',
                 'key':'',
                 'mount_point':'',
                 'ignore_time':'0',
                 'delete':'0',
                 'follow_links':'0',
                 'exclude':'',
                 'modify_window':'0',
                 'content':'0'}
     
    def __init__(self, cwd=None):
        """
        Create a new Config object based either on the current working directory or on a given path.
        
        Sets the root of the local directory (root), the synchronization directory (sync_dir), and 
        the current working directory relative to the local directory root (rel_cwd).
        Raises an exception if no configuration file was found or if it contains invalid options.
        """
        self._init_paths(cwd)
        self._read_remotes()
    
    def _init_paths(self, cwd):
        if cwd is None:
            cwd = os.getcwd()
        self.root = cwd
        while '.synkrotron' not in os.listdir(self.root) and not os.path.isfile(os.path.join(self.root, '.synkrotron', 'config')) and self.root != '/':
            self.root = os.path.dirname(self.root)
        self.sync_dir = os.path.join(self.root, '.synkrotron')
        self.config_file = os.path.join(self.sync_dir, 'config')
        if not os.path.isfile(self.config_file):
            raise Exception('no configuration file found')
        self.rel_cwd = os.path.relpath(cwd, self.root)
    
    def _read_remotes(self):
        config = configparser.ConfigParser()
        config[configparser.DEFAULTSECT] = Config._defaults
        config.read(self.config_file)
        self.remotes = {}
        for remote in config.sections():
            self.remotes[remote] = {}
            for key, value in config[remote].items():
                if key not in config[configparser.DEFAULTSECT]:
                    raise Exception('unknown option "%s" for %s (supported options: %s)' % (key, remote, ','.join(config['DEFAULT'].keys())))
                self.remotes[remote][key] = value
            if not self.remotes[remote]['location']:
                raise Exception('no location specified for %s' % remote)
            for opt in [opt for opt, value in config[configparser.DEFAULTSECT].items() if value in {'0', '1'}]:
                self.remotes[remote][opt] = int(self.remotes[remote][opt]) # convert to int
    
    @staticmethod
    def init_remote(remote):
        """Create or update a remote directory configuration."""
        dir = os.path.join(os.getcwd(), '.synkrotron')
        if not os.path.exists(dir):
            os.mkdir(dir)
        config_file = os.path.join(dir, 'config')
        if not os.path.exists(config_file):
            print('Creating new configuration')
            with io.open(config_file, 'w'):
                pass
        else:
            print('Updating existing configuration')
        print('(Hint: You can change all options by editing the file ".synkrotron/config".)')
        config = configparser.ConfigParser()
        config.read(config_file)
        if remote not in config:
            config[remote] = Config._defaults
        while (True):
            if config[remote]['location']:
                default = ' (default is "%s")' % config[remote]['location']
            else:
                default = ''
            result = input('Location of the remote repository [use the format "HOST:PATH" where "HOST:" is optional%s]: ' % default)
            if result:
                config[remote]['location'] = result
            if config[remote]['location']:
                break
            else:
                print('location cannot be empty')
        config[remote]['key'] = input('Password [encrypt all files at the remote location] (default is "%s"): ' % config[remote]['key'])
        config[remote]['mount_point'] = input('Mount point [mount the repository at a specific location] (default is "%s"): ' % config[remote]['mount_point'])
        config[remote]['exclude'] = input('Exclude patterns [optional: exclude specific files/directories, use ":" to specify multiple patterns] (default is "%s"): ' % config[remote]['exclude'])
        def number(prompt, binary=False):
            while (True):
                result = input(prompt)
                if binary and result in {'0', '1'}:
                    return result
                elif not result:
                    return '0'
                elif not binary:
                    try:
                        return result
                    except ValueError:
                        pass
                if binary:
                    print('Only "0" and "1" are allowed')
                else:
                    print('Expected a valid number')
        config[remote]['delete'] = number('Delete switch [optional: enter "1" if files that do not exist at the source location should be deleted at the destination] (default is "%s"): ' % config[remote]['delete'], True)
        config[remote]['ignore_time'] = number('Ignore time switch [optional: enter "1" for ignoring file modification times during synchronization] (default is "%s"): ' % config[remote]['ignore_time'], True)
        config[remote]['follow_links'] = number('Follow link switch [optional: enter "1" if symbolic links should be followed during synchronization] (default is "%s"): ' % config[remote]['follow_links'], True)
        config[remote]['content'] = number('Content switch [optional: enter "1" for additionally comparing files based on checksums at the cost of a significant performance penalty] (default is "%s"): ' % config[remote]['content'], True)
        config[remote]['modify_window'] = number('Modification window [optional: maximum allowed modification time difference (in seconds) for files to be considered unchanged] (default is "%s"): ' % config[remote]['modify_window'])
        with io.open(config_file, 'w') as f:
            config.write(f)


def execute(args, *, input=None, cwd=None, return_stdout=False, env=None):
    """
    Run an external program and return its exit code and, optionally, its output.
    
    input: a string passed to stdin of the program (optional)
    cwd: working directory of the program (optional)
    return_stdout: determines whether the program output should be returned (default is False)
    env: set environment variables for the program (optional)
    """
    if env:
        env.update(os.environ)
    process = subprocess.Popen(args, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE if return_stdout else None, env=env)
    if input and isinstance(input, str): # convert string input to bytes
        if input[-1] == '\n':
            input = input.encode()
        else:
            input = (input + '\n').encode()
    stdout, _ = process.communicate(input=input)
    if return_stdout:
        return process.returncode, stdout
    else:
        return process.returncode

def parse_args():
    """Parse command line arguments using argparse."""
    parser = argparse.ArgumentParser(description='Synchronize files between two directories.')
    parser.add_argument('command', choices={'pull','push', 'mount', 'umount', 'diff', 'init'}, help='init, mount, umount, diff, pull, or push')
    parser.add_argument('remote', help='remote name (must be defined in .synkrotron/config)')
    parser.add_argument('-p', '--path', dest='path', help='diff/pull/push only the specified file or directory')
    parser.add_argument('-u', '--umount', action='store_true', help='automatically un-mount remote location after pull or push')
    parser.add_argument('-s', '--simulate', action='store_true', help='set dry-run option for rsync (during pull or push)')
    parser.add_argument('-d', '--delete', action='store_true', help='set delete option for rsync (during pull or push)')
    parser.add_argument('-i', '--ignore-time', dest='ignore_time', action='store_true', help='ignore time stamps for determining whether files are different')
    parser.add_argument('--delta', dest='delta', help='pull/push only changes to the specified path')
    parser.add_argument('-c', '--content', action='store_true', help='compare file contents in addition to size and modification time')
    if len(sys.argv) == 1:
        parser.print_usage()
        exit()
    else:
        return parser.parse_args()


def main():
    """The main program logic."""
    try:
        signal.signal(signal.SIGINT, lambda signal, frame: sys.exit(0))
        args = parse_args()
        if args.command == 'init':
            Config.init_remote(args.remote)
            exit()
        config = Config()
        if args.remote not in config.remotes:
            raise Exception('unknown remote name "%s"' % args.remote)
        remote_config = config.remotes[args.remote]
        remote = Remote(args.remote, remote_config['location'], config.sync_dir, key=remote_config['key'], mount_point=remote_config['mount_point'])
        if args.command == 'umount':
            remote.umount()
        else:
            remote.mount()
            if args.command == 'mount':
                return
            if args.path:
                rel_path = os.path.normpath(os.path.join(config.rel_cwd, args.path))
            else:
                rel_path = config.rel_cwd
            repo_local = Repo(config.root, follow_links=remote_config['follow_links'], exclude=remote_config['exclude'], rel_path=rel_path)
            repo_remote = Repo(remote, follow_links=remote_config['follow_links'], exclude=remote_config['exclude'], rel_path=rel_path)
            ignore_time = args.ignore_time or remote_config['ignore_time']
            content = args.content or remote_config['content']
            if content and remote.key:
                remote.reverse_mount()
            diff = Diff(repo_local, repo_remote, ignore_time=ignore_time, content=content, modify_window=remote_config['modify_window'])
            if content and remote.key:
                remote.reverse_umount()
            delete = args.delete or remote_config['delete']
            if args.command in {'pull', 'push'}:
                diff._copy(operation=args.command, simulate=args.simulate, delete=delete, delta=args.delta)
            elif args.command == 'diff':
                diff.show()
            if args.umount:
                remote.umount()
    except Exception as e:
        print('error: ' + str(e))


if __name__ == '__main__':
    main()
