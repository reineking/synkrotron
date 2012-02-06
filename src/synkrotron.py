#!/usr/bin/env python3

# Copyright (C) 2011-2012  Thomas Reineking
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
import shutil
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
            if not os.path.isdir(location):
                raise Exception('%s is not a valid directory' % location)
        self.sync_dir = sync_dir
        self.key = key
        self.mount_point = mount_point
        self.mount_path = None
        self.reverse_mount_path = None
    
    def _sync_path(self, dir_name):
        return os.path.join(self.sync_dir, self.name + '-' + dir_name)
    
    def is_local(self):
        """Check whether the directory is located on a remote server."""
        return ':' not in self.location
    
    def mount(self):
        """Mount the directory and return the mount point."""
        if self.mount_path != None:
            raise Exception('already mounted at %s' % self.mount_path)
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
                    process_input = self.key
                else:
                    # manual encfs configuration; pretty ugly, but currently it's the only way for using custom options
                    process_input = 'x\n1\n192\n\n1\nno\nno\n\n0\n\n' + self.key
                if execute(['encfs', '--stdinpass', path, target], process_input=process_input) != 0:
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
        def fuse_umount(fs_type):
            path = self._sync_path(fs_type)
            if os.path.isdir(path):
                if os.path.ismount(path):
                    if execute(['fusermount', '-u', path]) != 0:
                        raise('unmounting %s at %s failed' % (fs_type, path))
                os.rmdir(path)
        if self.key:
            fuse_umount('encfs')
        if not self.is_local():
            fuse_umount('sshfs')
        self.mount_path = None
    
    def reverse_mount(self):
        """
        Mount the local directory with encfs in reverse mode.
        
        The remote directory must be encrypted and mounted.
        This is used for efficiently comparing encrypted file contents in case the remote directory is mounted over a network connection.
        """
        if self.reverse_mount_path != None:
            raise Exception('already reverse-mounted at %s' % self.reverse_mount_path)
        self.encfs_reverse = self._sync_path('encfs-reverse')
        if not os.path.ismount(self.encfs_reverse):
            if not os.path.exists(self.encfs_reverse):
                os.mkdir(self.encfs_reverse)
            if not hasattr(self, 'encfs_source'):
                raise Exception('remote must be mounted with encfs')
            env = {'ENCFS6_CONFIG':os.path.join(self.encfs_source, '.encfs6.xml')}
            if execute(['encfs', '--stdinpass', '--reverse', os.path.dirname(self.sync_dir), self.encfs_reverse], process_input=self.key, env=env) != 0:
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
        if not filenames:
            return []
        self._load_cache()
        cache_index = 0 if command == 'decrypt' else 1
        filenames = [fn.split(os.sep) for fn in filenames]
        uncached = [c for fn in filenames for c in fn if c not in self._cache[cache_index]]
        if uncached:
            process_input = '\n'.join(uncached)
            _, output = execute(['encfsctl', command, '--extpass=echo %s' % self.key, self.encfs_source], process_input=process_input, return_stdout=True)
            for c, mapped in zip(uncached, str(output, 'utf_8').split('\n')):
                self._cache[cache_index][c] = mapped
                self._cache[1 - cache_index][mapped] = c
        return [os.sep.join([self._cache[cache_index][c] for c in fn]) for fn in filenames]


class Repo:
    """
    Wrapper for collecting all files of a local or remote directory.
    
    Note that parts of this class are executed on the remote side and must therefore not reference any other parts of the code.
    """
    
    def __init__(self, source, *, preserve_links=False, exclude=None, include=None, rel_path='.'):
        """
        Create a directory wrapper.
        
        source: either a Remote object or a path referring to a local directory
        preserve_links: determines whether symbolic links are followed or not
        exclude: list or string of exclude patterns (optional, in case of a string, patterns are separated by ":")
        include: list or string of include-only patterns (optional, in case of a string, patterns are separated by ":")
        rel_path: relative path within the directory, all other files are ignored (optional)
        """
        self.source = source
        self.rel_path = rel_path
        self.preserve_links = preserve_links
        if exclude is None:
            self.exclude = []
        elif isinstance(exclude, str):
            self.exclude = exclude.split(':')
        else:
            self.exclude = exclude
        if include is None:
            self.include = []
        elif isinstance(include, str):
            self.include = include.split(':')
        else:
            self.include = include
        # remove leading slashes from include patterns
        self.include = [pattern[1:] if pattern[0] == '/' else pattern for pattern in self.include if pattern]
        # normalize patterns (remove trailing slashes etc.)
        self.exclude = [os.path.normpath(pattern) for pattern in self.exclude if pattern] + ['/.synkrotron']
        self.include = [os.path.normpath(pattern) for pattern in self.include if pattern]
        if isinstance(self.source, str):
            self.root = source # path
        else:
            self.root = source.mount_path # remote object
    
    def _remote_call(self, line):
        """
        Execute the given line of code on the remote machine and return the result.
        
        The whole class including all imports is transferred to the remote machine.
        """
        code = '\n'.join([l for l in inspect.getsource(sys.modules[__name__]).split('\n') if l.startswith('import ')])
        code += '\n' + inspect.getsource(Repo) + '\npickle.dump(%s, sys.stdout.buffer)' % line
        _, output = execute(['ssh', self.source.host, 'LC_CTYPE=en_US.utf-8 python3'], process_input=code, return_stdout=True)
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
            if self.preserve_links:
                st = os.lstat(file)
            else:
                st = os.stat(file)
            file_type = None
            if stat.S_ISDIR(st.st_mode):
                file_type = 'd'
            elif stat.S_ISREG(st.st_mode):
                file_type = 'f'
            if stat.S_ISLNK(st.st_mode):
                file_type = 'l'
            if file_type is None:
                raise Exception('unknown file type')
            return path, (file_type, st.st_size, st.st_mtime)
        base = os.path.join(self.root, self.rel_path)
        whitelist_dirs = set() # white-listed directories; avoid re-matching files within these directories
        if not os.path.exists(base):
            return # nothing to collect if base does not exist
        # check whether base (and thus everything) should be excluded:
        if list(self._ignore_files(self.rel_path, ['.'], whitelist_dirs)):
            return
        try:
            yield info(base)
        except:
            print('warning: ignoring file "%s" (unable to stat)' % os.path.normpath(base))
            return
        for dirpath, dirnames, filenames in os.walk(base, followlinks=not self.preserve_links):
            for names in (dirnames, filenames):
                names.sort()
                rel_dir = os.path.relpath(dirpath, self.root)
                for ign in reversed(list(self._ignore_files(rel_dir, names, whitelist_dirs))):
                    del names[bisect.bisect_left(names, ign)]
                for name in names:
                    try:
                        file = os.path.join(dirpath, name)
                        yield info(file)
                    except:
                        print('warning: ignoring file "%s" (unable to stat)' % os.path.normpath(file))
    
    def _collect_remote(self):
        def call(exclude, include, rel_path):
            return self._remote_call("list(Repo('''%s''',preserve_links=%d,exclude=%s,include=%s,rel_path='''%s''')._collect_local())"
                                      % (self.source.root, self.preserve_links, exclude, include, rel_path))
        if self.source.key:
            # wildcards can not be applied to encrypted names, so filtering is done in two steps (first without wildcards, then with wildcards)
            exclude_fixed = [pattern for pattern in self.exclude if '*' not in pattern and '?' not in pattern] # excludes without wildcards
            include_fixed = [pattern for pattern in self.include if '*' not in pattern and '?' not in pattern] # includes without wildcards
            # encrypt names in a single call since this is an expensive operation
            encrypted_names = self.source.encrypt_names(exclude_fixed + include_fixed + [self.rel_path])
            rel_path_encrypted = encrypted_names[-1]
            exclude_encrypted = encrypted_names[:len(exclude_fixed)]
            include_encrypted = encrypted_names[len(exclude_fixed):-1]
            exclude_encrypted.append('/.encfs6.xml')
            exclude_encrypted.append('/clear')
            stats_encrypted = call(exclude_encrypted, include_encrypted, rel_path_encrypted)
            paths = self.source.decrypt_names([s[0] for s in stats_encrypted])
            stats = dict()
            excluded = set()
            whitelist_dirs = set()
            # files must be in top-down order
            for path, stat in zip(paths, stats_encrypted):
                skip = False
                for e in excluded:
                    if path.startswith(e):
                        skip = True
                        break
                if skip:
                    continue
                for _ in self._ignore_files(os.path.dirname(path), [os.path.basename(path)], whitelist_dirs):
                    excluded.add(path)
                    break
                else:
                    stats[path] = stat[1]
            return stats
        else:
            return call(self.exclude, self.include, self.rel_path)
    
    def _ignore_files(self, dirpath, filenames, whitelist_dirs=None):
        """Return all filenames that should be ignored based on exclude and include patterns."""
        if not self.exclude and not self.include:
            return
        def match(path, pattern):
            """Match a pattern against a path."""
            if pattern.startswith('/'): # anchored: match the whole path starting from the repository root
                if fnmatch.fnmatch(path, pattern[1:]):
                    return True
            else: # not anchored: only match the last component of the path
                tmp_path, tail = os.path.split(path)
                components = [tail]
                for _ in range(pattern.count('/')):
                    tmp_path, tail = os.path.split(tmp_path)
                    components.append(tail)
                if fnmatch.fnmatch('/'.join(reversed(components)), pattern):
                    return True
            return False
        for fn in filenames:
            path = os.path.normpath(os.path.join(dirpath, fn))
            if path == '.':
                continue # always include the root directory
            ignore = False
            # match excludes
            for pattern in self.exclude:
                if match(path, pattern):
                    yield fn
                    ignore = True
                    break
            if ignore:
                continue
            # match includes
            if self.include:
                ignore = True
                if whitelist_dirs is not None:
                    for wl in whitelist_dirs:
                        if path.startswith(wl):
                            ignore = False
                            break
                    if not ignore:
                        continue
                path_depth = path.count('/')
                for pattern in self.include:
                    # match pattern partially in case the pattern is deeper than the path
                    # (e.g., match only with "foo" if the pattern is "foo/bar" and the path does not contain any slashes)
                    pattern_depth = pattern.count('/')
                    if pattern_depth > path_depth:
                        partial_pattern = '/'.join(pattern.split('/')[:path_depth + 1])
                    else:
                        partial_pattern = pattern
                    if match(path, '/' + partial_pattern): # match (anchored) pattern
                        if whitelist_dirs is not None and partial_pattern == pattern:
                            whitelist_dirs.add(path)
                        ignore = False
                        break
                if ignore:
                    yield fn
    
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
            return md5.hexdigest()


class DiffStatistics:
    """Compute and show cumulative diff statistics."""
    
    def __init__(self, diff):
        """Compute statistics from a Diff object."""
        self.pull_count = self.pull_size = self.push_count = self.push_size = self.rest_count = self.rest_size_local = self.rest_size_remote = 0
        if diff is None:
            return
        for _, stat, operation, _ in diff.list:
            if operation == 'push':
                if stat[0] == 'f':
                    self.push_size += stat[1]
                self.push_count += 1
            elif operation == 'pull':
                if stat[0] == 'f':
                    self.pull_size += stat[1]
                self.pull_count += 1
            else:
                if stat[0][0] == 'f':
                    self.rest_size_local += stat[0][1]
                if stat[1][0] == 'f':
                    self.rest_size_remote += stat[1][1]
                self.rest_count += 1
    
    def __add__(self, other):
        if not isinstance(other, DiffStatistics):
            raise TypeError
        ds = DiffStatistics(None)
        ds.pull_count = self.pull_count + other.pull_count
        ds.pull_size = self.pull_size + other.pull_size
        ds.push_count = self.push_count + other.push_count
        ds.push_size = self.push_size + other.push_size
        ds.rest_count = self.rest_count + other.rest_count
        ds.rest_size_local = self.rest_size_local + other.rest_size_local
        ds.rest_size_remote = self.rest_size_remote + other.rest_size_remote
        return ds
    
    def show(self):
        """Print the computed diff statistics."""
        if self.pull_count:
            print('pull: %d files (%s)' % (self.pull_count, Diff._format_size(self.pull_size)))
        if self.push_count:
            print('push: %d files (%s)' % (self.push_count, Diff._format_size(self.push_size)))
        if self.rest_count:
            print('rest: %d files (local: %s, remote: %s)' % (self.rest_count, Diff._format_size(self.rest_size_local), Diff._format_size(self.rest_size_remote)))
    

class Diff:
    """Compare and copy files between two directories."""
    
    def __init__(self, repo_local, repo_remote, *, ignore_time=False, content=False, modify_window=0):
        """
        Create a Diff object for generating a list of all differing files.
        
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
        self.list = None
        
    def compute(self, show=False, show_verbose=False):
        """
            Compute and return a list of all differing files.
            
            The file list is stored in 'self.list'.
            If 'show' is set, all differing items are printed to stdout.
            If 'show_verbose' is set in addition to 'show', additional information about the cause of the detected difference is printed.
        """
        self.list = []
        with futures.ThreadPoolExecutor(max_workers=2) as executor:
            stats_local, stats_remote = executor.map(Repo.collect, [self.repo_local, self.repo_remote])
        if show and show_verbose:
            print('Comparing %d local files against %d remote files...' % (len(stats_local), len(stats_remote)))
        for file_local, stat_local in sorted(stats_local.items()):
            if file_local in stats_remote:
                cmp = self._compare_stats(stat_local, stats_remote[file_local], file_local)
                if cmp:
                    self.list.append((file_local,) + cmp)
                    if show:
                        Diff._show_item(*self.list[-1], show_verbose=show_verbose)
            else:
                self.list.append((file_local, stat_local, 'push', 'remote file does not exist'))
                if show:
                    Diff._show_item(*self.list[-1], show_verbose=show_verbose)
        pulls = [(f, stats_remote[f], 'pull', 'local file does not exist') for f in sorted(set(stats_remote.keys()).difference(stats_local.keys()))]
        if show:
            for item in pulls:
                Diff._show_item(*item, show_verbose=show_verbose)
        self.list.extend(pulls)
        return self.list
    
    @staticmethod
    def _show_item(file, stat, operation, verbose_info, show_verbose):
        if not show_verbose:
            verbose_info = ''
        else:
            verbose_info = ' [%s]' % verbose_info
        if operation == 'push':
            if stat[0] == 'f':
                print('--> %s (%s)%s' % (file, Diff._format_size(stat[1]), verbose_info))
            else:
                print('--> %s%s' % (file, verbose_info))
        elif operation == 'pull':
            if stat[0] == 'f':
                print('<-- %s (%s)%s' % (file, Diff._format_size(stat[1]), verbose_info))
            else:
                print('<-- %s%s' % (file, verbose_info))
        else:
            print('<-> %s (%s/%s)%s' % (file, Diff._format_size(stat[0][1]), Diff._format_size(stat[1][1]), verbose_info))
    
    @staticmethod
    def _format_size(byte_size):
        """Format file size."""
        units = ['T', 'G', 'M', 'K', '']
        while len(units) and byte_size >= 1000:
            byte_size /= 1024
            units.pop()
        return '%.1f %sB' % (round(byte_size, 1), units[-1])
    
    def _compare_stats(self, stat_src, stat_dst, file):
        if stat_src[0] == stat_dst[0] == 'd':
            return None # do not compare directories
        # compare time
        diff_time = int(stat_src[2] - stat_dst[2]) # ignore fractional time information
        if abs(diff_time) < self.modify_window:
            diff_time = 0
        if diff_time < 0:
            time_cmp = stat_dst, 'pull', 'remote file is newer'
        elif diff_time > 0:
            time_cmp = stat_src, 'push', 'local file is newer'
        else:
            time_cmp = (stat_src, stat_dst), None, 'files have the same timestamp'
        if not self.ignore_time and diff_time:
            return time_cmp
        # compare type
        diff_type = ord(stat_src[0]) - ord(stat_dst[0])
        if diff_type:
            file_types = {'d': 'directory', 'f': 'regular file', 'l': 'symbolic link'}
            return (time_cmp[0], 
                    time_cmp[1] if diff_time else 'type', 
                    'files have different types (local: %s, remote: %s); %s' % (file_types[stat_src[0]], file_types[stat_dst[0]], time_cmp[2]))
        # compare size
        diff_size = stat_src[1] - stat_dst[1]
        if diff_size:
            return (time_cmp[0], 
                    time_cmp[1] if diff_time else 'size', 
                    'files have different sizes (local: %s, remote: %s); %s' % (file_types[stat_src[0]], file_types[stat_dst[0]], time_cmp[2]))
        # compare content
        if self.content:
            if not isinstance(self.repo_remote.source, str) and not self.repo_remote.source.is_local() and self.repo_remote.source.key:
                file_encrypted = self.repo_remote.source.encrypt_names([file])[0]
                file_local = os.path.join(self.repo_remote.source.encfs_reverse, file_encrypted)
            else:
                file_local = file
            with futures.ThreadPoolExecutor(max_workers=2) as executor:
                hash_local = executor.submit(self.repo_local.file_hash, file_local)
                hash_remote = executor.submit(self.repo_remote.file_hash, file)
            if hash_local.result() != hash_remote.result():
                return (time_cmp[0], 
                        time_cmp[1] if diff_time else 'content', 
                        'files have different content; %s\n    local file hash:  %s\n    remote file hash: %s' % (time_cmp[2], hash_local.result(), hash_remote.result()))
        return None
    
    def pull(self, *, simulate=False, delete=False):
        """
        Pull differing files from the remote directory to the local directory using rsync.
        
        simulate: run rsync in simulation mode
        delete: delete files that exist locally but not on the remote side
        """
        self._copy(operation='pull', simulate=simulate, delete=delete)
    
    def push(self, *, simulate=False, delete=False, delta=None, write_delta_config=True):
        """
        Push differing files from the local directory to the remote directory using rsync.
        
        simulate: run rsync in simulation mode
        delete: delete files that exist on the remote side but not locally
        delta: copy all differing files to this path instead of copying them to the remote directory
        write_delta_config: write configuration in delta mode
        """
        if delta:
            if ':' in delta:
                raise Exception('delta directory must be local')
            remote = self.repo_remote.source
            if not isinstance(remote, Remote):
                raise TypeError('"remote" must be of type "Remote"')
            if remote.key:
                # copy '.encfs6.xml' to the delta directory so the salt is the same as for the remote location
                # Note: this does not work if delta has to be mounted with sshfs first, hence the check above
                shutil.copy(os.path.join(remote.encfs_source, '.encfs6.xml'), os.path.join(delta, '.encfs6.xml'))
            delta_remote = Remote(remote.name + '-delta', delta, remote.sync_dir, key=remote.key)
            delta_remote.mount() # mount with encfs if key is set
            delta_path = delta_remote.mount_path
        else:
            delta_path = None
        self._copy(operation='push', simulate=simulate, delete=delete, delta=delta_path)
        if delta:
            delta_remote.umount()
            if write_delta_config:
                # create '.synkrotron' files in delta directory
                sync_dir = os.path.join(delta, '.synkrotron')
                os.mkdir(sync_dir)
                config_file = os.path.join(sync_dir, 'config')
                Config.write_delta_config(name=remote.name,
                                          location=remote.location, 
                                          ignore_time=self.ignore_time, 
                                          preserve_links=self.repo_remote.preserve_links, 
                                          modify_window=self.modify_window, 
                                          content=self.content, 
                                          config_file=config_file)
    
    def _copy(self, *, operation, simulate=False, delete=False, delta=None):
        """Copy files from src to dst using rsync."""
        if self.list is None:
            self.compute()
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
        if not file_list:
            return
        options = []
        if simulate:
            options.append('--dry-run')
        if not self.repo_local.preserve_links:
            options.append('--copy-links')
        if delta:
            dst = delta
        execute(['rsync', '-ahuR', '--files-from=-', '--progress', '--partial-dir', '.rsync-partial'] + options + ['.', dst], cwd=src, process_input=file_list)
    

class Config:
    """Find relevant paths and read the configuration file."""
    
    _defaults = {'clear': '',
                 'content': '0',
                 'delete': '0',
                 'exclude': '',
                 'ignore_time': '0',
                 'include': '',
                 'key': '',
                 'location': '',
                 'modify_window': '0',
                 'mount_point': '',
                 'preserve_links': '0'}
     
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
    def write_delta_config(*, name, location, ignore_time, preserve_links, modify_window, content, config_file):
        """ Write config file to delta location."""
        config = configparser.ConfigParser()
        config.add_section(name)
        config.set(name, 'location', location)
        config.set(name, 'ignore_time', str(ignore_time))
        config.set(name, 'preserve_links', str(preserve_links))
        config.set(name, 'modify_window', str(modify_window))
        config.set(name, 'content', str(content))
        with io.open(config_file, 'w') as f:
            config.write(f)
    
    @staticmethod
    def init_remote(remote):
        """Create or update a remote directory configuration."""
        sync_dir = os.path.join(os.getcwd(), '.synkrotron')
        if not os.path.exists(sync_dir):
            os.mkdir(sync_dir)
        config_file = os.path.join(sync_dir, 'config')
        if not os.path.exists(config_file):
            print('Creating new configuration')
            comments = '\n'.join(('# Synkrotron configuration file defining remote locations.',
                                  '# ',
                                  '# Each remote location is defined in a separate section starting with [<remote-name>].',
                                  '# A section name identifies the remote location must be unique.'
                                  '# The location itself is specified using the syntax "HOST:PATH" where "HOST:" is optional.',
                                  '# ',
                                  '# In addition, the following options can be specified in a section:',
                                  '#   clear:          List of files (separated by ":") to be excluded from encryption if key is set.',
                                  '#                   Filenames are relative with respect to the root of the synchronization directory.',
                                  '#                   Leading slashes are ignored.',
                                  '#   content:        Additionally compare files based on hashes of their contents if set to "1" (default is "0").',
                                  '#                   Equivalent to using the "-c" command line switch.',
                                  '#                   [Warning: Computing content hashes comes with a significant performance penalty.]',
                                  '#   delete:         Delete all files at the destination that do not exist at the source location if set to "1" (default is "0").',
                                  '#                   Equivalent to using the "-d" command line switch.',
                                  '#   exclude:        List of file patterns (separated by ":") for excluding files from the synchronization.',
                                  '#                   Supports wildcard characters like "?" and "*".',
                                  '#                   A "/" at the beginning of a pattern means it is matched starting from the root of the location.',
                                  '#                   Trailing slashes are ignored.',
                                  '#   preserve_links: Do not follow symbolic links during synchronization if set to "1" (default is "0").',
                                  '#   ignore_time:    Ignore modification timestamps when comparing files if set to "1" (default is "0").',
                                  '#   include:        Include only the listed files (separated by ":"), i.e., exclude all other files.',
                                  '#                   Patterns are specified similar to exclude except that they are always matched starting from the root.',
                                  '#                   Therefore, leading slashes can be omitted.',
                                  '#                   If a pattern matches a directory, all files within the directory are included as well.',
                                  '#                   Note that exclude pattern take precedence over include patterns.',
                                  '#   key:            Password of arbitrary length for encrypting files at the remote location.',
                                  '#                   Equivalent to using the "-i" command line switch.',
                                  '#   modify_window:  Maximum allowed modification time difference (in seconds) for files to be considered unchanged (default is "0").',
                                  '#   mount_point:    Mount the remote location at the specified mount point instead of mounting it in the ".synkrotron" directory.',
                                  '# ',
                                  '# Example:',
                                  '# [backup]',
                                  '# location: foo.org:/some/path',
                                  '# key: some_passphrase',
                                  '# exclude: *.log:*.bak',
                                  '# clear: public_dir:data/public_file'
                                  '# ',
                                  ''))
            with io.open(config_file, 'w') as f:
                f.write(comments)
        else:
            print('Updating existing configuration')
        with io.open(config_file, 'a') as f:
            f.write('\n[%s]\nlocation: <HOST>:<PATH>\n' % remote)
        print('Please edit ".synkrotron/config" to configure the new remote location.')
    

def execute(args, *, process_input=None, cwd=None, return_stdout=False, env=None):
    """
    Run an external program and return its exit code and, optionally, its output.
    
    process_input: a string passed to stdin of the program (optional)
    cwd: working directory of the program (optional)
    return_stdout: determines whether the program output should be returned (default is False)
    env: set environment variables for the program (optional)
    """
    if env:
        env.update(os.environ)
    process = subprocess.Popen(args, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE if return_stdout else None, env=env)
    if process_input and isinstance(process_input, str): # convert string input to bytes
        if process_input[-1] == '\n':
            process_input = process_input.encode()
        else:
            process_input = (process_input + '\n').encode()
    stdout, _ = process.communicate(input=process_input)
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
    parser.add_argument('--delta', dest='delta', help='push only changes to the specified directory')
    parser.add_argument('-c', '--content', action='store_true', help='compare file contents in addition to size and modification time')
    parser.add_argument('-v', '--verbose', action='store_true', help='print additional diff information')
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
            # initialize remote location and exit
            Config.init_remote(args.remote)
            return
        config = Config() # read configuration
        if args.remote not in config.remotes:
            raise Exception('unknown remote name "%s"' % args.remote)
        remote_config = config.remotes[args.remote]
        # create remote location wrapper
        remote = Remote(args.remote, remote_config['location'], config.sync_dir, key=remote_config['key'], mount_point=remote_config['mount_point'])
        if args.command == 'umount':
            # unmount remote location and exit
            remote.umount()
            return
        remote.mount() # mount remote location
        if args.command == 'mount':
            # exit after mounting
            return
        # set options
        clear_paths = remote_config['clear']
        content = args.content or remote_config['content']
        delete = args.delete or remote_config['delete']
        exclude = remote_config['exclude']
        ignore_time = args.ignore_time or remote_config['ignore_time']
        include = remote_config['include']
        modify_window = remote_config['modify_window']
        preserve_links = remote_config['preserve_links']
        # restrict synchronization to rel_path:
        if args.path:
            if args.path[0] == '/':
                print('warning: removing leading "/" from path argument')
                args.path = args.path[1:]
            rel_path = os.path.normpath(os.path.join(config.rel_cwd, args.path))
        else:
            rel_path = config.rel_cwd
        if remote.key and clear_paths:
            # exclude (absolute) clear paths in case encryption is used
            if exclude:
                exclude += ':'
            exclude_local = exclude + ':'.join(['/' + p for p in clear_paths.split(':')])
        else:
            exclude_local = exclude
        if content and remote.key:
            # reverse mount for encrypted conntent diff
            remote.reverse_mount()
        # create Repo objects and compute diff
        repo_local = Repo(config.root, preserve_links=preserve_links, exclude=exclude_local, include=include, rel_path=rel_path)
        repo_remote = Repo(remote, preserve_links=preserve_links, exclude=exclude, include=include, rel_path=rel_path)
        diff_statistics = None
        def process_command(diff, write_delta_config):
            nonlocal diff_statistics
            # perform the reuested operation on a diff object
            diff.compute(args.command == 'diff', args.verbose)
            if args.command == 'diff':
                if diff_statistics is None:
                    diff_statistics = DiffStatistics(diff)
                else:
                    diff_statistics += DiffStatistics(diff)
            if args.command == 'pull':
                diff.pull(simulate=args.simulate, delete=delete)
            elif args.command == 'push':
                diff.push(simulate=args.simulate, delete=delete, delta=args.delta, write_delta_config=write_delta_config)
        process_command(Diff(repo_local, repo_remote, ignore_time=ignore_time, content=content, modify_window=modify_window), True)
        if content and remote.key:
            # unmount (reverse) after encrypted conntent diff
            remote.reverse_umount()
        if remote.key and clear_paths:
            # process unencrypted paths
            for clear_path in clear_paths.split(':'):
                clear_path = os.path.normpath(clear_path) # remove trailing "/" etc.
                if clear_path.startswith('..'):
                    raise Exception(print('clear option "%s" points outside of the main directory' % clear_path))
                if clear_path.startswith('/'):
                    # ignore leading slashes
                    clear_path = clear_path[1:]
                rel_clear_path = clear_path
                if rel_path != '.' and not clear_path.startswith(rel_path):
                    if rel_path.startswith(clear_path):
                        rel_clear_path = rel_path
                    else:
                        continue # omit if rel_path is outside of clear_path
                if args.verbose:
                    print('processing unencrypted files at "%s"' % clear_path)
                # store clear files in a separate directory in order to avoid name clashes with encrypted files:
                clear_root = os.path.join(remote.encfs_source, 'clear')
                if not os.path.exists(clear_root):
                    os.mkdir(clear_root)
                repo_local_clear = Repo(config.root, preserve_links=preserve_links, exclude=exclude, include=include, rel_path=rel_clear_path)
                remote_clear = Remote('', clear_root, config.sync_dir)
                remote_clear.mount() # does nothing but setting the mount path
                repo_remote_clear = Repo(remote_clear, preserve_links=preserve_links, exclude=exclude, include=include, rel_path=rel_clear_path)
                process_command(Diff(repo_local_clear, repo_remote_clear, ignore_time=ignore_time, content=content, modify_window=modify_window), False)
        if args.command == 'diff':
            diff_statistics.show()
        if args.umount:
            remote.umount()
        remote.save_cache()
    except Exception as e:
        print('error: ' + str(e))


if __name__ == '__main__':
    main()
