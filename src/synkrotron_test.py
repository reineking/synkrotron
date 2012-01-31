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
Unit tests for "synkrotron.py".
"""

import configparser
import io
import synkrotron
from synkrotron import Config, Diff, DiffStatistics, Remote, Repo
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


class TestSynkrotron(unittest.TestCase):
    
    def _populate(self, dirpath):
        if not os.path.exists(dirpath):
            os.mkdir(dirpath)
        with io.open(os.path.join(dirpath, 'file_ä'), 'w') as f:
            f.write('content')
        os.mkdir(os.path.join(dirpath, 'dir'))
        with io.open(os.path.join(dirpath, 'dir', 'file_ä'), 'w') as f:
            f.write('content2')
    
    def _fix_mtime(self, path, mtime=0):
        os.utime(path, (mtime, mtime))
        for root, dirs, files in os.walk(path):
            try:
                del dirs[dirs.index('.synkrotron')]
            except ValueError:
                pass
            for name in dirs + files:
                os.utime(os.path.join(root, name), (mtime, mtime))
    
    def setUp(self):
        self.test_dir = os.path.join(tempfile.gettempdir(), 'synkrotron-test')
        if not os.path.exists(self.test_dir):
            os.mkdir(self.test_dir)
        self.dir = tempfile.mkdtemp(dir=self.test_dir)
        def create_local(name, **kwargs):
            base_dir = os.path.join(self.dir, name)
            sync_dir = os.path.join(base_dir, '.synkrotron')
            config_file = os.path.join(sync_dir, 'config')
            os.makedirs(sync_dir)
            config = configparser.ConfigParser()
            config['remote'] = kwargs
            with io.open(config_file, 'w') as f:
                config.write(f)
            return base_dir, sync_dir, config_file
        self.remote = os.path.join(self.dir, 'remote')
        os.mkdir(self.remote)
        self.local1_base, self.local1_ms, self.local1_config = create_local('local1', location=self.remote)
        self.remote_host = 'localhost:' + self.remote
        self.local2_base, self.local2_ms, self.local2_config = create_local('local2', location=self.remote_host)
        self.key = 'WeakPassword'
        self.mount_point = os.path.join(self.dir, 'mount_point')
        self.local3_base, self.local3_ms, self.local3_config = create_local('local3', location=self.remote_host, key=self.key, mount_point=self.mount_point)
        self.local4_base, self.local4_ms, self.local4_config = create_local('local4', location=self.remote_host, key=self.key, clear='dir:clear')
        self.delta = os.path.join(self.dir, 'delta')
        os.mkdir(self.delta)
    
    def tearDown(self):
        # unmount anything that is still mounted in self.dir
        for path, _, _ in os.walk(self.test_dir): 
            if os.path.ismount(path):
                subprocess.call(['fusermount', '-u', path])
        # delete it all
        shutil.rmtree(self.dir)
    

class TestDiff(TestSynkrotron):
    
    def _filter(self, diff):
        if diff.list is None:
            diff.compute()
        return tuple((d[0], d[2]) for d in diff.list)
    
    def test_diff(self):
        self._populate(self.local1_base)
        r1 = Repo(self.local1_base)
        r2 = Repo(self.local2_base)
        self.assertEqual((('dir', 'push'), ('dir/file_ä', 'push'), ('file_ä', 'push')), self._filter(Diff(r1, r2)))
        self._populate(self.local2_base)
        self._fix_mtime(self.local1_base)
        self._fix_mtime(self.local2_base)
        self.assertEqual((), tuple(Diff(r1, r2).compute()))
        os.remove(os.path.join(self.local1_base, 'file_ä'))
        os.remove(os.path.join(self.local1_base, 'dir', 'file_ä'))
        self.assertEqual((('dir/file_ä', 'pull'), ('file_ä', 'pull')), self._filter(Diff(r1, r2)))
        r1 = Repo(self.local1_base, rel_path='dir')
        r2 = Repo(self.local2_base, rel_path='dir')
        self.assertEqual((('dir/file_ä', 'pull'),), self._filter(Diff(r1, r2)))
    
    def test_diff_exclude(self):
        self._populate(self.local1_base)
        r1 = Repo(self.local1_base, exclude=['dir'])
        r2 = Repo(self.local2_base, exclude=['dir'])
        self.assertEqual((('file_ä', 'push'),), self._filter(Diff(r1, r2)))
        r1 = Repo(self.local1_base, exclude=['dir/file_ä'])
        r2 = Repo(self.local2_base, exclude=['dir/file_ä'])
        self.assertEqual((('dir', 'push'), ('file_ä', 'push')), self._filter(Diff(r1, r2)))
        r1 = Repo(self.local1_base, exclude=['/file_ä'])
        r2 = Repo(self.local2_base, exclude=['/file_ä'])
        self.assertEqual((('dir', 'push'), ('dir/file_ä', 'push')), self._filter(Diff(r1, r2)))
    
    def test_diff_content(self):
        self._populate(self.local1_base)
        self._populate(self.local2_base)
        self._fix_mtime(self.local1_base)
        self._fix_mtime(self.local2_base)
        diff = Diff(Repo(self.local1_base), Repo(self.local2_base), content=True)
        self.assertEqual((), self._filter(diff))
        with io.open(os.path.join(self.local1_base, 'dir', 'file_ä'), 'w') as f:
            f.write('xontent2')
        self._fix_mtime(self.local1_base)
        diff = Diff(Repo(self.local1_base), Repo(self.local2_base), content=True)
        self.assertEqual((('dir/file_ä', 'content'),), self._filter(diff))
    
    def test_diff_content_sshfs(self):
        remote = Remote('remote', self.remote_host, self.local1_ms)
        remote.mount()
        self._populate(self.local1_base)
        self._populate(self.remote)
        self._fix_mtime(self.local1_base)
        self._fix_mtime(self.remote)
        diff = Diff(Repo(self.local1_base), Repo(remote), content=True)
        self.assertEqual((), self._filter(diff))
        f_src = os.path.join(self.local1_base, 'dir', 'file_ä')
        f_dst = os.path.join(self.remote, 'dir', 'file_ä')
        with io.open(f_src, 'w') as f:
            f.write('xontent2')
        os.utime(f_src, (os.path.getatime(f_dst), os.path.getmtime(f_dst)))
        diff = Diff(Repo(self.local1_base), Repo(remote), content=True)
        self.assertEqual((('dir/file_ä', 'content'),), self._filter(diff))
        remote.umount()
    
    def test_diff_content_sshfs_encfs(self):
        remote = Remote('remote', self.remote_host, self.local1_ms, key=self.key)
        remote.mount()
        remote.reverse_mount()
        self._populate(self.local1_base)
        self._populate(remote.encfs_destination)
        self._fix_mtime(self.local1_base)
        self._fix_mtime(remote.encfs_destination)
        diff = Diff(Repo(self.local1_base), Repo(remote), content=True)
        self.assertEqual((), self._filter(diff))
        f_local = os.path.join(self.local1_base, 'dir', 'file_ä')
        f_remote = os.path.join(remote.encfs_destination, 'dir', 'file_ä')
        with io.open(f_local, 'w') as f:
            f.write('xontent2')
        os.utime(f_local, (os.path.getatime(f_remote), os.path.getmtime(f_remote)))
        diff = Diff(Repo(self.local1_base), Repo(remote), content=True)
        self.assertEqual((('dir/file_ä', 'content'),), self._filter(diff))
        remote.reverse_umount()
        remote.umount()
    
    def test_pull(self):
        self._populate(self.remote)
        Diff(Repo(self.local1_base), Repo(self.remote)).pull()
        self.assertEqual(3, len(os.listdir(self.local1_base)))
    
    def test_push(self):
        self._populate(self.local1_base)
        Diff(Repo(self.local1_base), Repo(self.remote)).push()
        self.assertEqual(2, len(os.listdir(self.remote)))
    
    def test_pull_path(self):
        self._populate(self.remote)
        Diff(Repo(self.local1_base, rel_path='dir/file_ä'), Repo(self.remote, rel_path='dir/file_ä')).pull()
        self.assertEqual(2, len(os.listdir(self.local1_base)))
        self.assertEqual(('file_ä',), tuple(os.listdir(os.path.join(self.local1_base, 'dir'))))
    
    def test_push_path(self):
        self._populate(self.local1_base)
        Diff(Repo(self.local1_base, rel_path='dir'), Repo(self.remote, rel_path='dir')).push()
        self.assertEqual(('dir',), tuple(os.listdir(self.remote)))
        self.assertEqual(('file_ä',), tuple(os.listdir(os.path.join(self.remote, 'dir'))))
    
    def test_pull_sshfs(self):
        self._populate(self.remote)
        remote = Remote('remote', self.remote_host, self.local1_ms)
        remote.mount()
        Diff(Repo(self.local1_base), Repo(remote)).pull()
        self.assertEqual(3, len(os.listdir(self.local1_base)))
        remote.umount()
    
    def test_push_sshfs_encfs(self):
        self._populate(self.local1_base)
        remote = Remote('remote', self.remote_host, self.local1_ms, key=self.key)
        remote.mount()
        Diff(Repo(self.local1_base), Repo(remote)).push()
        self.assertEqual(3, len(os.listdir(self.remote)))
        remote.umount()
    
    def test_push_exclude1(self):
        self._populate(self.local1_base)
        Diff(Repo(self.local1_base, exclude=['/file_ä']), Repo(self.remote, exclude=['/file_ä'])).push()
        self.assertEqual(('dir',), tuple(os.listdir(self.remote)))
        self.assertEqual(('file_ä',), tuple(os.listdir(os.path.join(self.remote, 'dir'))))
    
    def test_push_exclude2(self):
        self._populate(self.local1_base)
        Diff(Repo(self.local1_base, exclude=['dir/file_ä']), Repo(self.remote, exclude=['dir/file_ä'])).push()
        self.assertEqual(2, len(os.listdir(self.remote)))
        self.assertEqual(0, len(os.listdir(os.path.join(self.remote, 'dir'))))
    
    def test_push_path_exclude1(self):
        self._populate(self.local1_base)
        Diff(Repo(self.local1_base, exclude=['dir/file_ä'], rel_path='dir'), Repo(self.remote, exclude=['dir/file_ä'], rel_path='dir')).push()
        self.assertEqual(('dir',), tuple(os.listdir(self.remote)))
        self.assertEqual(0, len(os.listdir(os.path.join(self.remote, 'dir'))))
    
    def test_push_content(self):
        self._populate(self.local1_base)
        self._populate(self.local2_base)
        self.assertEqual(0, len(Diff(Repo(self.local1_base), Repo(self.local2_base), content=True).compute()))
        with io.open(os.path.join(self.local1_base, 'dir', 'file_ä'), 'w') as f:
            f.write('xontent2')
        self._fix_mtime(self.local1_base)
        self._fix_mtime(self.local2_base)
        diff = Diff(Repo(self.local1_base), Repo(self.local2_base), content=True)
        self.assertEqual((('dir/file_ä', 'content'),), self._filter(diff))
        diff.push()
        diff = Diff(Repo(self.local1_base), Repo(self.local2_base), content=True)
        self.assertEqual(0, len(diff.compute()))
    
    def test_push_simulate(self):
        self._populate(self.local1_base)
        Diff(Repo(self.local1_base), Repo(self.remote)).push(simulate=True)
        self.assertEqual(0, len(os.listdir(self.remote)))
    
    def test_pull_delete_file(self):
        self._populate(self.remote)
        self._populate(self.local1_base)
        os.remove(os.path.join(self.local1_base, 'file_ä'))
        Diff(Repo(self.remote), Repo(self.local1_base)).pull(delete=True)
        self.assertListEqual(['dir'], os.listdir(self.remote))
    
    def test_push_delete_dir(self):
        self._populate(self.local1_base)
        self._populate(self.remote)
        shutil.rmtree(os.path.join(self.local1_base, 'dir'))
        Diff(Repo(self.local1_base), Repo(self.remote)).push(delete=True)
        self.assertListEqual(['file_ä'], os.listdir(self.remote))
    
    def test_push_delta(self):
        self._populate(self.local1_base)
        self._populate(self.remote)
        os.remove(os.path.join(self.remote, 'file_ä'))
        remote = Remote('remote', self.remote, self.local1_ms)
        remote.mount()
        Diff(Repo(self.local1_base), Repo(remote)).push(delta=self.delta)
        remote.umount()
        self.assertListEqual(['.synkrotron', 'file_ä'], os.listdir(self.delta))
    
    def test_compute_show(self):
        self._populate(self.local1_base)
        os.mkdir(os.path.join(self.remote, 'test'))
        with io.open(os.path.join(self.remote, 'file_ä'), 'w') as f:
            f.write('xontent')
        stdout = sys.stdout
        output = io.StringIO()
        sys.stdout = output
        diff = Diff(Repo(self.local1_base), Repo(self.remote), content=True)
        diff.compute(show=True)
        DiffStatistics(diff).show()
        expected = '\n'.join(('--> dir',
                              '--> dir/file_ä (8.0 B)',
                              '<-> file_ä (7.0 B/7.0 B)',
                              '<-- test',
                              'pull: 1 files (0.0 B)',
                              'push: 2 files (8.0 B)',
                              'rest: 1 files (local: 7.0 B, remote: 7.0 B)',
                              ''))
        self.assertEqual(expected, output.getvalue())
        output = io.StringIO()
        sys.stdout = output
        diff.compute(show=True, show_verbose=True)
        DiffStatistics(diff).show()
        expected = '\n'.join(('Comparing 4 local files against 3 remote files...',
                              '--> dir [remote file does not exist]',
                              '--> dir/file_ä (8.0 B) [remote file does not exist]',
                              '<-> file_ä (7.0 B/7.0 B) [files have different content; files have the same timestamp',
                              '    local file hash:  9a0364b9e99bb480dd25e1f0284c8555',
                              '    remote file hash: d57830865b3020a563b955b27320c31e]',
                              '<-- test [local file does not exist]',
                              'pull: 1 files (0.0 B)',
                              'push: 2 files (8.0 B)',
                              'rest: 1 files (local: 7.0 B, remote: 7.0 B)',
                              ''))
        self.assertEqual(expected, output.getvalue())
        sys.stdout = stdout
    

class TestRepo(TestSynkrotron):
    
    def test_exclude(self):
        self.assertEqual(('/.synkrotron',), tuple(Repo(self.local1_base).exclude))
        self.assertEqual(('/.synkrotron', 'dir'), tuple(Repo(self.local1_base, exclude=['dir']).exclude))
    
    def test_ignore_files(self):
        self.assertEqual((), tuple(Repo(self.local1_base)._ignore_files('.', ['a', 'ax'])))
        self.assertEqual(('a',), tuple(Repo(self.local1_base, exclude=['a'])._ignore_files('.', ['a', 'ax'])))
        self.assertEqual(('a', 'ax'), tuple(Repo(self.local1_base, exclude=['a*'])._ignore_files('.', ['a', 'ax'])))
        self.assertEqual(('a',), tuple(Repo(self.local1_base, exclude=['/a'])._ignore_files('.', ['a', 'ax'])))
        self.assertEqual(('a', 'ax'), tuple(Repo(self.local1_base, exclude=['a*'])._ignore_files('dir', ['a', 'ax'])))
        self.assertEqual((), tuple(Repo(self.local1_base, exclude=['/a'])._ignore_files('dir', ['a', 'ax'])))
        self.assertEqual(('a',), tuple(Repo(self.local1_base, exclude=['dir/a'])._ignore_files('dir', ['a', 'ax'])))
        self.assertEqual(('a',), tuple(Repo(self.local1_base, exclude=['/dir/a'])._ignore_files('dir', ['a', 'ax'])))
        self.assertEqual((), tuple(Repo(self.local1_base, exclude=['/dir/a/x/y'])._ignore_files('dir', ['a', 'ax'])))
    
    def test_collect(self):
        self._populate(self.local1_base)
        files = Repo(self.local1_base).collect()
        self.assertEqual(4, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        self.assertEqual(('f', 7), files['file_ä'][:2])
        self.assertEqual('d', files['dir'][0])
    
    def test_collect_exclude(self):
        self._populate(self.local1_base)
        files = Repo(self.local1_base, exclude=['file_ä']).collect()
        self.assertEqual(2, len(files))
        self.assertEqual('d', files['dir'][0])
        self.assertEqual('d', files['.'][0])
    
    def test_collect_rel_path(self):
        self._populate(self.local1_base)
        files = Repo(self.local1_base, rel_path='dir').collect()
        self.assertEqual(2, len(files))
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        self.assertEqual('d', files['dir'][0])
    
    def test_collect_link(self):
        self._populate(self.local1_base)
        self._populate(self.remote)
        os.symlink(self.remote, os.path.join(self.local1_base, 'link'))
        files = Repo(self.local1_base).collect()
        self.assertEqual(8, len(files))
        self.assertEqual('d', files['link'][0])
        self.assertEqual(('f', 8), files['link/dir/file_ä'][:2])
        self.assertEqual(('f', 7), files['link/file_ä'][:2])
        self.assertEqual('d', files['link/dir'][0])
        files = Repo(self.local1_base, preserve_links=True).collect()
        self.assertEqual(5, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        self.assertEqual(('f', 7), files['file_ä'][:2])
        self.assertEqual('d', files['dir'][0])
        self.assertEqual('l', files['link'][0])
    
    def test_collect_remote(self):
        self._populate(self.remote)
        remote = Remote('remote', self.remote_host, self.local1_ms)
        remote.mount()
        files = Repo(remote).collect()
        self.assertEqual(4, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        self.assertEqual(('f', 7), files['file_ä'][:2])
        self.assertEqual('d', files['dir'][0])
        remote.umount()
    
    def test_collect_remote_rel_path(self):
        self._populate(self.remote)
        remote = Remote('remote', self.remote_host, self.local1_ms)
        remote.mount()
        files = Repo(remote, rel_path='dir').collect()
        self.assertEqual(2, len(files))
        self.assertEqual('d', files['dir'][0])
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        files = Repo(remote, rel_path='file_ä').collect()
        self.assertEqual(1, len(files))
        self.assertEqual(('f', 7), files['file_ä'][:2])
        remote.umount()
    
    def test_collect_remote_key(self):
        remote = Remote('remote', self.remote_host, self.local1_ms, key=self.key)
        remote.mount()
        self._populate(remote.encfs_destination)
        files = Repo(remote).collect()
        self.assertEqual(4, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        self.assertEqual(('f', 7), files['file_ä'][:2])
        self.assertEqual('d', files['dir'][0])
        remote.umount()
    
    def test_collect_remote_key_exclude(self):
        remote = Remote('remote', self.remote_host, self.local1_ms, key=self.key)
        remote.mount()
        self._populate(remote.encfs_destination)
        files = Repo(remote, exclude=['dir']).collect()
        self.assertEqual(2, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual(('f', 7), files['file_ä'][:2])
        files = Repo(remote, exclude=['di*']).collect()
        self.assertEqual(2, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual(('f', 7), files['file_ä'][:2])
        files = Repo(remote, exclude=['/file_ä']).collect()
        self.assertEqual(3, len(files))
        self.assertEqual('d', files['.'][0])
        self.assertEqual('d', files['dir'][0])
        self.assertEqual(('f', 8), files['dir/file_ä'][:2])
        remote.umount()


class TestRemote(TestSynkrotron):
    
    def test_mount(self):
        remote = Remote('remote', self.remote, self.local1_ms)
        self.assertEqual(self.remote, remote.mount())
    
    def test_mount_encfs(self):
        remote = Remote('remote', self.remote, self.local1_ms, key=self.key)
        path = remote.mount()
        self.assertEqual(remote._sync_path('encfs'), path)
        self.assertEqual(self.remote, remote.encfs_source)
        self.assertTrue(os.path.ismount(path))
        self._populate(path)
        remote.umount()
        self.assertFalse(os.path.exists(path))
        self.assertEqual(3, len(os.listdir(self.remote)))
        # inexistent location
        with self.assertRaises(Exception):
            Remote('remote', self.remote + 'x', self.local1_ms, key=self.key).mount()
        # re-mount with wrong key
        remote = Remote('remote', self.remote, self.local2_ms, key=self.key)
        remote.mount()
        remote.umount()
        remote = Remote('remote', self.remote, self.local2_ms, key=self.key + 'x')
        with self.assertRaises(Exception):
            remote.mount()
    
    def test_mount_sshfs(self):
        remote = Remote('remote', self.remote_host, self.local1_ms)
        path = remote.mount()
        self.assertEqual(remote._sync_path('sshfs'), path)
        self.assertTrue(os.path.ismount(path))
        self._populate(path)
        remote.umount()
        self.assertFalse(os.path.exists(path))
        self.assertEqual(2, len(os.listdir(self.remote)))
        with self.assertRaises(Exception):
            Remote('remote', self.remote_host + 'x', self.local2_ms).mount()
    
    def test_mount_sshfs_encfs_mp(self):
        remote = Remote('remote', self.remote_host, self.local1_ms, key=self.key, mount_point=self.mount_point)
        path = remote.mount()
        self.assertEqual(self.mount_point, path)
        self.assertTrue(os.path.islink(path))
        target_sshfs = remote._sync_path('sshfs')
        target_encfs = remote._sync_path('encfs')
        self.assertTrue(os.path.ismount(target_sshfs))
        self.assertTrue(os.path.ismount(target_encfs))
        self._populate(path)
        remote.umount()
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(target_sshfs))
        self.assertFalse(os.path.exists(target_encfs))
        self.assertEqual(3, len(os.listdir(self.remote)))
    
    def test_name_encryption(self):
        remote = Remote('remote', self.remote, self.local1_ms, key=self.key)
        remote.mount()
        clear = ['a/b', '/c', 'x/y/ ä']
        encrypted = remote.encrypt_names(clear)
        decrypted = remote.decrypt_names(encrypted)
        self.assertListEqual(clear, decrypted)
        remote.umount()
    
    def test_cache(self):
        remote = Remote('remote', self.remote, self.local1_ms, key=self.key)
        remote.mount()
        clear = ['a/b', 'c', 'x/y/ ä']
        remote.encrypt_names(clear)
        self.assertEqual(6, len(remote._cache[0]))
        self.assertEqual(6, len(remote._cache[1]))
        self.assertTrue('y' in remote._cache[0].values())
        self.assertTrue('y' in remote._cache[1].keys())
        cache = remote._cache
        remote.save_cache()
        del remote._cache
        remote._load_cache()
        self.assertSameElements(cache[0], remote._cache[0])
        self.assertSameElements(cache[1], remote._cache[1])
        remote.umount()
    
    def test_reverse_mount(self):
        remote = Remote('remote', self.remote, self.local1_ms, key=self.key)
        remote.mount()
        remote.reverse_mount()
        self._populate(self.local1_base)
        self._populate(remote.encfs_destination)
        files_remote = os.listdir(self.remote)
        files_reverse = os.listdir(remote.encfs_reverse)
        self.assertEqual(3, len(files_reverse))
        for name in files_remote:
            if name == '.encfs6.xml':
                continue
            self.assertTrue(name in files_remote)
            path_remote = os.path.join(self.remote, name)
            path_reverse = os.path.join(remote.encfs_reverse, name)
            if os.path.isfile(path_remote):
                self.assertEqual(Repo._file_hash(path_remote), Repo._file_hash(path_reverse))
        remote.reverse_umount()
        remote.umount()


class TestConfig(TestSynkrotron):
    
    def test_paths(self):
        config = Config(self.local1_base)
        self.assertEqual(self.local1_base, config.root)
        self.assertEqual(self.local1_ms, config.sync_dir)
        self.assertEqual(self.local1_config, config.config_file)
        self.assertEqual('.', config.rel_cwd)
    
    def test_paths_relative(self):    
        self._populate(self.local1_base)
        config = Config(os.path.join(self.local1_base, 'dir'))
        self.assertEqual(self.local1_base, config.root)
        self.assertEqual(self.local1_ms, config.sync_dir)
        self.assertEqual(self.local1_config, config.config_file)
        self.assertEqual('dir', config.rel_cwd)
    
    def test_remotes(self):
        config = Config(self.local1_base)
        self.assertEqual(1, len(config.remotes))
        self.assertEqual(10, len(config.remotes['remote']))
        self.assertEqual(self.remote, config.remotes['remote']['location'])
        self.assertEqual('', config.remotes['remote']['key'])
        self.assertEqual('', config.remotes['remote']['mount_point'])
        self.assertEqual(0, config.remotes['remote']['delete'])
        self.assertEqual(0, config.remotes['remote']['ignore_time'])
        self.assertEqual('', config.remotes['remote']['exclude'])
        self.assertEqual(0, config.remotes['remote']['modify_window'])
        self.assertEqual(0, config.remotes['remote']['preserve_links'])
        self.assertEqual(0, config.remotes['remote']['content'])
        self.assertEqual('', config.remotes['remote']['clear'])


class TestMain(TestSynkrotron):
    
    def test_parse_args(self):
        sys.argv[1:] = ['pull', 'remote']
        args = synkrotron.parse_args()
        self.assertEqual('pull', args.command)
        self.assertEqual('remote', args.remote)
        self.assertFalse(args.simulate)
        sys.argv[1:] = ['pull', 'remote', '--simulate']
        args = synkrotron.parse_args()
        self.assertTrue(args.simulate)
        sys.argv[1:] = ['pull', 'remote', '-s']
        args = synkrotron.parse_args()
        self.assertTrue(args.simulate)

    def test_main_mount(self):
        os.chdir(self.local3_base)
        sys.argv[1:] = ['mount', 'remote']
        synkrotron.main()
        self.assertTrue(os.path.islink(self.mount_point))
        self._populate(self.mount_point)
        Remote('remote', self.remote_host, self.local3_ms, key=self.key, mount_point=self.mount_point).umount()
        self.assertEqual(3, len(os.listdir(self.remote)))
    
    def test_main_umount(self):
        remote = Remote('remote', self.remote_host, self.local3_ms, key=self.key, mount_point=self.mount_point)
        remote.mount()
        os.chdir(self.local3_base)
        sys.argv[1:] = ['umount', 'remote']
        synkrotron.main()
        self.assertFalse(os.path.exists(self.mount_point))
        self.assertFalse(os.path.exists(remote._sync_path('sshfs')))
        self.assertFalse(os.path.exists(remote._sync_path('encfs')))
    
    def test_main_mount_pull_umount(self):
        self._populate(self.remote)
        os.chdir(self.local2_base)
        sys.argv[1:] = ['pull', 'remote', '-u']
        synkrotron.main()
        remote = Remote('remote', self.remote, self.local2_ms)
        self.assertFalse(os.path.exists(remote._sync_path('sshfs')))
        self.assertEqual(3, len(os.listdir(self.local2_base)))
    
    def test_main_mount_push(self):
        self._populate(self.local3_base)
        os.chdir(self.local3_base)
        sys.argv[1:] = ['push', 'remote']
        synkrotron.main()
        Remote('remote', self.remote_host, self.local3_ms, key=self.key, mount_point=self.mount_point).umount()
        self.assertEqual(3, len(os.listdir(self.remote)))
    
    def test_main_push_path(self):
        self._populate(self.local1_base)
        os.chdir(self.local1_base)
        sys.argv[1:] = ['push', 'remote', '-u', '-p', 'dir']
        synkrotron.main()
        self.assertEqual(('dir',), tuple(os.listdir(self.remote)))
        self.assertEqual(('file_ä',), tuple(os.listdir(os.path.join(self.remote, 'dir'))))
    
    def test_main_push_sshfs_encfs_content(self):
        self._populate(self.local3_base)
        os.chdir(self.local3_base)
        sys.argv[1:] = ['push', 'remote']
        synkrotron.main()
        file_local = os.path.join(self.local3_base, 'file_ä')
        file_remote = os.path.join(self.mount_point, 'file_ä')
        with io.open(file_local, 'w') as f:
            f.write('xontent')
        os.utime(file_local, (os.path.getatime(file_remote), os.path.getmtime(file_remote)))
        sys.argv[1:] = ['push', 'remote']
        synkrotron.main()
        with io.open(file_remote, 'r') as f:
            self.assertEqual('content', f.read())
        sys.argv[1:] = ['push', 'remote', '--content']
        synkrotron.main()
        with io.open(file_remote, 'r') as f:
            self.assertEqual('xontent', f.read())
        sys.argv[1:] = ['umount', 'remote']
        synkrotron.main()
    
    def _main_push_delta_key(self, path=None):
        self._populate(self.local3_base)
        os.chdir(self.local3_base)
        # push files to remote
        sys.argv[1:] = ['push', 'remote', '-u']
        synkrotron.main()
        os.makedirs(os.path.join(self.local3_base, 'dir', 'new'))
        # push changes to delta
        sys.argv[1:] = ['push', 'remote', '-u', '--delta=%s' % self.delta]
        if path:
            sys.argv.append('--path=' + path)
        synkrotron.main()
        # check delta files
        r = Remote('remote', self.remote_host, self.local3_ms, key=self.key, mount_point=self.mount_point)
        r.mount()
        files = [f for f in os.listdir(self.delta) if f != '.encfs6.xml' and f != '.synkrotron']
        self.assertListEqual(['dir'], r.decrypt_names(files))
        path = os.path.join(self.delta, files[0])
        self.assertListEqual(['new'], r.decrypt_names(os.listdir(path)))
        # push delta to remote
        os.chdir(self.delta)
        sys.argv[1:] = ['push', 'remote', '-u']
        synkrotron.main()
        # check remote files (should be the same now (encrypted of course) as the ones in self.local3_base)
        self.assertEqual(0, len(Diff(Repo(self.local3_base), Repo(r)).compute()))
        r.umount()
    
    def test_main_push_delta_key(self):
        self._main_push_delta_key()
    
    def test_main_push_delta_key_path(self):
        self._main_push_delta_key('dir/new')
    
    def test_main_push_clear(self):
        self._populate(self.local4_base)
        os.chdir(self.local4_base)
        sys.argv[1:] = ['push', 'remote', '-u']
        synkrotron.main()
        # "dir/file_ä" should be unencrypted
        self.assertListEqual(['file_ä'], os.listdir(os.path.join(self.remote, 'dir')))
        # "file_ä" should be encrypted
        r = Remote('remote', self.remote_host, self.local4_ms, key=self.key)
        r.mount()
        files = [f for f in os.listdir(self.remote) if f != '.encfs6.xml' and f != 'dir']
        self.assertListEqual(['file_ä'], r.decrypt_names(files))
        r.umount()
    
    def test_main_push_clear_delta(self):
        self._populate(self.local4_base)
        os.chdir(os.path.join(self.local4_base, 'dir'))
        sys.argv[1:] = ['push', 'remote', '-u', '--path=file_ä', '--delta=%s' % self.delta]
        synkrotron.main()
        # "dir/file_ä" should be unencrypted
        self.assertListEqual(['file_ä'], os.listdir(os.path.join(self.delta, 'dir')))
    

if __name__ == "__main__":
    unittest.main()
