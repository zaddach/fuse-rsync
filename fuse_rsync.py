#!/usr/bin/env python

import os
import sys
import errno
import optparse
import logging
import subprocess
import stat
import datetime
import time
import re
import fuse
from tempfile import mkstemp
from threading import Lock

fuse.fuse_python_api = (0, 2)  
log = logging.getLogger('fuse_rsync')

class RsyncModule():
    """
        This class implements access to an Rsync module.
    """
    def __init__(self, host, module, user = None, password = None):
        self._environment = os.environ.copy()
        self._remote_url = "rsync://"
        if not user is None:
            self._remote_url += user + "@"
            
        self._remote_url += host + "/" + module
        
        if not password is None:
            self._environment['RSYNC_PASSWORD'] = password
        self._attr_cache = {}

    def _parse_attrs(self, attrs):
        """
            Parse the textual representation of file attributes to binary representation.
        """
        result = 0
        if attrs[0] == 'd':
            result |= stat.S_IFDIR 
        elif attrs[0] == 'l':
            result |= stat.S_IFLNK
        elif attrs[0] == '-':
            result |= stat.S_IFREG
        else:
           assert(False)
            
        for i in range(0, 3):
            val = 0
            if 'r' in attrs[1 + 3 * i: 4 + 3 * i]:
                val |= 4
            if 'w' in attrs[1 + 3 * i: 4 + 3 * i]:
                val |= 2
            if 'x' in attrs[1 + 3 * i: 4 + 3 * i]:
                val |= 1
            result |= val << ((2 - i) * 3)
            
        return result
        
    def list(self, path = '/'):
        """
            List files contained in directory __path__.
            Returns a list of dictionaries with keys *attrs* (numerical attribute
            representation), *size* (file size), *timestamp* (File's atime timestamp
            in a datetime object) and *filename* (The file's name).
        """
        # See http://stackoverflow.com/questions/10323060/printing-file-permissions-like-ls-l-using-stat2-in-c for modes
        RE_LINE = re.compile("^([ldcbps-]([r-][w-][x-]){3})\s+([0-9]+)\s+([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (.*)$")
        remote_url = self._remote_url + path
        try:
            cmdline = ["rsync", "--list-only", remote_url]
            log.debug("executing %s", " ".join(cmdline))
            output = subprocess.check_output(["rsync", "--list-only", remote_url], env = self._environment)

            listing = []
            for line in output.decode(encoding = 'iso-8859-1').split("\n"):
                match = RE_LINE.match(line)

                if not match:
                    continue

                listing.append({
                        "attrs": self._parse_attrs(match.group(1)),
                        "size": int(match.group(3)),
                        "timestamp": datetime.datetime.strptime(match.group(4), "%Y/%m/%d %H:%M:%S"),
                        "filename": match.group(5)
                        })
            return listing
        except subprocess.CalledProcessError as err:
            if err.returncode == 23:
                return []
            raise err
           
    def copy(self, remotepath = '/', localpath = None):
        """
            Copy a file from the remote rsync module to the local filesystem.
            If no local destination is specified in __localpath__, a temporary
            file is created and its filename returned. The temporary file has
            to be deleted by the caller.
        """
        remote_url = self._remote_url + remotepath
        if localpath is None:
            (file, localpath) = mkstemp()
            os.close(file)
        cmdline = ["rsync", "--copy-links", remote_url, localpath]
        log.debug("executing %s", " ".join(cmdline))
        subprocess.check_call(cmdline, env = self._environment)
        
        return localpath

class FuseRsyncFileInfo(fuse.FuseFileInfo):
    """
        Encapsulates the file handle for an opened file.
    """
    def __init__(self, handle, **kw):
        super(FuseRsyncFileInfo, self).__init__(**kw)
        self.keep = True
        self.handle = handle

class FuseRsync(fuse.Fuse):
    """
        The implementation of the FUSE filesystem.
    """
    def __init__(self, *args, **kw):
        self.host = None
        self.module = None
        self.user = None
        self.password = None
        self.path = "/"

        self._attr_cache = {}
        self._file_cache = {}
        self._file_cache_lock = Lock()
        
        fuse.Fuse.__init__(self, *args, **kw)
        
        self.parser.add_option(mountopt = 'user', default = None, help = "Rsync user on the remote host")
        self.parser.add_option(mountopt = 'password', type = str, default = None, help = "Rsync password on the remote host")
        self.parser.add_option(mountopt = 'host', type = str, help = "Rsync remote host")
        self.parser.add_option(mountopt = 'module', type = str, help = "Rsync module on remote host")
        self.parser.add_option(mountopt = 'path', type = str, default = "/", help = "Rsync path in module on remote host that is supposed to be the root point")

    # Helpers
    # =======
            
    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.path, partial)
        return path
        
    def init(self):
        options = self.cmdline[0]
        log.debug("Invoked fsinit() with host=%s, module=%s, user=%s, password=%s", options.host, options.module, options.user, options.password)
        self._rsync = RsyncModule(options.host, options.module, options.user, options.password)

    # Filesystem methods
    # ==================

    #def access(self, path, mode):
        #full_path = self._full_path(path)
        #if not os.access(full_path, mode):
            #raise FuseOSError(errno.EACCES)

    #def chmod(self, path, mode):
        #full_path = self._full_path(path)
        #return os.chmod(full_path, mode)

    #def chown(self, path, uid, gid):
        #full_path = self._full_path(path)
        #return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        try:
            log.debug("Invoked getattr('%s')", path)

            path = self._full_path(path)
        
            st = fuse.Stat() 
            
            if path == "/":
                st.st_atime = int(time.time())
                st.st_ctime = int(time.time())
                st.st_mode  = stat.S_IFDIR | 0555
                st.st_mtime = int(time.time())
                st.st_nlink = 2
                st.st_uid = os.geteuid()
                st.st_gid = os.getegid()
                return st
            
            if path in self._attr_cache:
                info = self._attr_cache[path]
            else:
                listing = self._rsync.list(path)
                if len(listing) != 1:
                    log.warn("Found none or several files for path")
                    return -errno.ENOENT
                info = listing[0]
                self._attr_cache[path] = info

            timestamp = (info["timestamp"] - datetime.datetime(1970,1,1)).total_seconds()
            st.st_atime = timestamp
            st.st_ctime = timestamp
            st.st_uid = os.geteuid()
            st.st_gid = os.getegid()
            if info["attrs"] & stat.S_IFDIR:
                st.st_mode  = stat.S_IFDIR | 0555
            else:
                st.st_mode = stat.S_IFREG | 0444
            st.st_mtime = timestamp
            st.st_nlink = 1
            st.st_size = info["size"]
            
            return st
        except Exception as ex:
            log.exception("while doing getattr")
            return -errno.ENOENT

    def readdir(self, path, offset): 
        try:
            if not path.endswith("/"):
                path += "/"
            log.debug("Invoked readdir('%s')", path)

            full_path = self._full_path(path)

            yield fuse.Direntry('.')
            yield fuse.Direntry('..')
        
            for dirent in self._rsync.list(full_path):
                if dirent["filename"] == ".":
                    continue
                self._attr_cache[path + dirent["filename"]] = dirent
                yield fuse.Direntry(str(dirent["filename"]))
        except Exception as ex:
            log.exception("While doing readdir")

    #def readlink(self, path):
        #pathname = os.readlink(self._full_path(path))
        #if pathname.startswith("/"):
            ## Path name is absolute, sanitize it.
            #return os.path.relpath(pathname, self.root)
        #else:
            #return pathname

    #def mknod(self, path, mode, dev):
        #return os.mknod(self._full_path(path), mode, dev)

    #def rmdir(self, path):
        #full_path = self._full_path(path)
        #return os.rmdir(full_path)

    #def mkdir(self, path, mode):
        #return os.mkdir(self._full_path(path), mode)

    #def statfs(self, path):
        #full_path = self._full_path(path)
        #stv = os.statvfs(full_path)
        #return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            #'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            #'f_frsize', 'f_namemax'))

    #def unlink(self, path):
        #return os.unlink(self._full_path(path))

    #def symlink(self, target, name):
        #return os.symlink(self._full_path(target), self._full_path(name))

    #def rename(self, old, new):
        #return os.rename(self._full_path(old), self._full_path(new))

    #def link(self, target, name):
        #return os.link(self._full_path(target), self._full_path(name))

    #def utimens(self, path, times=None):
        #return os.utime(self._full_path(path), times)

    ## File methods
    ## ============

    def open(self, path, flags):
        log.debug("invoking open(%s, %d)", path, flags)

        full_path = self._full_path(path)
        if flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) != os.O_RDONLY:
            return -errno.EACCES

        with self._file_cache_lock:
            if not path in self._file_cache:
                localfile = self._rsync.copy(full_path)
                self._file_cache[path] = {"refcount": 1, "localpath": localfile}
            else:
                self._file_cache[path]["refcount"] += 1
                localfile = self._file_cache[path]["localpath"]

        handle = os.open(localfile, os.O_RDONLY)
        log.debug("Created file handle %d", handle)
        return FuseRsyncFileInfo(handle)

    #def create(self, path, mode, fi=None):
        #full_path = self._full_path(path)
        #return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        log.debug("invoking read(%s, %d, %d, %d)", path, length, offset, fh.handle)
        os.lseek(fh.handle, offset, os.SEEK_SET)
        return os.read(fh.handle, length)

    #def write(self, path, buf, offset, fh):
        #os.lseek(fh, offset, os.SEEK_SET)
        #return os.write(fh, buf)

    #def truncate(self, path, length, fh=None):
        #full_path = self._full_path(path)
        #with open(full_path, 'r+') as f:
            #f.truncate(length)

    #def flush(self, path, fh):
        #return os.fsync(fh)

    def release(self, path, dummy, fh):
        log.debug("invoking release(%s, %d, %d)", path, dummy, fh.handle)
        os.close(fh.handle)

        with self._file_cache_lock:
            self._file_cache[path]["refcount"] -= 1
            if self._file_cache[path]["refcount"] <= 0:
                localfile = self._file_cache[path]["localpath"]
                del self._file_cache[path]
                os.unlink(localfile)

    #def fsync(self, path, fdatasync, fh):
        #return self.flush(path, fh)

if __name__ == '__main__':
    fs = FuseRsync()  
    fs.parse(errex=1)  
#TODO: Below is hacky, find properly parsed debug attribute
    if '-d' in sys.argv:
        logging.basicConfig(level = logging.DEBUG)
    else:
        logging.basicConfig(level = logging.ERROR)
    fs.init()
    fs.main()  
