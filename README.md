fuse-rsync
==========

A FUSE filesystem that lets you mount remote rsync modules.

## Installation ##
Install the python-fuse package on your distro (at least that is how it is 
called in Ubuntu).

## Usage ##
The module has several mount options:
- __host__: The rsync host where the module is hosted. If the host is listening
            on a non-standard port, just append the port with the usual colon
            notation.
- __module__: Name of the rsync module.
- __path__: If you do not want to export the root of the module but a subpath,
            specify the subpath here.
- __user__: User name that is used to connect to that module.
- __password__: Rsync password that is used to connect to that module.

A sample invocation of the command could look like this:

*python fuse_rsync.py -o host=remoteserver,module=mymodule,user=nobody,password=none /mnt*

to connect to the rsync module *mymodule* on *remoteserver* with user *nobody* and password *none* 
and mount it to */mnt*. Other useful switches might be *-f* to keep the execution of the program
in foreground and see logging output, and *-d* to see debugging output.

To unmount, use *fusermount -u /mnt*.

## Notes ##

There is some rudimentary caching for filesystem attributes, which should work fine because
the filesystem is read-only, but might be a nuisance if files are changed frequently on the remote
side. Broken symlinks will currently kill the program, and symlinks are converted to files in the
process of copying. Overall the program has a hacky quality and should be taken more for learning
than for production purposes.



