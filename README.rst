.. hightlight:: rst

Myrinet-mx Roll
================

.. contents::

Introduction
----------------
This roll installs  myrinet drivers and software for Myricom switch


Requirements
~~~~~~~~~~~~~~
To build the roll, first, download myrinet-mx src from google drive 
and place in ``src/myrinet_mx``. Update ``/src/myrinet_mx/version.mk``
to reflect the version.


Building
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To build the roll execute: ::

    # make roll 2>&1 | tee build.log


Installing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. A roll can be added during a frontend build as any other roll.

#. A roll can be added to the existing frontend. 
   Execute all commands from top level directory ::

   # rocks add roll *.iso
   # rocks enable roll myrinet-mx
   # (cd /export/rocks/install; rocks create distro)  
   # rocks run roll myrinet-mx > add-roll.sh  
   # bash add-roll.sh 2>&1 | tee install.log

What is installed 
------------------

Roll installs the following: ::

    /etc/ld.so.conf.d/mx.conf
    /opt/mx
    /opt/mx/source/mx_1.2.16.tar.gz

and then configures and installs mx drivers from source using a current kernel on the node.

Notes from 2011 roll
~~~~~~~~~~~~~~~~~~~~~~

mx-1.2.12 patched version was installed on FE and vm-containers to prevent log 
files /var/run/fms//fma.log build up (fill disk within a week)
make roll and install on vm containers and frontend.
The log size problem effects only vm-container nodes and frontend, the compute nodes are unaffected.
Bug report was filed with myrinet developmers.

If this problem shows up with mx-1.2.16 verison, need to apply a similar patch

Myrinet Switch Firmware
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Drivers distro mx_1.2.16.tar.gz is available on google drive on nbcr.ucsd@gmail.com account
in ``privaterolls/myrinet-mx/`` and the sw firmware in ``privaterolls/myrinet-mx/firmware/`` 

:Switch:                                           Software
:Myri-10G 10G-{21U,12U,7U}-{CLOS,EDGE}-ENCL:       fridgefs.img
:Myri-10G 10G-CLOS-ENCL (with the TFT Display):    fridgefs.img                
:Myrinet-2000 M3-CLOS-ENCL-B/M3-SPINE-ENCL-B:      shipfs.img	
:Myrinet-2000 M3-E128, M3-E64, M3-E32, and M3-E16: m3-dist.tar.gz	
