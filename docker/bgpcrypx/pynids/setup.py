#! /usr/bin/env python

# setup.py - Distutils instructions for the pynids package

# This file is part of the pynids package, a python interface to libnids.
# See the file COPYING for license information.

from distutils.core import setup, Extension
from distutils.command.build import build    # nidsMaker
from distutils.spawn import spawn            # nidsMaker.run()
import os, os.path

pathjoin = os.path.join

PKGNAME  = 'libnids'
BUILDDIR = PKGNAME

INCLUDE_DIRS  = ['/usr/local/include', '/opt/local/include']
LIBRARY_DIRS  = ['/usr/local/lib', '/opt/local/lib']
EXTRA_OBJECTS = []

class nidsMaker(build):
    NIDSDIR = BUILDDIR
    include_dirs = [ pathjoin(NIDSDIR, 'src') ]
    library_dirs = []
    extra_objects  = [ pathjoin(NIDSDIR, 'src', 'libnids.a') ]

    def buildNids(self):
        os.chdir(self.NIDSDIR)
        if not os.path.exists(pathjoin('src', 'Makefile')):
            spawn([pathjoin('.','configure'), '--enable-tcpreasm', 'CFLAGS=-fPIC'])
        ## Always make
        spawn(['make'], search_path = 1)
        os.chdir('..')

    def run(self):
        self.buildNids()
        build.run(self)

INCLUDE_DIRS = nidsMaker.include_dirs + INCLUDE_DIRS
EXTRA_OBJECTS = nidsMaker.extra_objects + EXTRA_OBJECTS

setup (# Distribution meta-data
        name = "pynids",
        version = "0.6.3",
        description = "libnids wrapper",
        author = "Jon Oberheide",
        author_email = "jon@oberheide.org",
        license = "GPL",
        long_description = \
'''pynids is a python wrapper for libnids, a Network Intrusion Detection System
library offering sniffing, IP defragmentation, TCP stream reassembly and TCP
port scan detection.
-------
''',
        cmdclass = {'build': nidsMaker},
        ext_modules = [ Extension(
                            "nids",
                            define_macros = [
                                #("DEBUG", None),
                                #("ENABLE_TCPREASM_DEBUG", None),
                                ("ENABLE_TCPREASM", None),
                            ],
                            sources=["nidsmodule.c"],
                            include_dirs = INCLUDE_DIRS,
                            libraries = ["pcap", "net", "glib-2.0", "gthread-2.0"],
                            library_dirs = LIBRARY_DIRS,
                            extra_objects = EXTRA_OBJECTS
                        ) 
                      ],
        url = "https://bitbucket.org/jmichel/pynids"
        )

