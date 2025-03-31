#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import print_function


from setuptools import setup, find_packages

import os
import platform
import sys


lib_base = os.path.join("extras", "libargon2", "src")
include_dirs = [
    os.path.join(lib_base, "..", "include"),
    os.path.join(lib_base, "blake2"),
]

# Add vendored integer types headers if necessary.
windows = "win32" in str(sys.platform).lower()
if windows:
    int_base = "extras/msinttypes/"
    inttypes = int_base + "inttypes"
    stdint = int_base + "stdint"
    vi = sys.version_info[0:2]
    if vi in [(2, 6), (2, 7)]:
        # VS 2008 needs both.
        include_dirs += [inttypes, stdint]
    elif vi in [(3, 3), (3, 4)]:
        # VS 2010 needs inttypes.h and fails with both.
        include_dirs += [inttypes]

# Optimized version requires SSE2 extensions.  They have been around since
# 2001 so we try to compile it on every recent-ish x86.
optimized = platform.machine() in ("i686", "x86", "x86_64", "AMD64")

LIBRARIES = [
    (
        "libargon2",
        {
            "include_dirs": include_dirs,
            "sources": [
                os.path.join(lib_base, path)
                for path in [
                    "argon2.c",
                    os.path.join("blake2", "blake2b.c"),
                    "core.c",
                    "encoding.c",
                    "opt.c" if optimized else "ref.c",
                    "thread.c",
                ]
            ],
        },
    ),
]


setup(
    packages=find_packages(),
    libraries=LIBRARIES,
)
