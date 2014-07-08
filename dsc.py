#!/usr/bin/env python

"""
dsc.py

Copyright (c) 2007 Adam Hupp <adam nospam hupp.org>
Distributed under the PSF License: http://www.python.org/psf/license/

This program will detect and warn about unpatched security problems on
a Debian installation.  It does this by looking for any upgradable
packages appear in the security advisories RSS feed.

Requires: python-apt, dctrl-tools, python-feedparser
"""

import sys
import os
import feedparser
import apt

def source_to_binary(source_package):   
    """Given a source package name, return a list of all installed
    binary packages"""
    
    process = os.popen("grep-status -F Source -s Package -s Status %s |" 
                       "grep-dctrl -F Status --regex installed |"
                       " grep-dctrl -s Package ''" % source_package)
    output = process.readlines()

    # "Package: foo\n" -> "foo"
    return [i.split(None, 1)[1].strip() for i in output]



def src_needs_upgrade(cache, srcpackage):
    """
    Given a source package name and an apt.Cache instance, return True
    if any of its binary packages are upgradable.
    """

    binpackage = source_to_binary(srcpackage)

    for i in binpackage:
        if cache[i].is_upgradable:
            return True
    return False


if __name__ == "__main__":

    cache = apt.Cache()

    feed = feedparser.parse("http://www.debian.org/security/dsa-long")

    for i in feed.entries:
        srcpackage = i.title.split()[1]
    
        if src_needs_upgrade(cache, srcpackage):
            print >>sys.stderr, "Security Update:", srcpackage.encode('utf-8')
            print >>sys.stderr, i.summary.encode('utf-8')
            print >>sys.stderr, ""


