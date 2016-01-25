#!/usr/bin/env python

"""
netns - context manager for network namespaces
"""

import ctypes
import os
import resource
import subprocess
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

_libc = ctypes.CDLL('libc.so.6')

NETNS_DIR = "/var/run/netns/"


class Namespace:
    def __init__(self, name):
        self.parent_fd = open("/proc/self/ns/net")
        self.parent_fileno = self.parent_fd.fileno()
        self.target_fd = open(NETNS_DIR + str(name))
        self.target_fileno = self.target_fd.fileno()

    def __enter__(self):
        _libc.setns(self.target_fileno, 0)

    def __exit__(self, type, value, tb):
        _libc.setns(self.parent_fileno, 0)
        try:
            self.target_fd.close()
        except:
            LOG.warning(_("Failed to close target_fd: %s"), target_fd)
            pass
        self.parent_fd.close()


def nslist():
    return os.listdir(NETNS_DIR) if os.path.exists(NETNS_DIR) else []


def iflist(ignore=set()):
    interfaces = []
    for line in subprocess.check_output(['ip', 'addr', 'show']).splitlines():
        if not line.strip().startswith('inet '):
            continue
        words = line.split()
        name = words[-1]
        if name in ignore:
            continue
        addr, _, mask = words[1].partition('/')
        interfaces.append((name, addr, mask))
    return interfaces


def increase_ulimit(ulimit):
    resource.setrlimit(resource.RLIMIT_NOFILE, (ulimit, ulimit))
