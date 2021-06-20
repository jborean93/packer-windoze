# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

DOCUMENTATION = '''
lookup: ip_info
author: Jordan Borean (@jborean93)
short_description: Retrieves the IP address and default gateway of a WSL host
description:
- This lookup returns the IP address and the default gatewya of the WSL2 host.
options: {}
'''

EXAMPLES = """
- set_fact:
    ip_info: '{{ lookup("jborean93.windoze.ip_info") }}"
"""

RETURN = """
_raw:
  description:
  - IP address and default gateway.
  type: dict
"""

import fcntl
import ipaddress
import socket
import struct

from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase

from typing import (
    Tuple,
    Union,
)


def get_gateway(
    interface: str
) -> str:
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if (
                fields[0] != interface or
                fields[1] != '00000000' or
                not int(fields[3], 16) & 2
            ):
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))


def get_interfaceinfo(
    interface: str
) -> Tuple[Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface], str]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # SIOCGIFADDR
        b_ip = fcntl.ioctl(s, 0x8915, struct.pack('256s', interface.encode()))[20:24]
        ip = socket.inet_ntoa(b_ip)

        # SIOCGIFNETMASK
        b_mask = fcntl.ioctl(s, 0x0891b, struct.pack('256s', interface.encode()))[20:24]
        mask =  socket.inet_ntoa(b_mask)

        gateway = get_gateway(interface)

        return ipaddress.ip_interface(f'{ip}/{mask}'), gateway


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        #self.set_options(var_options=variables, direct=kwargs)

        for _, name in socket.if_nameindex():
            interface = gateway = None
            try:
                interface, gateway = get_interfaceinfo(name)
                if (
                    interface.is_link_local or
                    interface.is_loopback or
                    interface.is_multicast or
                    interface.is_reserved
                ):
                    continue

                break

            except:
                continue

        if interface is None:
            raise AnsibleLookupError('Failed to find WSL interface details')

        return [{
            'ip': str(interface),
            'prefixlen': interface.network.prefixlen,
            'gateway': gateway,
        }]
