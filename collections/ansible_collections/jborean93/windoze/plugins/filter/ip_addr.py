# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import ipaddress

from typing import (
    List,
)

def ip_addr(
    value: str,
    reserved: List[str],
    idx: int
) -> str:
    """Gets the next IP address available."""
    interface = ipaddress.ip_interface(value)
    reserved_ips = set(reserved)
    reserved_ips.add(str(interface.ip))

    for next_ip in interface.network.hosts():
        if str(next_ip) in reserved:
            continue

        if idx == 0:
            return str(next_ip)

        else:
            idx -= 1


class FilterModule:

    def filters(self):
        return {
            'ip_addr': ip_addr,
        }
