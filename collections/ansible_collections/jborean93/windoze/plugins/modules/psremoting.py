#!/usr/bin/python

# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

DOCUMENTATION = r'''
module: psremoting:
short_description: Enable pwsh PSRemoting endpoint
description:
- Enables the PSRemoting endpoint for pwsh.
notes:
- This module uses async internally to survive the WinRM service being restarted when enabling the remoting endpoint.
  Do not run with async explictly.
options: {}
author:
- Jordan Borean (@jborean93)
'''

EXAMPLES = r'''
- name: enable PSRemoting for pwsh
  jborean93.windoze.psremoting:
'''

RETURN = r'''
# Nothing
'''
