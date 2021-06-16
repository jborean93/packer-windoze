# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time
import traceback

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

from typing import (
    Dict,
)

display = Display()

_GET_SCRIPT = r'''[CmdletBinding(SupportsShouldProcess)]
param ()

$Ansible.Changed = $false
Get-PSSessionConfiguration -Name PowerShell.* -ErrorAction SilentlyContinue
'''


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._supports_async = False

        result = self._execute_module(
            module_name='ansible.windows.win_powershell',
            module_args={
                'script': _GET_SCRIPT,
                'executable': 'pwsh',
                'depth': 1,
            },
            task_vars=task_vars,
        )
        if result['output'] != []:
            return {'changed': False}

        res = {'changed': True}

        if self._play_context.check_mode:
            return res

        # We run with async as it allows the process to outlive the WinRM connection which is bounced with
        # Enable-PSRemoting. Inspired from community.windows.win_pssession_configuration.
        self._task.async_val = 60
        self._task.poll = 5
        async_result = self._execute_module(
            module_name='ansible.windows.win_powershell',
            module_args={
                'script': 'Enable-PSRemoting -Force',
                'error_action': 'stop',
                'executable': 'pwsh',
                'depth': 1,
            },
            task_vars=task_vars,
        )
        jid = async_result['ansible_job_id']

        # Turn off async so we don't run the following actions as async
        self._task.async_val = 0
        wait_for_action = self._get_action_task('wait_for_connection', {
            'timeout': 60,
            'sleep': 5,
        })
        status_action = self._get_action_task('async_status', {
            'jid': jid,
            'mode': 'status',
        })

        tries = 0
        while True:
            try:
                # check up on the async job
                job_status = status_action.run(task_vars=task_vars)

                if job_status.get('failed', False):
                    res.update(job_status)  # Includes the failure information
                    break

                if job_status.get('finished', False):
                    break

                time.sleep(self._task.poll)

            except Exception as e:
                tries += 1
                if tries == 5:
                    return {
                        'msg': f'Unknown failure while waiting for task to complete: {e!s}',
                        'exception': traceback.format_exc(),
                    }

                display.vvvv(f'Failure while waiting for task to complete (running wait_for_connection): {e!s}')
                wait_for_action.run(task_vars=task_vars)

        cleanup_action = self._get_action_task('async_status', {
            'jid': jid,
            'mode': 'cleanup',
        })
        try:
            cleanup_res = cleanup_action.run(task_vars=task_vars)
            if cleanup_res.get('failed', False):
                display.warning(f"Clean up of async status failed on the remote host: {cleanup_res.get('msg', cleanup_res)}")

        except Exception as e:
            display.warning(f"Clean up of async status failed on the remote host: {e}")

        return res

    def _get_action_task(
        self,
        action: str,
        action_args: Dict,
    ):
        action_task = self._task.copy()
        action_task.args = action_args

        return self._shared_loader_obj.action_loader.get(
            action,
            task=action_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj
        )
