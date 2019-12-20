# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class FilterModule:

    def filters(self):
        return {
            'update_dict': self.update_dict,
            'merge_dict': self.merge_dict,
        }

    def update_dict(self, old_dict, key, value):
        old_dict[key] = value
        return old_dict

    def merge_dict(self, old_dict, new_dict):
        old_dict.update(new_dict)
        return old_dict
