# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re


class FilterModule:

    def filters(self):
        return {
            'parse_update': self.parse_update,
        }

    def parse_update(self, update, filename_pattern=None):
        """ Converts a WindowsUpdate object in the windows_update lookup to a simple dict with the KB and URL."""
        kb_numbers = update.kb_numbers
        download_urls = update.get_download_urls()

        if filename_pattern:
            matched_urls = []
            for download_info in download_urls:
                if re.match(filename_pattern, download_info.file_name):
                    matched_urls.append(download_info.url)
        else:
            matched_urls = [d.url for d in download_urls]

        if len(matched_urls) != 1:
            raise ValueError("Expecting only 1 download link for '%s' but found %d" % (str(update), len(matched_urls)))

        update_info = {
            'title': update.title,
            'name': 'KB%s' % kb_numbers[0] if kb_numbers else update.id,
            'url': matched_urls[0],
        }
        return update_info
