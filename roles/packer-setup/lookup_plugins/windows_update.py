# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
lookup: windows_update
author: Jordan Borean (@jborean93)
hort_description: Search for updates on the Microsoft Update Catalog.
description:
- Searches for updates on the Microsoft Update Catalog.
- The search terms are fairly rudimentary due to a limitation of the server side.
requirements:
- beautifulsoup4
options:
  _terms:
    description:
    - The search string to search for on the Microsoft update catalog.
    required: True
    type: str
  all:
    description:
    - Whether to retrieve all updates available or just the first 25 returning.
    - Setting to C(True) can result in a lot more mores to the update catalog itself and will take some time for large
      results to be returned.
    type: bool
    default: False
  architecture:
    description:
    - Filter the updates returned by architecture they are for.
    - Typical values are C(amd64) and C(x86).
    type: str
  ascending:
    description:
    - Whether to sort in ascending order if I(sort) is set.
    - Setting C(False) will sort the field specified by I(sort) in descending order. This results in another call
      request to the Microsoft Update Catalog.
    type: bool
    default: True
  product:
    description:
    - Filter the updates returned by the product they are for.
    type: str
  sort:
    description:
    - Sort the results by the header specified.
    - Sorting by any field will result in an extra request to the Microsoft Update Catalog.
    - Control the sort order with I(ascending).
    type: str
    choices:
    - title
    - products
    - classification
    - last_updated
    - version
    - size
"""

import contextlib
import datetime
import json
import re
import traceback
import uuid

from ansible.errors import AnsibleLookupError
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.urls import open_url
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six.moves import urllib

BS_IMP_ERR = None
try:
    from bs4 import BeautifulSoup
    HAS_BS = True
except ImportError:
    BS_IMP_ERR = traceback.format_exc()
    HAS_BS = False


CATALOG_URL = 'https://www.catalog.update.microsoft.com/'
DOWNLOAD_PATTERN = re.compile(r'\[(\d*)\]\.url = [\"\'](http[s]?://w{0,3}.?download\.windowsupdate\.com/[^\'\"]*)')
PRODUCT_SPLIT_PATTERN = re.compile(r',(?=[^\s])')


@contextlib.contextmanager
def urlopen(*args, **kwargs):
    resp = open_url(*args, http_agent='packer-windoze/%s' % __name__, **kwargs)
    try:
        yield resp
    finally:
        resp.close()


class WUDownloadInfo:

    def __init__(self, download_id, url, raw):
        """
        Contains information about an individual download link for an update. An update might have multiple download
        links available and this keeps track of the metadata for each of them.

        :param download_id: The ID that relates to the download URL.
        :param url: The download URL for this entry.
        :param raw: The raw response text of the downloads page.
        """
        self.url = url
        self.digest = None
        self.architectures = None
        self.languages = None
        self.long_languages = None
        self.file_name = None

        attribute_map = {
            'digest': 'digest',
            'architectures': 'architectures',
            'languages': 'languages',
            'long_languages': 'longLanguages',
            'file_name': 'fileName',
        }
        for attrib_name, raw_name in attribute_map.items():
            regex_pattern = r"\[%s]\.%s = ['\"]([\w\-\.=+\/\(\) ]*)['\"];" % (
            re.escape(download_id), re.escape(raw_name))
            regex_match = re.search(regex_pattern, raw)
            if regex_match:
                setattr(self, attrib_name, regex_match.group(1))

    def __str__(self):
        return to_native("%s - %s" % (self.file_name or "unknown", self.long_languages or "unknown language"))


class WindowsUpdate:

    def __init__(self, raw_element):
        """
        Stores information about a Windows Update entry.

        :param raw_element: The raw XHTML element that has been parsed by BeautifulSoup4.
        """
        cells = raw_element.find_all('td')

        self.title = cells[1].get_text().strip()

        # Split , if there is no space ahead.
        products = cells[2].get_text().strip()
        self.products = list(filter(None, re.split(PRODUCT_SPLIT_PATTERN, products)))

        self.classification = cells[3].get_text().strip()
        self.last_updated = datetime.datetime.strptime(cells[4].get_text().strip(), '%m/%d/%Y')
        self.version = cells[5].get_text().strip()
        self.size = int(cells[6].find_all('span')[1].get_text().strip())
        self.id = uuid.UUID(cells[7].find('input').attrs['id'])
        self._details = None
        self._architecture = None
        self._description = None
        self._download_urls = None
        self._kb_numbers = None
        self._more_information = None
        self._msrc_number = None
        self._msrc_severity = None
        self._support_url = None

    @property
    def architecture(self):
        """ The architecture of the update. """
        if not self._architecture:
            details = self._get_details()
            raw_arch = details.find(id='ScopedViewHandler_labelArchitecture_Separator')
            self._architecture = raw_arch.next_sibling.strip()

        return self._architecture

    @property
    def description(self):
        """ The description of the update. """
        if not self._description:
            details = self._get_details()
            self._description = details.find(id='ScopedViewHandler_desc').get_text()

        return self._description

    @property
    def download_url(self):
        """ The download URL of the update, will fail if the update contains multiple packages. """
        download_urls = self.get_download_urls()

        if len(download_urls) != 1:
            raise ValueError("Expecting only 1 download link for '%s', received %d. Use get_download_urls() and "
                             "filter it based on your criteria." % (str(self), len(download_urls)))

        return download_urls[0].url

    @property
    def kb_numbers(self):
        """ A list of KB article numbers that apply to the update. """
        if self._kb_numbers is None:
            details = self._get_details()
            raw_kb = details.find(id='ScopedViewHandler_labelKBArticle_Separator')

            # If no KB's apply then the value will be n/a. Technically an update can have multiple KBs but I have
            # not been able to find an example of this so cannot test that scenario.
            self._kb_numbers = [int(n.strip()) for n in list(raw_kb.next_siblings) if n.strip().lower() != 'n/a']

        return self._kb_numbers

    @property
    def more_information(self):
        """ Typically the URL of the KB article for the update but it can be anything. """
        if self._more_information is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelMoreInfo_Separator')
            self._more_information = list(raw_info.next_siblings)[1].get_text().strip()

        return self._more_information

    @property
    def msrc_number(self):
        """ The MSRC Number for the update, set to n/a if not defined. """
        if self._msrc_number is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSecurityBulliten_Separator')
            self._msrc_number = list(raw_info.next_siblings)[0].strip()

        return self._msrc_number

    @property
    def msrc_severity(self):
        """ THe MSRC severity level for the update, set to Unspecified if not defined. """
        if self._msrc_severity is None:
            details = self._get_details()
            self._msrc_severity = details.find(id='ScopedViewHandler_msrcSeverity').get_text().strip()

        return self._msrc_severity

    @property
    def support_url(self):
        """ The support URL for the update. """
        if self._support_url is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSupportUrl_Separator')
            self._support_url = list(raw_info.next_siblings)[1].get_text().strip()

        return self._support_url

    def get_download_urls(self):
        """
        Get a list of WUDownloadInfo objects for the current update. These objects contain the download URL for all the
        packages inside the update.
        """
        if self._download_urls is None:
            update_ids = json.dumps({
                'size': 0,
                'updateID': str(self.id),
                'uidInfo': str(self.id),
            })
            data = to_bytes(urllib.parse.urlencode({'updateIDs': '[%s]' % update_ids}))

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            linkFound = False
            while not linkFound:
                with urlopen('%s/DownloadDialog.aspx' % CATALOG_URL, data=data,
                            headers=headers, timeout=120) as resp:
                    resp_text = to_text(resp.read()).strip()

                link_matches = re.findall(DOWNLOAD_PATTERN, resp_text)
                if len(link_matches) == 0:
                    # raise ValueError("Failed to find any download links for '%s'" % str(self))
                    #display.v("Download link not found - read it again")
                    linkFound = False
                else:
                    linkFound = True

            download_urls = []
            for download_id, url in link_matches:
                download_urls.append(WUDownloadInfo(download_id, url, resp_text))

            self._download_urls = download_urls

        return self._download_urls

    def _get_details(self):
        if not self._details:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            bodyOK = False
            while not bodyOK:
                with urlopen('%s/ScopedViewInline.aspx?updateid=%s' % (CATALOG_URL, str(self.id)),
                            headers=headers, timeout=120) as resp:
                    resp_text = to_text(resp.read()).lstrip()
                self._details = BeautifulSoup(resp_text, 'html.parser')

                body_class_list = self._details.body['class']
                if "error" in body_class_list:
                    #display.vv("Page error  - read it again")
                    bodyOK = False
                else:
                    bodyOK = True

        return self._details

    def __str__(self):
        return self.title


def find_updates(search, all_updates=False, sort=None, sort_reverse=False, data=None):
    """
    Generator function that yields WindowsUpdate objects for each update found on the Microsoft Update catalog.
    Yields a list of updates from the Microsoft Update catalog. These updates can then be downloaded locally using the
    .download(path) function.

    :param search: The search string used when searching the update catalog.
    :param all_updates: Set to True to continue to search on all pages and not just the first 25. This can dramatically
        increase the runtime of the script so use with caution.
    :param sort: The field name as seen in the update catalog GUI to sort by. Setting this will result in 1 more call
        to the catalog URL.
    :param sort_reverse: Reverse the sort after initially sorting it. Setting this will result in 1 more call after
        the sort call to the catalog URL.
    :param data: Data to post to the request, used when getting all pages
    :return: Yields the WindowsUpdate objects found.
    """
    search_safe = urllib.parse.quote(search)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    if data:
        data = to_bytes(urllib.parse.urlencode(data))

    url = '%s/Search.aspx?q=%s' % (CATALOG_URL, search_safe)
    with urlopen(url, data=data, headers=headers) as resp:
        resp_text = to_text(resp.read()).lstrip()

    catalog = BeautifulSoup(resp_text, 'html.parser')

    # If we need to perform an action (like sorting or next page) we need to add these 4 fields that are based on the
    # original response received.
    def build_action_data(action):
        data = {
            '__EVENTTARGET': action,
        }
        for field in ['__EVENTARGUMENT', '__EVENTVALIDATION', '__VIEWSTATE', '__VIEWSTATEGENERATOR']:
            element = catalog.find(id=field)
            if element:
                data[field] = element.attrs['value']

        return data

    raw_updates = catalog.find(id='ctl00_catalogBody_updateMatches').find_all('tr')
    headers = raw_updates[0]  # The first entry in the table are the headers which we may use for sorting.

    if sort:
        # Lookup the header click JS targets based on the header name to sort.
        header_links = headers.find_all('a')
        event_targets = dict((l.find('span').get_text(), l.attrs['id'].replace('_', '$')) for l in header_links)
        data = build_action_data(event_targets[sort])

        sort = sort if sort_reverse else None  # If we want to sort descending we need to sort it again.
        for update in find_updates(search, all_updates, sort=sort, data=data):
            yield update
        return

    for u in raw_updates[1:]:
        yield WindowsUpdate(u)

    # ctl00_catalogBody_nextPage is set when there are no more updates to retrieve.
    last_page = catalog.find(id='ctl00_catalogBody_nextPage')
    if not last_page and all_updates:
        data = build_action_data('ctl00$catalogBody$nextPageLinkText')
        for update in find_updates(search, True, data=data):
            yield update


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        if not HAS_BS:
            msg = missing_required_lib("beautifulsoup4", url="https://pypi.org/project/beautifulsoup4/")
            msg += ". Import Error: %s" % BS_IMP_ERR
            raise AnsibleLookupError(msg)

        self.set_options(var_options=variables, direct=kwargs)
        all_updates = self.get_option('all')
        architecture = self.get_option('architecture')
        ascending = self.get_option('ascending')
        product = self.get_option('product')
        sort = self.get_option('sort')

        if sort:
            # Map the lookup plugin's option title choices to the actual titles as returned in the XML.
            sort = {
                'title': 'Title',
                'products': 'Products',
                'classification': 'Classification',
                'last_updated': 'Last Updated',
                'version': 'Version',
                'size': 'Size',
            }[sort]

        ret = []
        for search in terms:
            for update in find_updates(search, all_updates, sort=sort, sort_reverse=not ascending):
                if product and product not in update.products:
                    continue
                if architecture and architecture.lower() != update.architecture.lower():
                    continue
                ret.append(update)

        return ret
