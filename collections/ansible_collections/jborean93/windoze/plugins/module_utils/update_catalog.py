# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import collections
import datetime
import json
import re
import traceback
import uuid

from typing import (
    Any,
    AsyncIterable,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)

HTTPX_IMP_ERR = None
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HTTPX_IMP_ERR = traceback.format_exc()
    HAS_HTTPX = False


BS_IMP_ERR = None
try:
    import bs4
    HAS_BS = True
except ImportError:
    BS_IMP_ERR = traceback.format_exc()
    HAS_BS = False


CATALOG_URL = 'https://www.catalog.update.microsoft.com/'
DOWNLOAD_PATTERN = re.compile(r'\[(\d*)\]\.url = [\"\'](http[s]?://w{0,3}.?download\.windowsupdate\.com/[^\'\"]*)')
PRODUCT_SPLIT_PATTERN = re.compile(r',(?=[^\s])')


class WindowsUpdate(collections.namedtuple('WindowsUpdate', [
                                               'title', 'products', 'classification', 'last_update', 'version',
                                               'size', 'update_id', 'architecture', 'description', 'download_urls',
                                               'kb_numbers', 'more_information', 'msrc_number', 'msrc_severity',
                                               'support_url',
                                           ])):

    def __str__(self):
        return self.title


class WUDownloadInfo(collections.namedtuple('WUDownloadInfo', [
                                                'url', 'digest', 'architectures', 'languages', 'long_languages',
                                                'file_name',
                                            ])):

    def __str__(self):
        return f'{self.file_name or "unknown"} - {self.long_languages or "unknown language"}'


async def _invoke_request(
    proc_func: Callable[[str], Any],
    func: Callable[[Any], Awaitable[Any]],
    *args,
    **kwargs
) -> Any:
    # The update catalog is crazy unstable and can comsetimes return an error, no response, something else. Instead we
    # just try the request multiple times until it works. Not great but I don't have time to find out a better way.
    failed_once = False

    while True:
        try:
            resp = await func(*args, **kwargs)
            resp_text = resp.content.decode().strip()
            return proc_func(resp_text)

        except:
            if failed_once:
                # I found that if it fails at least once adding a sleep between attempts helps.
                await asyncio.sleep(1)

            failed_once = True


async def _get_update_details(
    client: httpx.AsyncClient,
    update_id: str,
) -> bs4.BeautifulSoup:

    def proc_func(text: str) -> bs4.BeautifulSoup:
        details = bs4.BeautifulSoup(text, 'html.parser')
        body_class_list = details.body['class']
        if 'error' in body_class_list:
            raise Exception("Invalid response - try again")

        return details

    return await _invoke_request(proc_func, client.get, f'{CATALOG_URL}ScopedViewInline.aspx',
        params={'updateId': update_id})


async def _get_update_download_urls(
    client: httpx.AsyncClient,
    update_id: str,
) -> List[WUDownloadInfo]:

    def proc_func(text: str) -> Tuple[str, List]:
        link_matches = re.findall(DOWNLOAD_PATTERN, text)
        if len(link_matches):
            return text, link_matches

        else:
            raise Exception("Invalid response - try again")

    update_ids = json.dumps({
        'size': 0,
        'updateID': update_id,
        'uidInfo': update_id,
    })
    resp_text, link_matches = await _invoke_request(proc_func, client.post, f'{CATALOG_URL}DownloadDialog.aspx',
        data={'updateIDs': f'[{update_ids}]'})

    urls = []
    for download_id, url in link_matches:
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

            regex_match = re.search(regex_pattern, resp_text)
            if regex_match:
                attribute_map[attrib_name] = regex_match.group(1)

            else:
                attribute_map[attrib_name] = None

        urls.append(WUDownloadInfo(url, **attribute_map))

    return urls


async def _parse_raw_update(
    client: httpx.AsyncClient,
    raw_element: bs4.Tag,
) -> WindowsUpdate:
    cells = raw_element.find_all('td')

    update_id = cells[7].find('input').attrs['id']
    details, download_urls = await asyncio.gather(
        _get_update_details(client, update_id),
        _get_update_download_urls(client, update_id),
    )

    raw_kb = details.find(id='ScopedViewHandler_labelKBArticle_Separator')
    # If no KB's apply then the value will be n/a. Technically an update can have multiple KBs but I have
    # not been able to find an example of this so cannot test that scenario.
    kb_numbers = [int(n.strip()) for n in list(raw_kb.next_siblings) if n.strip().lower() != 'n/a']

    raw_info = details.find(id='ScopedViewHandler_labelMoreInfo_Separator')
    raw_msrc_number = details.find(id='ScopedViewHandler_labelSecurityBulliten_Separator')
    raw_support_url = details.find(id='ScopedViewHandler_labelSupportUrl_Separator')

    return WindowsUpdate(
        title=cells[1].get_text().strip(),
        products=list(filter(None, re.split(PRODUCT_SPLIT_PATTERN, cells[2].get_text().strip()))),
        classification=cells[3].get_text().strip(),
        last_update=datetime.datetime.strptime(cells[4].get_text().strip(), '%m/%d/%Y'),
        version=cells[5].get_text().strip(),
        size=int(cells[6].find_all('span')[1].get_text().strip()),
        update_id=uuid.UUID(update_id),
        architecture=details.find(id='ScopedViewHandler_labelArchitecture_Separator').next_sibling.strip(),
        description=details.find(id='ScopedViewHandler_desc').get_text(),
        download_urls=download_urls,
        kb_numbers=kb_numbers,
        more_information=list(raw_info.next_siblings)[1].get_text().strip(),
        msrc_number=list(raw_msrc_number.next_siblings)[0].strip(),
        msrc_severity=details.find(id='ScopedViewHandler_msrcSeverity').get_text().strip(),
        support_url=list(raw_support_url.next_siblings)[1].get_text().strip(),
    )


async def get_updates(
    client: httpx.AsyncClient,
    search: str,
    all_updates: bool = False,
    sort: Optional[str] = None,
    sort_reverse: bool = False,
    data: Dict = None,
) -> AsyncIterable[WindowsUpdate]:
    """Gets all updates based on the search criteria.

    Async generator function that outputs WindowsUpdate objects for each
    update found on the Microsoft Update catalog.

    Args:
        search: The search string to use when searching the update catalog.
        all_updates: Set to True to yield all updates and not just the first
            25. This can increase the runtime quite dramatically so use with
            caution.
        sort: The field name as seen in the update catalog GUI to sort by.
        sort_reverse: Reverse the sort order if sort is set.
        data: Data to post to the request, used internally.

    Returns:
        (AsyncIterable[WindowsUpdate]): An async iterable that yields a
            WindowsUpdate object for each update found.
    """
    resp = await client.post(f'{CATALOG_URL}Search.aspx', data=data, params={'q': search})
    resp_text = resp.content.decode().lstrip()
    catalog = bs4.BeautifulSoup(resp_text, 'html.parser')

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

    matches = catalog.find(id='ctl00_catalogBody_updateMatches')
    if not matches:
        return
    raw_updates = matches.find_all('tr')

    if sort:
        # Lookup the header click JS targets based on the header name to sort.
        headers = raw_updates[0]  # The first entry in the table are the headers which we may use for sorting.
        header_links = headers.find_all('a')
        event_targets = dict((l.find('span').get_text(), l.attrs['id'].replace('_', '$')) for l in header_links)
        data = build_action_data(event_targets[sort])

        sort = sort if sort_reverse else None  # If we want to sort descending we need to sort it again.
        async for update in get_updates(client, search, all_updates=all_updates, sort=sort, data=data):
            yield update

        return

    # Would like to use asyncio.as_completed but we do care about the order here
    coros = [_parse_raw_update(client, u) for u in raw_updates[1:]]
    for update in await asyncio.gather(*coros):
        yield update

    # ctl00_catalogBody_nextPage is set when there are no more updates to retrieve.
    last_page = catalog.find(id='ctl00_catalogBody_nextPage')
    if not last_page and all_updates:
        data = build_action_data('ctl00$catalogBody$nextPageLinkText')
        async for update in get_updates(client, search, all_updates=True, data=data):
            yield update


def get_client() -> httpx.AsyncClient:
    """Returns a httpx client that can be used with get_updates()."""
    transport = httpx.AsyncHTTPTransport(
        limits=httpx.Limits(max_keepalive_connections=5),
        retries=5,
    )
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'packet-windoze',
    }
    return httpx.AsyncClient(headers=headers, timeout=30, transport=transport)
