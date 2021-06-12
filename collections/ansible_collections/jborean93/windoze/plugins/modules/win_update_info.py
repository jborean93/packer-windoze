#!/usr/bin/python

# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

DOCUMENTATION = r'''
module: win_update_info:
short_description: Get Windows Update information
description:
- Gets Windows Update information from the Microsoft Update catalog.
options:
  name:
    description:
    - A list of search terms to search in the update catalog.
    - The results of each search term are a list in the C(updates) return result.
    type: list
    elements: str
    required: True
  architecture:
    description:
    - The architecture each update should match.
    - If the update arch does not match this value then it is not returned.
    type: str
  product:
    description:
    - The update product to filter the update results by.
    type: str
  ignore_terms:
    description:
    - Filter the found update titles with thse regex terms.
    - If matched the update is skipped and not returned.
    type: list
    elements: str
  sort:
    description:
    - Whether to sort the results using these categories.
    - The sorting rules are based on the Microsoft Update Catalog site and is filtered server side.
    type: str
    choices:
    - title
    - products
    - classification
    - last_updated
    - version
    - size
requirements:
- beautifulsoup4
- httpx
author:
- Jordan Borean (@jborean93)
'''

EXAMPLES = r'''
- name: get update information
  jborean93.windoze.win_update_info:
    name:
    - Servicing Stack Update for Windows Server 2019
    - Cumulative Update for Windows Server 2019
    product: Windows Server 2019
    architecture: amd64
    sort: latest_updated
'''

RETURN = r'''
updates:
  description:
  - A list of lists containing the found updates.
  - The list entries correlate to the C(name) terms
  type: list
  elements: list
'''

import asyncio
import re

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ..module_utils import update_catalog


async def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='list', elements='str', required=True),
            architecture=dict(type='str'),
            product=dict(type='str'),
            ignore_terms=dict(type='list', elements='str'),
            sort=dict(type='str', choices=['title', 'products', 'classification', 'last_updated', 'version', 'size']),
        ),
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        updates=[],
    )

    arch = (module.params['architecture'] or '').lower()
    product = module.params['product']
    sort = module.params['sort']
    ignore_terms = module.params['ignore_terms'] or []
    if sort:
        sort = {
            'title': 'Title',
            'products': 'Products',
            'classification': 'Classification',
            'last_updated': 'Last Updated',
            'version': 'Version',
            'size': 'Size',
        }[sort]

    if not update_catalog.HAS_BS:
        msg = missing_required_lib("beautifulsoup4", url="https://pypi.org/project/beautifulsoup4/")
        module.fail_json(msg=msg, exception=update_catalog.BS_IMP_ERR, **result)

    if not update_catalog.HAS_HTTPX:
        msg = missing_required_lib("httpx", url="https://pypi.org/project/httpx/")
        module.fail_json(msg=msg, exception=update_catalog.BS_IMP_ERR, **result)

    async with update_catalog.get_client() as client:
        raw_updates = await asyncio.gather(*[search_update(client, n, sort) for n in module.params['name']])

        for updates in raw_updates:
            name_updates = []
            for update in updates:
                if product and product not in update.products:
                    continue

                if arch and arch != update.architecture.lower():
                    continue

                matched = False
                for term in ignore_terms:
                    if re.search(term, update.title):
                        matched = True
                        break
                if matched:
                    continue

                name_updates.append({
                    'id': str(update.update_id),
                    'title': update.title,
                    'kb': f'KB{update.kb_numbers[0]}',
                    'url': update.download_urls[0].url,
                    'filename': update.download_urls[0].file_name,
                })

            result['updates'].append(name_updates)

    module.exit_json(**result)


async def search_update(client, search, sort):
    updates = []
    async for update in update_catalog.get_updates(client, search, sort=sort):
        updates.append(update)

    return updates


def main():
    asyncio.run(run_module())


if __name__ == '__main__':
    main()
