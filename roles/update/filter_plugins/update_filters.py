#!/usr/bin/python

class FilterModule(object):
    def filters(self):
        return {
            'update_merge': self.update_merge,
            'categories_to_list': self.categories_to_list
        }

    def update_merge(self, original_list, key, value):
        new_list = []
        for entry in original_list:
            if entry['name'] == key:
                new_list.append(
                    {
                        'name': key,
                        'finished': value
                    }
                )
            else:
                new_list.append(entry)

        return new_list

    def categories_to_list(self, update_dict):
        categories = []
        for meta in update_dict:
            categories.append(meta['name'])

        return categories
