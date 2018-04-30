class FilterModule(object):
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
