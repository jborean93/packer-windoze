class FilterModule(object):
    def filters(self):
        return {
            'update_dict': self.update_dict
        }

    def update_dict(self, dict, key, value):
        dict[key] = value

        return dict
