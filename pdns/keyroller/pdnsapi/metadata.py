class ZoneMetadata:
    def __init__(self, kind, metadata, type="Metadata"):
        self.kind = kind
        if not isinstance(metadata, list):
            raise Exception('metadata must be a list, not a {}'.format(type(metadata)))
        self.metadata = metadata

    def empty(self):
        return not self.metadata

    def __repr__(self):
        return 'ZoneMetadata({}, {})'.format(self.kind, self.metadata)

    def __str__(self):
        return str({
            'kind': self.kind,
            'metadata': self.metadata
        })
