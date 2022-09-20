class KeyRoll:
    def __init__(self, **kwargs):
        self.rolltype = kwargs.get('rolltype')
        self.complete = False

    def initiate(self, zone, api, **kwargs):
        raise NotImplementedError()

    def step(self, zone, api):
        raise NotImplementedError()

    def validate(self, zone, api):
        raise NotImplementedError()

    def __str__(self):
        return ''

    def __repr__(self):
        raise NotImplementedError()

    @property
    def started(self):
        return False

    @property
    def current_step_name(self):
        raise NotImplementedError()
