import os
import shutil
from recursortests import RecursorTest
import pytest

@pytest.fixture(scope='session', autouse=True)
def run_auths() -> str:
    confdir = 'configs/auths'
    shutil.rmtree(confdir, True)
    os.mkdir(confdir)
    print('Starting auths from fixture..')
    RecursorTest.generateAllAuthConfig(confdir)
    RecursorTest.startAllAuth(confdir)
    yield "foo"
    print('\nStopping auths by fixture')
    RecursorTest.tearDownAuth()
