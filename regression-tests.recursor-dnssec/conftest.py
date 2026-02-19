import os
import shutil
from recursortests import RecursorTest
import pytest

@pytest.fixture(scope='session')
def run_auths() -> str:
    confdir = 'configs/auths'
    shutil.rmtree(confdir, True)
    os.mkdir(confdir)
    print('\nStarting auths from fixture...')
    RecursorTest.generateAllAuthConfig(confdir)
    RecursorTest.startAllAuth(confdir)
    yield "Here's Johnny!"
    print('\nStopping auths by fixture')
    RecursorTest.tearDownAuth()
