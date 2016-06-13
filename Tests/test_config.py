'''
This test is useable as template for other tests.
Start off with importing the module you want to test and any other modules you need for this.
In setup_module() you can do anything needed before the tests, this will run before each test function.
Teardown_module() can be used for cleanup after testing.
'''

import config

def setup_module():
    pass

def teardown_module():
    pass

def test_config():
    assert config.getSetting('setup', 'eth') == 'ens33'
    assert config.getSetting('setup', 'ignore').split(',') == ['value1', 'value2', 'value3']
    assert config.getSetting('dnsdb', 'endpoint') == 'https://api.dnsdb.info/'



