import config

def setup_module():
    pass

def teardown_module():
    pass

def test_config():
    assert config.getSetting('setup', 'eth') == 'ens33'
    assert config.getSetting('setup', 'ignore').split(',') == ['value1', 'value2', 'value3']



