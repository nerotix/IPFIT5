import ConfigParser
"""
class that handles reading the config.ini file.
"""
def getConfig():
    """
    :return: the config object
    """
    config = ConfigParser.ConfigParser()
    config.read("config.ini")
    return config

def getSetting(section, setting):
    """
    :param section: the section where the setting is
    :param setting: the setting to return
    :return: the value of the requested setting
    """
    config = getConfig()
    value = config.get(section, setting)
    return value



