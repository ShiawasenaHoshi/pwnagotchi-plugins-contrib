import logging
import os
import string
import subprocess

import pwnagotchi.plugins as plugins

'''
Aircrack-ng needed, to install:
> apt-get install aircrack-ng
'''

LOG_PREFIX = "[AircrackOnly]"
CMD_CHECK_AIRCRACK_NG = '/usr/bin/dpkg -l aircrack-ng | grep aircrack-ng | awk \'{{print $2, $3}}\''


class AircrackOnly(plugins.Plugin):
    __author__ = 'pwnagotchi [at] rossmarks [dot] uk'
    __version__ = '1.0.1'
    __license__ = 'GPL3'
    __description__ = 'confirm pcap contains handshake/PMKID or delete it'

    def __init__(self):
        self.text_to_set = ""

    def on_loaded(self):
        logging.info("aircrackonly plugin loaded")

        if 'face' not in self.options:
            self.options['face'] = '(>.<)'

        check = subprocess.run((CMD_CHECK_AIRCRACK_NG), shell=True, stdout=subprocess.PIPE)
        check = check.stdout.decode('utf-8').strip()
        if check != "aircrack-ng <none>":
            logging.info(f"{LOG_PREFIX}: Found {check}")
        else:
            logging.warning(f"{LOG_PREFIX}: aircrack-ng is not installed!")

    def on_handshake(self, agent, filename, access_point, client_station):
        display = agent._view
        todelete = 0
        handshakeFound = 0

        result = subprocess.run(('/usr/bin/aircrack-ng ' + filename + ' | grep "1 handshake" | awk \'{print $2}\''),
                                shell=True, stdout=subprocess.PIPE)
        result = result.stdout.decode('utf-8').translate({ord(c): None for c in string.whitespace})
        if result:
            handshakeFound = 1
            logging.info(f"{LOG_PREFIX}: {filename} contains handshake")

        if handshakeFound == 0:
            result = subprocess.run(('/usr/bin/aircrack-ng ' + filename + ' | grep "PMKID" | awk \'{print $2}\''),
                                    shell=True, stdout=subprocess.PIPE)
            result = result.stdout.decode('utf-8').translate({ord(c): None for c in string.whitespace})
            if result:
                logging.info(f"{LOG_PREFIX}: {filename} contains PMKID")
            else:
                todelete = 1

        if todelete == 1:
            os.remove(filename)
            self.text_to_set = "Removed an uncrackable pcap"
            logging.warning(f"{LOG_PREFIX}: Removed uncrackable pcap {filename}")
            display.update(force=True)

    def on_ui_update(self, ui):
        if self.text_to_set:
            ui.set('face', self.options['face'])
            ui.set('status', self.text_to_set)
            self.text_to_set = ""


if __name__ == "__main__":
    p = AircrackOnly()
    p.options = {}

    class Display:
        def update(self, force):
            pass


    class Agent:
        _view = Display()

        def view(self):
            return Display()

    p.on_loaded()

    from shutil import copyfile

    copyfile("no_hs.pcap", "no_hs_del.pcap")
    p.on_handshake(Agent(), "no_hs_del.pcap", "no hs AP", "")
    p.on_handshake(Agent(), "hs.pcap", "AP", "")
