import logging
import json
import os
import glob
from datetime import datetime

import pwnagotchi
import pwnagotchi.plugins as plugins

from flask import abort
from flask import send_from_directory
from flask import render_template_string

TEMPLATE = """
{% extends "base.html" %}
{% set active_page = "handshakes" %}

{% block title %}
    {{ title }}
{% endblock %}

{% block styles %}
    {{ super() }}
    <style>
        #filter {
            width: 100%;
            font-size: 16px;
            padding: 12px 20px 12px 40px;
            border: 1px solid #ddd;
            margin-bottom: 12px;
        }
    </style>
{% endblock %}
{% block script %}
    var shakeList = document.getElementById('list');
    var filter = document.getElementById('filter');
    var filterVal = filter.value.toUpperCase();

    filter.onkeyup = function() {
        document.body.style.cursor = 'progress';
        var table, tr, tds, td, i, txtValue;
        filterVal = filter.value.toUpperCase();
        li = shakeList.getElementsByTagName("li");
        for (i = 0; i < li.length; i++) {
            txtValue = li[i].textContent || li[i].innerText;
            if (txtValue.toUpperCase().indexOf(filterVal) > -1) {
                li[i].style.display = "list-item";
            } else {
                li[i].style.display = "none";
            }
        }
        document.body.style.cursor = 'default';
    }

{% endblock %}

{% block content %}
    <input type="text" id="filter" placeholder="Search for ..." title="Type in a filter">
    <ul id="list" data-role="listview" style="list-style-type:disc;">
        {% for handshake in handshakes %}
            <li class="file">
                {% if handshake[2] == "" %}
                <a href="/plugins/handshakes-dl/{{handshake[1]}}">{{"<" + handshake[0] + "> " + handshake[1]}}</a>
                {% else %}
                <a href="/plugins/handshakes-dl/{{handshake[1]}}" style="color:green">{{"<" + handshake[0] + "> " + handshake[1] + " : " + handshake[2]}}</a>
                {% endif %}
            </li>
        {% endfor %}
    </ul>
{% endblock %}
"""

class HandshakesDL(plugins.Plugin):
    __author__ = 'me@sayakb.com'
    __version__ = '0.2.1'
    __license__ = 'GPL3'
    __description__ = 'Download hadshake captures from web-ui.'

    def __init__(self):
        self.ready = False

    def on_loaded(self):
        logging.info("[HandshakesDL] plugin loaded")

    def on_config_changed(self, config):
        self.config = config
        self.ready = True

    def on_webhook(self, path, request):
        if not self.ready:
            return "Plugin not ready"

        if path == "/" or not path:
            handshakes = glob.glob(os.path.join(self.config['bettercap']['handshakes'], "*.pcap"))
            handshakes.sort(key=lambda x: os.path.getmtime(x))
            handshakes.reverse()
            handshakes_date = [(os.path.basename(h)[:-5], datetime.fromtimestamp(os.path.getmtime(h)).strftime('%Y.%m.%d %H-%M-%S')) for h in handshakes]
            cracked = glob.glob(os.path.join(self.config['bettercap']['handshakes'], "*.pcap.cracked"))
            cracked = {os.path.basename(path)[:-13] for path in cracked}
            handshakes_pswd = []

            for handshake, date in handshakes_date:
                if handshake in cracked:
                    with open(self.config['bettercap']['handshakes'] + "/" + handshake + ".pcap.cracked") as f:
                        pswd = f.readlines()[0]
                    handshakes_pswd.append((date, handshake, pswd))
                else:
                    handshakes_pswd.append((date, handshake, ""))
            try:
                return render_template_string(TEMPLATE,
                                        title="Handshakes | " + pwnagotchi.name(),
                                        handshakes=handshakes_pswd)
            except BaseException as ba:
                return str(ba)

        else:
            dir = self.config['bettercap']['handshakes']
            try:
                logging.info(f"[HandshakesDL] serving {dir}/{path}.pcap")
                return send_from_directory(directory=dir, filename=path+'.pcap', as_attachment=True)
            except FileNotFoundError:
                abort(404)

if __name__ == "__main__":
    hdl = HandshakesDL()
    hdl.ready = True
    hdl.config = {}
    hdl.config["bettercap"] = {}
    hdl.config["bettercap"]['handshakes'] = "handshakes"
    hdl.on_webhook("/", None)