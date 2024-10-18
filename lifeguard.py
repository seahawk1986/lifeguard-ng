#!/usr/bin/python3
import subprocess
import configparser
import psutil
import os
import sys
import re


if int(psutil.__version__.replace(".", "")) < 60:
    print("requires psutil >= 0.6.0")
    exit(1)
from gi.repository import GLib
import threading
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop


class IP_Check(threading.Thread):
    def __init__(self, ip):
        threading.Thread.__init__(self)
        self.ip = ip
        self.__successful_pings = -1

    def run(self):
        self.ping = subprocess.call(
            ["ping", "-c", "1", "-W", "250", self.ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    def status(self):
        return not bool(self.ping)


class Main(dbus.service.Object):
    def __init__(self, config='/etc/lifeguard.conf'):
        self.wakeupTimer = {}
        self.bus = dbus.SystemBus()
        bus_name = dbus.service.BusName('org.yavdr.lifeguard', bus=self.bus)
        dbus.service.Object.__init__(self, bus_name, '/Lifeguard')
        self.init_parser(config)
        self.config = config
        self.matchFiles = re.compile(
            r'(\d+)\s+\d+\s+\S+\s+0x\S+\s+\S+\s+\S+\s+(\S+)\s+(.*?)\s{3}.*?$',
            re.M | re.I
        )

    def init_parser(self, config):
        self.hostnames = []
        self.users = []
        self.processnames = []
        self.inet = {}
        self.samba = []
        self.time = []
        self.enableSamba = False
        self.enableNFS = False
        self.enableSSH = False
        self.parser = configparser.ConfigParser(
            delimiters=(" ", ":", "="),
            allow_no_value=True,
            interpolation=None
        )
        self.parser.optionxform = str
        with open(config, 'r', encoding='utf-8') as f:
            self.parser.read_file(f)
        self.get_settings()

    def get_settings(self):
        if self.parser.has_section("Hosts"):
            for host, description in self.parser.items("Hosts"):
                self.hostnames.append(host)
        if self.parser.has_section("Options"):
            self.enableSamba = self.parser.getboolean(
                'Options',
                'EnableSamba',
                fallback = False
            )
            self.enableNFS = self.parser.getboolean(
                'Options',
                'EnableNFS',
                fallback = False
            )
            self.enableSSH = self.parser.getboolean(
                'Options',
                'EnableSSH',
                fallback = False
            )
        if self.parser.has_section("Process"):
            for process, description in self.parser.items("Process"):
                self.processnames.append(process)
        if self.parser.has_section("TCP"):
            for connection, ports in self.parser.items("TCP"):
                portlist = ports.split()
                self.inet[connection] = [int(port.strip()
                                             ) for port in portlist]
        if self.parser.has_section("User"):
            for user, description in self.parser.items("User"):
                self.users.append(user)

    def check_hosts(self):
        check_results = []
        for host in self.hostnames:
            ip = host
            current = IP_Check(ip)
            check_results.append(current)
            current.start()
        for el in check_results:
            el.join()
            if el.status() is True:
                return el.ip

    def check_user(self):
        for user in psutil.users():
            if user.name in self.users:
                return user.name

    def check_nfs(self):
        if self.enableNFS is True:
            # alternative NFS recognition
            p = subprocess.run(
                ['ss', '-t', '-o', 'state', 'established'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            for line in p.stdout.splitlines():
                recv_q, send_q, local, remote, *_ = line.split()
                if local.endswith(":nfs") or local.endswith(":shilp"):
                    return remote

    def check_process(self):
        if len(self.processnames) > 0:
            for process in psutil.process_iter():
                pname = process.as_dict(attrs=['name'])['name']
                if pname in self.processnames:
                    return pname

    def check_tcp(self):
        connectionl = [(p.connections(), p.as_dict(attrs=['name'])['name']
                        ) for p in psutil.process_iter() if p.as_dict(
                            attrs=['name'])['name'] in self.inet.keys()]
        for c, pname in connectionl:
            connections = []
            connections.extend(c)
            for c in connections:
                if c.status == "ESTABLISHED" and c.laddr[1] in self.inet[pname]:
                    return f"{pname} on port {c.laddr[1]}"

    def check_ssh(self):
        if self.enableSSH is True:
            for p in [
                p for p in psutil.process_iter() if "sshd" == p.as_dict(
                    attrs=['name'])['name']]:
                for con in p.connections():
                    if "ESTABLISHED" in con.status:
                        return con.raddr[0]

    def check_samba(self):
        """http://swick.2flub.org/smbstatus-Ausgabe-pro-User-statt-PID"""
        if self.enableSamba is True:
            p = subprocess.run(
                'smbstatus',
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            USERS = {}
            for line in p.stdout.splitlines():
                f = self.matchFiles.match(line)
                if f:
                    basename = f.group(2)
                    filename = f.group(3)
                    if filename == '.':
                        filename = ''
                    return os.path.join(basename, filename)

    def check_systemd_inhibitors(self):
        """check inhibitors set by systemd/logind"""
        login1 = self.bus.get_object('org.freedesktop.login1',
                                    '/org/freedesktop/login1')
        interface = 'org.freedesktop.login1.Manager'
        inhibitors = login1.ListInhibitors(dbus_interface=interface)
        for inhibitor in inhibitors:
            what, who, why, inhibitor_type, *_ = inhibitors[0]
            if inhibitor_type != 'block':
                continue
            if 'shutdown' in what or 'sleep' in what:
                return f"{who}: {why}"


    @dbus.service.method('org.yavdr.lifeguard', out_signature='bs')
    def CheckVDR(self):
        print(self.EnableNFS)
        files = psutil.Process(
            (
                next(
                    (
                        p.pid for p in psutil.process_iter()
                        if "vdr" == str(p.name)
                    ),
                    None
                )
            )
        ).get_open_files()
        return(
            next(
                (
                    (False, "VDR has lock in video dir") for file
                    in files if file.path.endswith(("/index", ".ts"))
                ),
                (
                    True, "no file locks in video dir"
                )
            )
        )

    @dbus.service.method('org.yavdr.lifeguard', out_signature='bs')
    def Check(self):
        self.init_parser(self.config)
        checkf = {
            self.check_process: "process {0} active",
            self.check_samba: "Samba share {0} active",
            self.check_nfs: "NFS share {0} active",
            self.check_tcp: "tcp connection: {0} active",
            self.check_ssh: "SSH connection from {0} active",
            self.check_user: "User {0} still logged in",
            self.check_hosts: "host {0} still alive",
            self.check_systemd_inhibitors: "shutdown inhibited by {0}",
        }
        for f, s in checkf.items():
            result = f()
            if result is not None:
                return False, s.format(result)
        return True, "shutdown possible"

if __name__ == '__main__':
    DBusGMainLoop(set_as_default=True)
    main = Main()
    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        loop.quit()
