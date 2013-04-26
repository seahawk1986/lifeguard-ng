#!/usr/bin/python3
import subprocess
import configparser
import psutil
import os
import sys
import re
if int(psutil.__version__.replace(".","")) < 60:
    print("requires psutil >= 0.7.0")
    exit(1)
from gi.repository import GObject
import threading
GObject.threads_init()
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop

class ip_check(threading.Thread):
    def __init__ (self,ip):
        threading.Thread.__init__(self)
        self.ip = ip
        self.__successful_pings = -1
    def run(self):
        self.ping = subprocess.call(["ping", "-c", "1", "-W", "250", self.ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def status(self):
        return not bool(self.ping)

class Main(dbus.service.Object):
    def __init__(self, config='/etc/lifeguard.conf'):
        self.wakeupTimer = {}
        bus_name = dbus.service.BusName('org.yavdr.lifeguard', bus=dbus.SystemBus())
        dbus.service.Object.__init__(self, bus_name, '/Lifeguard')
        self.init_parser(config)
        self.config = config
        self.matchUsers = re.compile(r'\s*(\d+)\s+([\w|\d|\S]+)\s+([\w|\d|\S]+)\s+([\w|\d|\S]+)\s+\(([\w|\d|\S]+)\)$', re.M|re.I)
        self.matchFiles = re.compile(r'(\d+)\s+\d+\s+\S+\s+0x\S+\s+\S+\s+\S+\s+(\S+)\s+(.*?)\s{3}.*?$', re.M|re.I)
        
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
        self.parser = configparser.SafeConfigParser(
                                                    delimiters=(" ", ":", "="),
                                                    allow_no_value=True,
                                                    interpolation=None
                                                    )
        self.parser.optionxform = str
        with open(config, 'r', encoding='utf-8') as f:
            self.parser.readfp(f)
        self.get_settings()
        
    def get_settings(self):
        if self.parser.has_section("Hosts"):
            [self.hostnames.append(host) for host, description in self.parser.items("Hosts")]
        if self.parser.has_section("Options"):
            self.enableSamba = self.parser.getboolean('Options', 'EnableSamba')
            self.enableNFS = self.parser.getboolean('Options', 'EnableNFS')
            self.enableSSH = self.parser.getboolean('Options', 'EnableSSH')
        if self.parser.has_section("Process"):
            [self.processnames.append(process) for process, description in self.parser.items("Process")]
        if self.parser.has_section("TCP"):
            for connection, port in self.parser.items("TCP"):
                self.inet[connection] = int(port)
        if self.parser.has_section("User"):
            [self.users.append(user) for user, description in self.parser.items("User")]

    def check_hosts(self):
        check_results = []
        for host in self.hostnames:
           ip = host
           current = ip_check(ip)
           check_results.append(current)
           current.start()
        for el in check_results:
                el.join()
                if el.status() is True:
                    return el.ip
                
    def check_user(self):
        return next((user.name for user in psutil.get_users() if user.name in self.users), None)

    def check_nfs(self):
        if self.enableNFS is True:
            p = subprocess.Popen(['showmount',"-d"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                return next((lined.replace("\n","") for lined in line.decode() if lined.startswith('/')), None)

    def check_process(self):
        if len(self.processnames) >0:
            return next((process.name for process in psutil.process_iter() if process.name in self.processnames), None)

    def check_tcp(self):
        connections = []
        connectionl = [p.get_connections() for p in psutil.process_iter()]
        for con in connectionl:
            connections.extend(con)
        for c in connections:
                result =  next((name for name, port in self.inet.items() if c.status is "ESTABLISHED" and port == c.local_address[1]), None)

    def check_ssh(self):
        if self.enableSSH is True:
            for p in [p for p in psutil.process_iter() if "sshd" in str(p.name)]:
                return next((con.remote_address[0] for con in p.get_connections() if "ESTABLISHED" in con.status), None)

    def check_samba(self):
        """thanks to http://swick.2flub.org/smbstatus-Ausgabe-pro-User-statt-PID"""
        if self.enableSamba is True:
            p = subprocess.Popen('smbstatus', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            lines = p.stdout.readlines()
            USERS = {}
            for line in lines:
                line = line.decode()
                if self.matchUsers.match(line):
                    USERS[self.matchUsers.match(line).group(1)] = self.matchUsers.match(line).group(2)
                if self.matchFiles.match(line):
                    if self.matchFiles.match(line).group(1) not in USERS:
                      USERS[self.matchFiles.match(line).group(1)] = "unknown"
                    #return USERS[self.matchFiles.match(line).group(1)] + " on " + os.path.join(self.matchFiles.match(line).group(2), self.matchFiles.match(line).group(3))
                    return os.path.join(self.matchFiles.match(line).group(2), self.matchFiles.match(line).group(3))

    @dbus.service.method('org.yavdr.lifeguard', out_signature='bs')
    def Check(self):
        self.init_parser(self.config)
        checkf = {
        self.check_process:"process {0} active",
        self.check_samba:"Samba share {0} active",
        self.check_nfs:"NFS share {0} active",
        self.check_tcp:"tcp connection: {0} active",
        self.check_ssh:"SSH connection from {0} active",
        self.check_user:"User {0} still logged in",
        self.check_hosts:"host {0} still alive",
        }
        for f, s in checkf.items():
            result = f()
            if result is not None:
                return False, s.format(result)
        return True, "shutdown possible"

if __name__ == '__main__':
    DBusGMainLoop(set_as_default=True)
    main = Main()
    loop = GObject.MainLoop()
    loop.run()
