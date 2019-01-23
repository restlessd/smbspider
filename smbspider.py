#!/usr/bin/python
# SMB Spider
# Created by T$A
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import os
import random
import socket
import sys
import tempfile
import threading
import time

from netaddr import *
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection


class ScanThread(threading.Thread):
    def __init__(self, ip, share, subfolder, user, pwd, domain, recursive, pattern, chance, delay):
        threading.Thread.__init__(self)
        self.ip = ip
        self.share = share
        self.subfolder = subfolder
        self.user = user
        self.pwd = pwd
        self.domain = domain
        self.recursive = recursive
        self.pattern = pattern
        self.chance = chance
        self.delay = delay

    def run(self):
        print("Starting thread for " + self.ip)
        net = NetBIOS()
        net_name = str(net.queryIPForName(self.ip)).strip("['").strip("']")
        net.close()
        local_name = socket.gethostname()
        if not local_name:
            local_name = "DESKTOP"
        conn = SMBConnection(self.user, self.pwd, local_name, net_name, domain=self.domain, use_ntlm_v2=True)
        try:
            successful_connection = conn.connect(self.ip, port=139, timeout=10)
        except:
            print("Exception while connecting to: %s" % (self.ip))
            return 1
        if successful_connection:
            print(("Successfully connected to %s! Spidering %s%s!" % (self.ip, self.share, self.subfolder)))
        else:
            print("Failed to connect to: %s" % (self.ip))
            return 1
        if int(self.recursive) > 0:
            recurse(conn, self.ip, self.share, self.subfolder, self.pattern, int(self.recursive), self.chance,
                    int(self.delay))
        else:
            request_delay(int(self.delay))
            file_list = conn.listPath(self.share, self.subfolder)
            dir_list(conn, self.ip, self.share, self.subfolder, self.pattern, self.chance, file_list, int(self.delay))
        conn.close()
        print("Exiting thread for " + self.ip)


def request_delay(sleep_val):
    """
    Cause the thread to sleep for n seconds.
    Function should be used before requests to the SMB connection to mimic pauses between user actions.
    :param sleep_val: The number of seconds to delay.
    :return:
    """
    time.sleep(sleep_val)
    return 0


def get_ips(ip_arg):
    ips = []
    try:
        if os.path.isfile(ip_arg):
            f = open(ip_arg, 'r')
            for line in f:
                line = line.rstrip()
                if '/' in line:
                    for ip in IPNetwork(line).iter_hosts():
                        ips.append(str(ip))
                else:
                    ips.append(line)
            f.close()
            return ips
        if '/' in ip_arg:
            for ip in IPNetwork(ip_arg).iter_hosts():
                ips.append(str(ip))
        else:
            ips.append(str(IPAddress(ip_arg)))
    except:
        print(("Error reading file or IP Address notation: %s" % ip_arg))
        exit()
    return ips


def recurse(smb_conn, ip, share, subfolder, pattern, depth, chance, delay):
    try:
        request_delay(delay)
        filelist = smb_conn.listPath(share, subfolder.replace("//", ""))
        dir_list(smb_conn, ip, share, subfolder, pattern, chance, filelist, delay)
        if depth == 0:
            return 0
    except:
        print(("//%s/%s [Unable to read]" % (ip, subfolder.replace("//", ""))))
        err = sys.exc_info()[0]
        print(err.msg)
        return 1

    for result in filelist:
        if result.isDirectory and result.filename != '.' and result.filename != '..':
            recurse(smb_conn, ip, share, subfolder + '/' + result.filename, pattern, depth - 1, chance, delay)
    return 0


def dir_list(smb_conn, ip, share, path, pattern, chance, files, delay):
    for file in files:
        chance_download(smb_conn, share, path, chance, file, delay)
        for instance in pattern:
            if instance in file.filename:
                if file.isDirectory:
                    print(("//%s/%s/%s [dir]" % (ip, path.replace("//", ""), file.filename)))
                else:
                    print(("//%s/%s/%s" % (ip, path.replace("//", ""), file.filename)))
    return 0


def chance_download(smb_conn, share, path, chance, file, delay):
    """
    Probabilistically download the specified file.
    :param smb_conn:
    :param share:
    :param path:
    :param chance: Chance that the file will be downloaded.
    :param file: File object.
    :param delay:
    :return:
    """
    if file.filename.startswith('.') or file.isDirectory:
        return 0
    path = path.replace('/', '')
    if random.random() < float(chance):
        file_obj = tempfile.NamedTemporaryFile()
        try:
            print("Collecting {}/{}".format(path, file.filename))
            request_delay(delay)
            file_attributes, filesize = smb_conn.retrieveFile(share, path + '/' + file.filename, file_obj)
        except:
            print("Unable to retrieve file {}/{} from {}".format(path, file.filename, share))

        file_obj.close()
    return 0

start_time = time.time()

banner = " ____________________________________________"
banner += "\n |\'-._(   /                                 |"
banner += "\n | \  .'-._\                           ,   ,|"
banner += "\n |-.\'    .-;    SMB Spider           .'\`-' |"
banner += "\n |   \  .' (    v1.0 beta         _.'   \   |"
banner += "\n |.--.\'   _)                   ;-;       \._|"
banner += "\n |    ` _\(_)/_                 \ `'-,_,-'\ |"
banner += "\n |______ /(O)\  ________________/____)_`-._\|"
banner += "\n"
print(banner)

# parse the arguments
parser = argparse.ArgumentParser(
    description='SMB Spider will search shares. It is best used to search SMB shares for sensitive files, i.e., passwords.xls')
parser.add_argument('-ip', '--ipaddress', help='IP Address, IP/CIDR, IP Address File', required=True)
parser.add_argument('-s', '--share', help='SMB share to spider', required=True)
parser.add_argument('-f', '--subfolder', help='SMB subfolder to spider', default='/', required=False)
parser.add_argument('-pa', '--pattern', help='Keyword to search for, i.e., password', default='', required=False)
parser.add_argument('-pf', '--patternfile', help='File of keywords to search for, i.e., password', default='',
                    required=False)
parser.add_argument('-u', '--user', help='SMB user to connect with', default='', required=False)
parser.add_argument('-p', '--pwd', help='SMB password to connect with', default='', required=False)
parser.add_argument('-d', '--domain', help='SMB domain to connect with', default='', required=False)
parser.add_argument('-r', '--recursive', help='Spider subfolders. Set value for depth.', default=0, required=False)
parser.add_argument('-t', '--threads', help='Number of threads', default=1, required=False)
parser.add_argument('-c', '--chance', help='Percentage chance of downloading any one file that we come across.', default=0.0, required=False)
parser.add_argument('-de', '--delay', help='Seconds to wait between requests, per thread.', default=0, required=False)
args = parser.parse_args()

# get the list of ips
ips = get_ips(args.ipaddress)

# create pattern list from supplied args
pattern = []
if args.patternfile != '':
    try:
        f = open(args.patternfile, 'r')
        for line in f:
            line = line.rstrip()
            pattern.append(line)
        f.close()
        if args.pattern != '':
            pattern.append(args.pattern)
    except:
        print(("Error reading pattern file: %s" % args.patternfile))
else:
    pattern.append(args.pattern)

for ip in ips:
    # create a thread
    thread = ScanThread(ip, args.share, args.subfolder, args.user, args.pwd, args.domain, args.recursive, pattern,
                        args.chance, args.delay)
    thread.start()

    # make sure threads do not exceed the threshold set by the -t arg
    while threading.activeCount() > int(args.threads):
        time.sleep(0.01)

# make sure all spidering threads are dead before closing primary thread
while threading.activeCount() > 1:
    time.sleep(0.01)

print(("Done spidering...\nCompleted in: %s" % (time.time() - start_time)))
