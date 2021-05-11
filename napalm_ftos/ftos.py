# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
# Copyright 2021 Berlin Institute of Health. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""Napalm driver for Dell/Force10 FTOS."""

import re
import socket

from napalm.base.helpers import textfsm_extractor
from napalm.base.helpers import mac, ip
from napalm.base.netmiko_helpers import netmiko_args

from napalm.base import NetworkDriver
from napalm.base.exceptions import ConnectionException

from netaddr.core import AddrFormatError

import paramiko

from napalm_ftos.utils import (
    canonical_interface_name,
    parse_uptime,
    transform_lldp_capab,
    prep_addr
)


class FTOSDriver(NetworkDriver):
    """NAPALM Dell Force10 FTOS Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Dell Force10 FTOS Handler."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Allow old key exchange algorithms in paramiko.  Old FTOS devices don't get
        # patches any more.
        lst = list(paramiko.Transport._preferred_kex)
        more = (
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1",
        )
        for x in more:
            if x not in lst:
                lst.insert(0, x)
        paramiko.Transport._preferred_kex = tuple(lst)

    def _send_command(self, command):
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionException(str(e))

    def open(self):
        """Open a connection to the device."""
        self.device = self._netmiko_open(
            'dell_force10',
            netmiko_optional_args=self.netmiko_optional_args,
        )

    def close(self):
        """Close the connection to the device."""
        self._netmiko_close()

    def get_arp_table(self, vrf=u''):
        """FTOS implementation of get_arp_table."""
        if vrf:
            msg = "VRF support has not been added for this getter on this platform."
            raise NotImplementedError(msg)

        command = "show arp"
        arp_entries = self._send_command(command)
        arp_entries = textfsm_extractor(self, 'show_arp', arp_entries)

        table = []
        for idx, arp in enumerate(arp_entries):
            entry = {
                'interface': arp['interface'],
                'ip': ip(arp['ip']),
                'mac': mac(arp['mac']),
            }

            try:
                # age is given in minutes
                entry['age'] = float(arp['age']) * 60
            except ValueError:
                entry['age'] = -1.0

            table.append(entry)

        return table

    def get_bgp_neighbors_detail(self, neighbor_address=u''):
        """FTOS implementation of get_bgp_neighbors_detail."""
        cmd = ["show ip bgp neighbors"]
        if len(neighbor_address.strip()) > 0:
            cmd.append(neighbor_address)

        command = ' '.join(cmd)
        neighbors = self._send_command(command)
        neighbors = textfsm_extractor(self, 'show_ip_bgp_neighbors', neighbors)

        table = {u'global': {}}
        for idx, entry in enumerate(neighbors):
            # TODO: couldn't detect VRF from output
            vrf = u'global'

            neighbor = {
                "up": (entry['connection_state'] == 'ESTABLISHED'),
                "local_as": -1,  # unimplemented
                "router_id": ip(entry['router_id']),
                "local_address": str(entry['local_address']),
                "routing_table": u'',  # unimplemented
                "local_address_configured": False,  # unimplemented
                "local_port": entry['local_port'],
                "remote_address": ip(entry['remote_address']),
                "multihop": False,  # unimplemented
                "multipath": False,  # unimplemented
                "remove_private_as": False,  # unimplemented
                "import_policy": u'',  # unimplemented
                "export_policy": u'',  # unimplemented
                "connection_state": entry['connection_state'],
                "previous_connection_state": u'',  # unimplemented
                "last_event": u'',  # unimplemented
                "suppress_4byte_as": False,  # unimplemented
                "local_as_prepend": False,  # unimplemented
                "configured_holdtime": -1,  # unimplemented
                "configured_keepalive": -1,  # unimplemented
                "active_prefix_count": -1,  # unimplemented
                "received_prefix_count": -1,  # unimplemented
                "suppressed_prefix_count": -1,  # unimplemented
            }

            # cast some integers
            for k in ['remote_as', 'local_port', 'remote_port', 'input_messages',
                      'output_messages', 'input_updates', 'output_updates',
                      'messages_queued_out', 'holdtime', 'keepalive',
                      'accepted_prefix_count', 'advertised_prefix_count',
                      'flap_count']:
                try:
                    neighbor[k] = int(entry[k])
                except ValueError:
                    neighbor[k] = -1

            if entry['remote_as'] not in table[vrf]:
                table[vrf][int(entry['remote_as'])] = []
            table[vrf][int(entry['remote_as'])].append(neighbor)

        return table

    def get_config(self, retrieve='all', full=False, sanitized=False):
        """FTOS implementation of get_config."""
        config = {
            'startup':   u'',
            'running':   u'',
            'candidate': u'Not implemented for FTOS',  # not implemented
        }

        if retrieve in ['all', 'running']:
            config['running'] = self._send_command("show running-config")

        if retrieve in ['all', 'startup']:
            config['startup'] = self._send_command("show startup-config")

        return config

    def get_environment(self):
        """FTOS implementation of get_environment."""
        env = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {
                'available_ram': 0,
                'used_ram': 0,
            },
        }

        # get fan data
        #

        # get sensor data
        environment = self._send_command("show environment stack-unit")
        environment = textfsm_extractor(self, 'show_environment_stack-unit', environment)
        for idx, entry in enumerate(environment):
            name = "Unit %d" % int(entry['unit'])
            # temperature
            env['temperature'][name] = {
                'temperature': float(entry['temperature']),
                'is_alert': (entry['temp_status'] != '2'),
                'is_critical': (entry['temp_status'] != '2')
            }
            # power
            env['power'][name] = {
                'status': (entry['volt_status'] == 'ok'),
                'capacity': -1.0,  # not implemented
                'output': -1.0,    # not implemented
            }

        # get CPU data
        processes = self._send_command("show processes cpu summary")
        processes = textfsm_extractor(self, 'show_processes_cpu_summary', processes)
        for idx, entry in enumerate(processes):
            env['cpu']["Unit %d" % int(entry['unit'])] = {
                '%usage': float(entry['omin']),
            }

        # get memory data
        memory = self._send_command("show memory")
        memory = textfsm_extractor(self, "show_memory", memory)
        for idx, entry in enumerate(memory):
            env['memory']['available_ram'] += int(entry['total'])
            env['memory']['used_ram'] += int(entry['used'])

        return env

    def get_facts(self):
        """FTOS implementation of get_facts."""
        # default values.
        facts = {
            'uptime': -1,
            'vendor': u'Dell EMC',
            'os_version': 'Unknown',
            'serial_number': 'Unknown',
            'model': 'Unknown',
            'hostname': 'Unknown',
            'fqdn': 'Unknown',
            'interface_list': [],
        }

        show_ver = self._send_command("show system stack-unit 0")

        # parse version output
        for line in show_ver.splitlines():
            if line.startswith('Up Time'):
                uptime_str = line.split(': ')[1]
                facts['uptime'] = parse_uptime(uptime_str)
            elif line.startswith('Mfg By'):
                facts['vendor'] = line.split(': ')[1].strip()
            elif ' OS Version' in line:
                facts['os_version'] = line.split(': ')[1].strip()
            elif line.startswith('Serial Number'):
                facts['serial_number'] = line.split(': ')[1].strip()
            elif line.startswith('Product Name'):
                facts['model'] = line.split(': ')[1].strip()

        # invoke get_interfaces and list interfaces
        facts['interface_list'] = sorted(self.get_interfaces().keys())

        # get hostname from running config
        config = self.get_config('running')['running']
        for line in config.splitlines():
            if line.startswith('hostname '):
                facts['hostname'] = re.sub('^hostname ', '', line)
                facts['fqdn'] = facts['hostname']
                break

        return facts

    def get_lldp_neighbors(self):
        """FTOS implementation of get_lldp_neighbors."""
        lldp = {}
        neighbors_detail = self.get_lldp_neighbors_detail()
        for intf_name, entries in neighbors_detail.items():
            lldp[intf_name] = []
            for lldp_entry in entries:
                hostname = lldp_entry['remote_system_name']
                lldp_dict = {
                    'port': lldp_entry['remote_port_description'],
                    'hostname': hostname,
                }
                lldp[intf_name].append(lldp_dict)

        return lldp

    def get_lldp_neighbors_detail(self, interface=''):
        """FTOS implementation of get_lldp_neighbors_detail."""
        if interface:
            command = "show lldp neighbors interface {} detail".format(interface)
        else:
            command = "show lldp neighbors detail"

        lldp_entries = self._send_command(command)
        lldp_entries = textfsm_extractor(self, 'show_lldp_neighbors_detail', lldp_entries)

        lldp = {}
        for idx, lldp_entry in enumerate(lldp_entries):
            # TODO: the current textfsm template keeps adding an empty entry at
            # the end of each interface and I couldn't fix it so at some point
            # it was just easier to get rid of these empty entries in code
            nonZero = False
            for key in lldp_entry.keys():
                # local_interface is set to Filldown so that is always filled
                if key == 'local_interface':
                    continue
                if len(lldp_entry[key].strip()) > 0:
                    nonZero = True
                    break
            if not nonZero:
                continue

            # get pretty interface name
            local_intf = canonical_interface_name(lldp_entry.pop('local_interface'))

            # cast some mac addresses
            for k in ['remote_port', 'remote_chassis_id']:
                if len(lldp_entry[k].strip()) > 0:
                    try:
                        lldp_entry[k] = mac(lldp_entry[k])
                    except AddrFormatError:
                        pass

            # transform capabilities
            for k in ['remote_system_capab', 'remote_system_enable_capab']:
                lldp_entry[k] = transform_lldp_capab(lldp_entry[k])

            # not implemented
            lldp_entry['parent_interface'] = u''

            lldp.setdefault(local_intf, [])
            lldp[local_intf].append(lldp_entry)

        return lldp

    def get_mac_address_table(self):
        """FTOS implementation of get_mac_address_table."""
        mac_entries = self._send_command("show mac-address-table")
        mac_entries = textfsm_extractor(self, 'show_mac-address-table', mac_entries)

        mac_table = []
        for idx, entry in enumerate(mac_entries):
            entry['mac'] = mac(entry['mac'])
            entry['interface'] = canonical_interface_name(entry['interface'])
            entry['vlan'] = int(entry['vlan'])
            entry['static'] = (entry['static'] == 'Static')
            entry['active'] = (entry['active'] == 'Active')
            entry['moves'] = -1        # not implemented
            entry['last_move'] = -1.0  # not implemented

            mac_table.append(entry)

        return mac_table

    def _get_interfaces_detail(self):
        iface_entries = self._send_command("show interfaces")
        return textfsm_extractor(self, 'show_interfaces', iface_entries)

    def get_interfaces(self):
        """FTOS implementation of get_interfaces."""
        iface_entries = self._get_interfaces_detail()

        interfaces = {}
        for i, entry in enumerate(iface_entries):
            if len(entry['iface_name']) == 0:
                continue

            # init interface entry with default values
            iface = {
                'is_enabled':   False,
                'is_up':        False,
                'description':  str(entry['description']),
                'mac_address':  u'',
                'last_flapped': 0.0,  # in seconds
                'speed':        0,    # in megabits
                'mtu':          0,
            }

            # not all interface have MAC addresses specified in `show interfaces'
            # so if converting it to a MAC address won't work, leave it like that
            try:
                iface['mac_address'] = mac(entry['mac_address'])
            except AddrFormatError:
                pass

            # set statuses
            if entry['admin_status'] == 'up':
                iface['is_enabled'] = True
            if entry['oper_status'] == 'up':
                iface['is_up'] = True

            # parse line_speed
            if re.search(r'bit$', entry['line_speed']):
                speed = entry['line_speed'].split(' ')
                if speed[1] == 'Mbit':
                    iface['speed'] = int(speed[0])
                # not sure if this ever occurs
                elif speed[1] == 'Gbit':
                    iface['speed'] = int(speed[0]*1000)

            # parse mtu
            iface['mtu'] = int(entry['mtu'])

            # parse last_flapped
            iface['last_flapped'] = float(parse_uptime(entry['last_flapped'], True))

            # add interface data to dict
            local_intf = canonical_interface_name(entry['iface_name'])
            interfaces[local_intf] = iface

        return interfaces

    def get_interfaces_counters(self):
        """FTOS implementation of get_interfaces_counters."""
        iface_entries = self._get_interfaces_detail()
        interfaces = {}
        key_map = [
            ['rx_octets',  'rx_octets'],
            ['rx_unicast', 'rx_unicast_packets'],
            ['rx_mcast',   'rx_multicast_packets'],
            ['rx_bcast',   'rx_broadcast_packets'],
            ['rx_dcard',   'rx_discards'],
            ['tx_octets',  'tx_octets'],
            ['tx_unicast', 'tx_unicast_packets'],
            ['tx_mcast',   'tx_multicast_packets'],
            ['tx_bcast',   'tx_broadcast_packets'],
            ['tx_dcard',   'tx_discards'],
        ]
        for idx, entry in enumerate(iface_entries):
            iface = {
                'rx_errors': 0,  # unimplemented
                'tx_errors': 0,  # unimplemented
            }
            for key in key_map:
                try:
                    iface[key[1]] = int(entry[key[0]])
                except ValueError:
                    iface[key[1]] = 0

            # add interface data to dict
            local_intf = canonical_interface_name(entry['iface_name'])
            interfaces[local_intf] = iface

        return interfaces

    def get_interfaces_ip(self):
        """FTOS implementation of get_interfaces_ip."""
        addr = {}

        # get IPv4 info
        ip_cmd = "show ip interface"
        ip_res = self._send_command(ip_cmd)

        # parse IP addresses
        iface = None
        for line in ip_res.splitlines():
            # interface line
            m = re.search(r'^(\w+( \d+(\/\d+)?)?) is \w+', line)
            if m:
                # capture interface name and move on to next line
                iface = m.group(1)
                continue

            # look for IPv4 address line
            m = re.search(r'^Internet address is ([0-9\.]+)(?:\/(\d+))?', line)
            if not m:
                continue

            # prepare address dict for this interface
            addr = prep_addr(addr, iface)

            address = ip(m.group(1))

            # try to get subnet mask from output as well
            # otherwise assume /32
            mask = 32
            if m.group(2):
                mask = int(m.group(2))
                # remove subnet mask from address
                address = address.replace('/%d' % mask, '')

            addr[iface][u'ipv4'][address] = {
                'prefix_length': mask
            }

        ip6_cmd = "show ipv6 interface brief"
        ip6_res = self._send_command(ip6_cmd)

        # parse IPv6 addresses
        iface = None
        for line in ip6_res.splitlines():
            # interface line
            m = re.search(r'^(\w+( \d+(\/\d+)?)?)\s+', line)
            if m:
                # capture interface name and move on to next line
                iface = m.group(1)
                continue

            # look for IPv6 address line
            m = re.search(r'^\s*([a-f0-9:]+)(?:\/(\d+))?', line)
            if not m:
                continue

            # prepare address dict for this interface
            addr = prep_addr(addr, iface, u'ipv6')

            address = ip(m.group(1))

            # try to get prefix length from output as well
            # otherwise assume /128
            preflen = 128
            if m.group(2):
                preflen = int(m.group(2))
                # remove prefix length from address
                address = address.replace('/%d' % preflen, '')
            # for link-local addresses assume prefix length /64
            elif re.search(r'^fe80', address):
                preflen = 64

            addr[iface][u'ipv6'][address] = {
                'prefix_length': preflen
            }

        return addr

    def _get_ntp_assoc(self):
        ntp_entries = self._send_command("show ntp associations")
        return textfsm_extractor(self, 'show_ntp_associations', ntp_entries)

    def get_ntp_peers(self):
        """FTOS implementation of get_ntp_peers."""
        entries = self._get_ntp_assoc()

        peers = {}
        for idx, entry in enumerate(entries):
            peers[ip(entry['remote'])] = {}

        return peers

    def get_ntp_servers(self):
        """FTOS implementation of get_ntp_servers."""
        return self.get_ntp_peers()

    def get_ntp_stats(self):
        """FTOS implementation of get_ntp_stats."""
        entries = self._get_ntp_assoc()
        stats = []
        for idx, entry in enumerate(entries):
            # cast ints
            for key in ['stratum', 'hostpoll', 'reachability']:
                try:
                    entry[key] = int(entry[key])
                except ValueError:
                    entry[key] = 0
            # cast floats
            for key in ['delay', 'offset', 'jitter']:
                try:
                    entry[key] = float(entry[key])
                except ValueError:
                    entry[key] = 0.0
            # cast ips
            for k in ['referenceid', 'remote']:
                if len(entry[k].strip()) > 0:
                    entry[k] = ip(entry[k])

            entry['synchronized'] = (entry['type'] == '*')
            stats.append(entry)

        return stats

    def get_snmp_information(self):
        """FTOS implementation of get_snmp_information."""
        command = "show running-config snmp"
        snmp = self._send_command(command)

        info = {
            'chassis_id': u'',  # not implemented
            'community':  {},
            'contact':    u'',
            'location':   u'',
        }

        for line in snmp.splitlines():
            if 'community' in line:
                m = re.search(r'^snmp-server community ([^\s]+) ([^\s]+)(?: ([^\s]+))?', line.strip())
                if not m:
                    continue
                com = {
                    'mode': m.group(2),
                    'acl':  u'N/A',
                }
                if m.group(3):
                    com['acl'] = m.group(3)

                info['community'][m.group(1)] = com

            elif 'location' in line:
                info['location'] = line.strip().replace('snmp-server location ', '').strip('"')
            elif 'contact' in line:
                info['contact'] = line.strip().replace('snmp-server contact ', '').strip('"')

        return info

    def get_users(self):
        """FTOS implementation of get_users."""
        command = "show running-config users"
        output = self._send_command(command)

        ptr = re.compile(r'^username ([^\s]+).+(?:sha256-)?password \d+ ([^\s]+) (?:privilege (\d+))?')
        users = {}
        for line in output.splitlines():
            m = ptr.search(line.strip())
            if not m:
                continue

            g = m.groups()
            user = {
                'password': g[1],
                'sshkeys':  [],
                'level':    0,
            }
            if g[2]:
                user['level'] = int(g[2])

            users[g[0]] = user

        return users

    def is_alive(self):
        """FTOS implementation of is_alive."""
        null = chr(0)
        if self.device is None:
            return {'is_alive': False}

        try:
            # Try sending ASCII null byte to maintain the connection alive
            self.device.write_channel(null)
            return {'is_alive': self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {'is_alive': False}

        return {'is_alive': False}

    def ping(self, destination, source=u'', ttl=255, timeout=2, size=100, count=5, vrf=u''):
        """FTOS implementation of ping."""
        # build command string based on input
        cmd = ["ping"]
        if len(vrf.strip()) > 0:
            cmd.append("vrf %s" % vrf)
        cmd.append(destination)
        cmd.append("timeout %d" % timeout)
        cmd.append("datagram-size %d" % size)
        if len(source.strip()) > 0:
            cmd.append("source ip %s" % source)
        cmd.append("count %d" % count)

        command = ' '.join(cmd)
        result = self._send_command(command)

        # check if output holds an error
        m = re.search(r'% Error: (.+)', result)
        if m:
            return {
                'error': m.group(1)
            }

        # try to parse the output
        m = re.search(r'Success rate is [\d\.]+ percent \((\d+)\/(\d+)\).+ = (\d+)\/(\d+)\/(\d+)', result)
        if not m:
            return {
                'error': 'could not parse output',
            }

        g = m.groups()
        return {
            'success': {
                'probes_sent': int(g[1]),
                'packet_loss': int(g[1]) - int(g[0]),
                'rtt_min':     float(g[2]),
                'rtt_avg':     float(g[3]),
                'rtt_max':     float(g[4]),
                'rtt_stddev':  0.0,  # not implemented
                'results': [
                    {
                        'ip_address': ip(destination),
                        'rtt':        float(g[3]),
                    }
                ],
            }
        }

    def traceroute(self, destination, source=u'', ttl=255, timeout=2, vrf=u''):
        """FTOS implementation of traceroute."""
        # source, ttl and timeout are not implemented and therefore ignored
        cmd = ["traceroute"]
        if len(vrf.strip()) > 0:
            cmd.append("vrf %s" % vrf)
        cmd.append(destination)

        command = ' '.join(cmd)
        result = self._send_command(command)

        # check if output holds an error
        m = re.search(r'% Error: (.+)', result)
        if m:
            return {
                'error': m.group(1)
            }

        # process results of succesful traceroute
        result = textfsm_extractor(self, 'traceroute', result)
        trace = {}
        ttl = None
        for idx, entry in enumerate(result):
            if len(entry['ttl'].strip()) > 0 and ttl != int(entry['ttl']):
                ttl = int(entry['ttl'])
                trace[ttl] = {'probes': {}}
                ctr = 1

            # rewrite probes for easier splitting
            probes = re.sub(r'\s+', ' ', entry['probes'].replace('ms', '').strip())
            if len(probes) == 0:
                probes = []
            else:
                probes = probes.split(' ')

            for probe in probes:
                trace[ttl]['probes'][ctr] = {
                    'rtt': float(probe),
                    'ip_address': ip(str(entry['hop'])),
                    'host_name': str(entry['hop']),
                }
                ctr += 1

        return {
            'success': trace,
        }
