#!WORKDIR/.venv/bin/python -u

# TODO
# manage ca certificate
# eliminate subprocess call to `wg set`
# eliminate default region - pick one??
# generate PUBLIC_IPS by inverting rfc1918?
# ipv6 support
# remove netns name
# check dns when checking connectivity
# proper logging

import json
import requests
import random
import urllib
import subprocess
from requests.adapters import DEFAULT_POOLSIZE, DEFAULT_RETRIES, DEFAULT_POOLBLOCK
from tempfile import NamedTemporaryFile
from uuid import uuid4
from datetime import datetime, timedelta
from os import environ

import docker as dockerlib
import python_wireguard
import netns as larsks_netns
from pyroute2 import netns, NetNS, NDB, IPRoute, WireGuard
from icmplib import ping

PIA_DEFAULT_REGION = 'ca_vancouver'
PIA_CA_CERT = 'WORKDIR/ca.crt'
INTERFACE_PREFIX = 'wg-'
LABEL_FILTER = {'label': 'wg-docker.enable=true'}

PUBLIC_IPS = [
    # 0.0.0.0-9.255.255.255
    '0.0.0.0/5', '8.0.0.0/7',
    # 11.0.0.0-172.15.255.255
    '11.0.0.0/8', '12.0.0.0/6', '16.0.0.0/4', '32.0.0.0/3', '64.0.0.0/2',
    '128.0.0.0/3', '160.0.0.0/5', '168.0.0.0/6', '172.0.0.0/12',
    # 172.32.0.0-192.167.255.255
    '172.32.0.0/11', '172.64.0.0/10', '172.128.0.0/9', '173.0.0.0/8',
    '174.0.0.0/7', '176.0.0.0/4', '192.0.0.0/9', '192.128.0.0/11',
    '192.160.0.0/13',
    # 192.169.0.0-223.255.255.255
    '192.169.0.0/16', '192.170.0.0/15', '192.172.0.0/14', '192.176.0.0/12',
    '192.192.0.0/10', '193.0.0.0/8', '194.0.0.0/7', '196.0.0.0/6',
    '200.0.0.0/5', '208.0.0.0/4',
]

class NamespaceClosedError(Exception):
    pass

class PiaVpn:
    '''
    This class handles connecting to Private Internet Access APIs and
    retrieving the necessary data from them. It also implements a cache of the
    serverlist data and token.
    '''

    serverlist_url = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
    token_url = 'https://www.privateinternetaccess.com/gtoken/generateToken'
    # only wireguard supported
    conn_types = ('wg')

    serverlist = None
    serverlist_expire = None
    cachetime = timedelta(days=1)

    def __init__(self, user, password, conn_type='wg'):
        self.auth = (user, password)
        self.token = None
        self.token_expire = None
        if conn_type in self.conn_types:
            self.conn_type = conn_type
        else:
            raise ValueError('Invalid connection type: {}'.format(conn_type))

    @classmethod
    def _update_serverlist(cls):
        rsp = requests.get(cls.serverlist_url)
        rsp.raise_for_status()
        cls.serverlist = json.loads(rsp.text.split('\n')[0])
        cls.serverlist_expire = datetime.now() + cls.cachetime

    @classmethod
    def get_serverlist(cls, cached=True):
        if not cached:
            print('updating serverlist: forced')
            cls._update_serverlist()
        elif not cls.serverlist:
            print('updating serverlist: first time')
            cls._update_serverlist()
        elif cls.serverlist_expire and datetime.now() > cls.serverlist_expire:
            print('updating serverlist: cached data expired')
            cls._update_serverlist()
        else:
            print('skipping serverlist update: cache valid')
        return cls.serverlist

    def get_ports(self, cached=True):
        self.get_serverlist(cached)
        return self.serverlist['groups'][self.conn_type][0]['ports']

    def get_region_servers(self, region, cached=True):
        self.get_serverlist(cached)
        region_data = next(filter(lambda x: x['id'] == region, self.serverlist['regions']))
        return region_data['servers'][self.conn_type]

    def get_random_server(self, region, cached=True):
        return random.choice(self.get_region_servers(region, cached))

    def _update_token(self):
        rsp = requests.post(self.token_url, auth=self.auth)
        rsp.raise_for_status()
        data = rsp.json()
        if data['status'] != 'OK':
            raise RuntimeError('Could not get token: {}'.format(data))
        self.token = data['token']
        self.token_expire = datetime.now() + self.cachetime

    def get_token(self, cached=True):
        if not cached:
            print('updating token: forced')
            self._update_token()
        elif not self.token:
            print('updating token: first time')
            self._update_token()
        elif self.token_expire and datetime.now() > self.token_expire:
            print('updating token: cached data expired')
            self._update_token()
        else:
            print('skipping token update: cache valid')
        return self.token

    def get_config(self, region, public_key):
        server = self.get_random_server(region)
        port = self.get_ports()[0]

        config_url = 'https://{host}:{port}/addKey'.format(
            host = server['cn'],
            port = port,
        )
        config_query = 'pt={token}&pubkey={public}'.format(
            token = urllib.parse.quote(self.get_token(), safe=''),
            public = urllib.parse.quote(str(public_key), safe=''),
        )

        config_sess = requests.Session()
        config_sess.mount(config_url, DNSOverrideAdapter(server['cn'], server['ip']))
        rsp = config_sess.get('{}?{}'.format(config_url, config_query), verify=PIA_CA_CERT)
        return rsp.json()

# use in-region api to get wireguard config
class DNSOverrideAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, common_name, host, pool_connections=DEFAULT_POOLSIZE, pool_maxsize=DEFAULT_POOLSIZE,
        max_retries=DEFAULT_RETRIES, pool_block=DEFAULT_POOLBLOCK):
        self.__common_name = common_name
        self.__host = host
        super(DNSOverrideAdapter, self).__init__(pool_connections=pool_connections, pool_maxsize=pool_maxsize,
            max_retries=max_retries, pool_block=pool_block)

    def get_connection(self, url, proxies=None):
        redirected_url = url.replace(self.__common_name, self.__host)
        return super(DNSOverrideAdapter, self).get_connection(redirected_url, proxies=proxies)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        pool_kwargs['assert_hostname'] = self.__common_name
        super(DNSOverrideAdapter, self).init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

def get_index(context, name):
    idx = context.link_lookup(ifname=name)
    if len(idx) == 1:
        return idx[0]
    return -1

def wg_up(pid, iface, config, private_key):

    nsname = str(uuid4())
    netns.attach(nsname, pid)

    with IPRoute() as ip, NetNS(nsname) as ns:

        # create interface and move to netns, if necessary
        wg_idx = get_index(ns, iface)
        if wg_idx < 0:
            print('"{}" does not exist in netns'.format(iface))
            wg_idx_ip = get_index(ip, iface)
            if wg_idx_ip < 0:
                print('"{}" does not exist in localhost'.format(iface))
                ip.link('add', ifname=iface, kind='wireguard')
                wg_idx_ip = get_index(ip, iface)
                print('added "{}" to localhost with index {}'.format(iface, wg_idx_ip))
            ip.link('set', index=wg_idx_ip, net_ns_fd=nsname)
            wg_idx = get_index(ns, iface)
            print('moved "{}" to netns with index {}'.format(iface, wg_idx))
        else:
            print('"{}" exists in netns with index {}'.format(iface, wg_idx))

        # flush and set address on interface
        ns.flush_addr(index=wg_idx)
        ns.addr('add', index=wg_idx, address=config['peer_ip'], mask=32)

    # set wireguard configuration on interface
    with larsks_netns.NetNS(nsname=nsname) as ns, NamedTemporaryFile() as keyfile:
        keyfile.write(str(private_key).encode())
        keyfile.flush()
        allowed_ips = ','.join(PUBLIC_IPS + config['dns_servers'])
        command = [
            'wg', 'set', iface,
            'private-key', keyfile.name,
            'peer', config['server_key'],
            'endpoint', '{ip}:{port}'.format(ip=config['server_ip'],
                                             port=config['server_port']),
            'allowed-ips', allowed_ips,
        ]
        wg = subprocess.run(command, capture_output=True)
        print(wg.stdout)

    # bring interface up and set default route
    with NetNS(nsname) as ns:
        wg_idx = get_index(ns, iface)
        ns.link('set', index=wg_idx, state='up')
        ns.route('replace', dst='0.0.0.0/0', oif=wg_idx)

    # show wireguard connection
    with larsks_netns.NetNS(nsname=nsname) as ns:
        print(subprocess.run(['wg','show'], capture_output=True).stdout)

    # discard netns name; container processes will hold it open unnamed
    ns = NetNS(nsname)
    ns.close()
    ns.remove()

def check_netns_connectivity(nspid, iface):
    print('checking connectivity pid={} iface={}'.format(nspid, iface))
    try:
        with larsks_netns.NetNS(nspid=nspid) as ns:
            with IPRoute() as ip:
                if get_index(ip, iface) < 0:
                    print('  iface={} does not exist, no connectivity')
                    return False
            ip_ping = ping('1.1.1.1')
            if ip_ping.packets_received > 0:
                print('  ip connectivity confirmed, but not checking dns')
                return True
            else:
                print('  no ip connectivity')
    except ValueError:
        raise NamespaceClosedError()
    ('  connectivity not confirmed, returning False')
    return False

def set_resolvconf(container, nameservers):
    resolvconf = container.attrs['ResolvConfPath']
    print('setting nameservers for {} at {}'.format(container.name, resolvconf))
    with open(resolvconf, 'w') as f:
        for ns in nameservers:
            f.write('nameserver {}\n'.format(ns))
    with open(resolvconf, 'r') as f:
        print(f.read())

def configure_container(container, pia):
    print('configuring container {}'.format(container.name))
    pid = container.attrs['State']['Pid']
    iface = '{}{}'.format(INTERFACE_PREFIX, container.name)[0:15]
    try:
        if not check_netns_connectivity(pid, iface):
            private, public = python_wireguard.Key.key_pair()
            region = container.labels.get('wg-docker.region', PIA_DEFAULT_REGION)
            config = pia.get_config(region, public)
            wg_up(pid, iface, config, private)
            set_resolvconf(container, config['dns_servers'])
    except NamespaceClosedError:
        print('container namespace was closed before setup complete')

def main():
    # setup pia object and connect to docker
    pia = PiaVpn(environ['PIA_USERNAME'], environ['PIA_PASSWORD'])
    docker = dockerlib.from_env()

    # check all containers for label on startup
    events_start = datetime.now()
    print('looking for existing containers')
    for container in docker.containers.list(filters=LABEL_FILTER):
        print('container {} running on startup...'.format(container.name))
        configure_container(container, pia)

    # after startup, watch docker events
    event_filter = {
        'type': 'container',
        'event': 'start',
    }
    event_filter.update(LABEL_FILTER)

    print('startup complete, watching events')
    for event in docker.events(filters=event_filter, decode=True, since=events_start):
        container = docker.containers.get(event['id'])
        print('container {} started...'.format(container.name))
        configure_container(docker.containers.get(event['id']), pia)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
