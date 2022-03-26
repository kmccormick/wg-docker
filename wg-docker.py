#!WORKDIR/.venv/bin/python -u

# TODO
# manage ca certificate
# generate PUBLIC_IPS by inverting rfc1918?
# ipv6 support
# check dns when checking connectivity
# proper logging

import os
import json
import requests
import random
import urllib.parse
from datetime import datetime, timedelta

import docker as dockerlib
import python_wireguard
import icmplib
from netns import NetNS as SimpleNetNS
from pyroute2 import NetNS, IPRoute, WireGuard

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

class CacheExpiredError(Exception):
    pass

class CachedValue:
    def __init__(self, value, expire_in):
        self.update(value, expire_in)

    def is_valid(self):
        return datetime.now() < self.expire

    def value(self):
        if not self.is_valid():
            raise CacheExpiredError()
        return self._value

    def update(self, value, expire_in):
        self.expire = datetime.now() + expire_in
        self._value = value

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
    cachetime = timedelta(days=1)

    def __init__(self, user, password, conn_type='wg'):
        self.auth = (user, password)
        self.token = None
        if conn_type in self.conn_types:
            self.conn_type = conn_type
        else:
            raise ValueError('Invalid connection type: {}'.format(conn_type))

    @classmethod
    def _update_serverlist(cls):
        rsp = requests.get(cls.serverlist_url)
        rsp.raise_for_status()
        ret = json.loads(rsp.text.split('\n')[0])
        cls.serverlist = CachedValue(ret, cls.cachetime)
        return ret

    @classmethod
    def get_serverlist(cls, cached=True):
        if not cached:
            print('updating serverlist: forced')
            return cls._update_serverlist()

        try:
            return cls.serverlist.value()
        except AttributeError:
            print('updating serverlist: first time')
        except CacheExpiredError:
            print('updating serverlist: cached data expired')

        return cls._update_serverlist()

    def get_ports(self, cached=True):
        self.get_serverlist(cached)
        return self.serverlist.value()['groups'][self.conn_type][0]['ports']

    def get_region_servers(self, region, cached=True):
        self.get_serverlist(cached)
        region_data = next(filter(lambda x: x['id'] == region,
                                  self.serverlist.value()['regions']))
        return region_data['servers'][self.conn_type]

    def get_random_server(self, region, cached=True):
        return random.choice(self.get_region_servers(region, cached))

    def _update_token(self):
        rsp = requests.post(self.token_url, auth=self.auth)
        rsp.raise_for_status()
        data = rsp.json()
        if data['status'] != 'OK':
            raise RuntimeError('Could not get token: {}'.format(data))
        ret = data['token']
        self.token = CachedValue(ret, self.cachetime)
        return ret

    def get_token(self, cached=True):
        if not cached:
            print('updating token: forced')
            return self._update_token()

        try:
            return self.token.value()
        except AttributeError:
            print('updating token: first time')
        except CacheExpiredError:
            print('updating token: cached data expired')

        return self._update_token()

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
    def __init__(self, common_name, host, **kwargs):
        self.__common_name = common_name
        self.__host = host
        super(DNSOverrideAdapter, self).__init__(**kwargs)

    def get_connection(self, url, proxies=None):
        redirected_url = url.replace(self.__common_name, self.__host)
        return super(DNSOverrideAdapter, self).get_connection(redirected_url, proxies=proxies)

    def init_poolmanager(self, connections, maxsize, **pool_kwargs):
        pool_kwargs['assert_hostname'] = self.__common_name
        super(DNSOverrideAdapter, self).init_poolmanager(connections, maxsize, **pool_kwargs)

def get_index(context, name):
    idx = context.link_lookup(ifname=name)
    if len(idx) == 1:
        return idx[0]
    return -1

def wg_up(iface, config, private_key, nspath):

    with IPRoute() as ip, NetNS(nspath) as ns:

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
            ip.link('set', index=wg_idx_ip, net_ns_fd=nspath)
            wg_idx = get_index(ns, iface)
            print('moved "{}" to netns with index {}'.format(iface, wg_idx))
        else:
            print('"{}" exists in netns with index {}'.format(iface, wg_idx))

        # flush and set address on interface
        ns.flush_addr(index=wg_idx)
        ns.addr('add', index=wg_idx, address=config['peer_ip'], mask=32)

    # set wireguard configuration on interface
    with SimpleNetNS(nspath=nspath):
        nameservers = [ '{}/32'.format(ip) for ip in config['dns_servers'] ]
        peer = {
            'public_key': config['server_key'],
            'endpoint_addr': config['server_ip'],
            'endpoint_port': config['server_port'],
            'allowed_ips': PUBLIC_IPS + nameservers,
        }
        wg = WireGuard()
        wg.set(iface, private_key=str(private_key), peer=peer)

    # bring interface up and set default route
    with NetNS(nspath) as ns:
        wg_idx = get_index(ns, iface)
        ns.link('set', index=wg_idx, state='up')
        ns.route('replace', dst='0.0.0.0/0', oif=wg_idx)

def check_netns_connectivity(nspath, iface, host='1.1.1.1'):
    print('checking connectivity nspath={} iface={}'.format(nspath, iface))
    try:
        with SimpleNetNS(nspath=nspath):
            with IPRoute() as ip:
                if get_index(ip, iface) < 0:
                    print('  iface={} does not exist, no connectivity'.format(iface))
                    return False
            ip_ping = icmplib.ping(host)
            if ip_ping.packets_received > 0:
                print('  connectivity to {} confirmed'.format(host))
                return True
            else:
                print('  no ip connectivity to {}'.format(host))
    except ValueError:
        raise NamespaceClosedError()
    ('  connectivity not confirmed, returning False')
    return False

def set_resolvconf(container, nameservers, search=None):
    resolvconf = container.attrs['ResolvConfPath']
    print('setting nameservers for {} at {}'.format(container.name, resolvconf))
    with open(resolvconf, 'w') as f:
        if search:
            f.write('search {}\n'.format(search))
        for ns in nameservers:
            f.write('nameserver {}\n'.format(ns))
    with open(resolvconf, 'r') as f:
        print(f.read())

def configure_container(container, pia):
    print('configuring container {}'.format(container.name))
    nspath = container.attrs['NetworkSettings']['SandboxKey']
    iface = '{}{}'.format(INTERFACE_PREFIX, container.name)[0:15]
    try:
        if not check_netns_connectivity(nspath, iface):
            private, public = python_wireguard.Key.key_pair()
            region = container.labels.get('wg-docker.region', PIA_DEFAULT_REGION)
            config = pia.get_config(region, public)
            wg_up(iface, config, private, nspath)
            set_resolvconf(container, config['dns_servers'])
    except NamespaceClosedError:
        print('container namespace was closed before setup complete')

def main():
    # setup pia object and connect to docker
    pia = PiaVpn(os.environ['PIA_USERNAME'], os.environ['PIA_PASSWORD'])
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
    for event in docker.events(filters=event_filter, decode=True,
                               since=events_start):
        container = docker.containers.get(event['id'])
        print('container {} started...'.format(container.name))
        configure_container(container, pia)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
