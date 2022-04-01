#!WORKDIR/.venv/bin/python -u

import os
import json
import requests
import random
import urllib.parse
from datetime import datetime, timedelta
from tempfile import NamedTemporaryFile

import docker as dockerlib
import python_wireguard
import icmplib
from netns import NetNS as SimpleNetNS
from pyroute2 import NetNS, IPRoute, WireGuard
from netaddr import IPSet

PIA_DEFAULT_REGION = 'ca_vancouver'
INTERFACE_PREFIX = 'wg-'
LABEL_FILTER = {'label': 'wg-docker.enable=true'}

# IPV4 non-routable space from RFC6890 / https://en.wikipedia.org/wiki/Reserved_IP_addresses
IPV4_NON_ROUTABLE = IPSet([
    '0.0.0.0/8',       #Current network
    '10.0.0.0/8',      #Private network
    '100.64.0.0/10',   #Private network (CGNAT)
    '127.0.0.0/8',     #Loopback
    '169.254.0.0/16',  #Link-local
    '172.16.0.0/12',   #Private network
    '192.0.0.0/24',    #Private network (IETF Protocol Assignments)
    '192.0.2.0/24',    #Documentation
    '192.168.0.0/16',  #Private network
    '198.18.0.0/15',   #Benchmark
    '198.51.100.0/24', #Documentation
    '203.0.113.0/24',  #Documentation
    '233.252.0.0/24',  #Documentation
])
IPV4_ROUTABLE = [ str(net) for net in (IPSet(['0.0.0.0/0']) ^ IPV4_NON_ROUTABLE).iter_cidrs() ]

class NamespaceClosedError(Exception):
    pass

class CacheExpiredError(Exception):
    pass

class CachedValue:
    '''
    Pass a value and a timedelta, and the value will be returned until the
    timedelta has elapsed. Attempts to access the value past its expiration
    will raise CacheExpiredError.
    '''
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

    ca = '''
    -----BEGIN CERTIFICATE-----
    MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
    VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
    BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
    dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
    IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
    FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
    MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
    EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
    QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
    AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
    ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
    bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
    hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
    De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
    V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
    25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
    fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
    p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
    Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
    tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
    jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
    meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
    1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
    HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
    yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
    EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
    cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
    HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
    ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
    aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
    hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
    pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
    Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
    tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
    LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
    6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
    5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
    JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
    iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
    8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
    +no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
    -----END CERTIFICATE-----
    '''
    ca = '\n'.join([s.lstrip(' ') for s in ca.splitlines()])

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
        'get serverlist from api and cache it'
        rsp = requests.get(cls.serverlist_url)
        rsp.raise_for_status()
        ret = json.loads(rsp.text.split('\n')[0])
        cls.serverlist = CachedValue(ret, cls.cachetime)
        return ret

    @classmethod
    def get_serverlist(cls, cached=True):
        'get serverlist from cache or api'
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
        'get token from api and cache it'
        rsp = requests.post(self.token_url, auth=self.auth)
        rsp.raise_for_status()
        data = rsp.json()
        if data['status'] != 'OK':
            raise RuntimeError('Could not get token: {}'.format(data))
        ret = data['token']
        self.token = CachedValue(ret, self.cachetime)
        return ret

    def get_token(self, cached=True):
        'get token from cache or api'
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
        'use in-region api to get wireguard config'
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

        with NamedTemporaryFile('w') as ca:
            ca.write(self.ca)
            ca.flush()
            rsp = config_sess.get(f'{config_url}?{config_query}', verify=ca.name)
            rsp.raise_for_status()
            return rsp.json()

class DNSOverrideAdapter(requests.adapters.HTTPAdapter):
    '''
    This adapter intercepts requests made to common_name and connects to host
    instead. Any SSL checks will be performed against common_name, not host.
    This is useful if common_name is not in DNS and for mismatched SSL
    certificates.
    '''
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
    '''
    Gets an interface index by its name from a pyroute2 context. Works with both
    IPRoute and NetNS contexts.
    '''
    idx = context.link_lookup(ifname=name)
    if len(idx) == 1:
        return idx[0]
    return -1

def wg_up(iface, config, private_key, nspath):
    '''
    Create, set netns, and configure a WireGuard interface in the nspath netns.
    '''
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
    # Use larsks's NetNS here because pyroute2's WireGuard and NetNS don't seem
    # to interoperate.
    with SimpleNetNS(nspath=nspath):
        nameservers = [ '{}/32'.format(ip) for ip in config['dns_servers'] ]
        peer = {
            'public_key': config['server_key'],
            'endpoint_addr': config['server_ip'],
            'endpoint_port': config['server_port'],
            'allowed_ips': IPV4_ROUTABLE + nameservers,
        }
        wg = WireGuard()
        wg.set(iface, private_key=str(private_key), peer=peer)

    # bring interface up and set default route
    with NetNS(nspath) as ns:
        wg_idx = get_index(ns, iface)
        ns.link('set', index=wg_idx, state='up')
        ns.route('replace', dst='0.0.0.0/0', oif=wg_idx)

def check_netns_connectivity(nspath, iface, host='1.1.1.1'):
    '''
    Check for connectivity to a host (default 1.1.1.1) inside a netns. The iface
    is only checked for existence as an early out. If the iface exists but is
    unconfigured, and the netns has other connectivity to the host, this will not
    detect the unconfigured/misconfigured iface.
    '''
    print('checking connectivity nspath={} iface={}'.format(nspath, iface))
    try:
        # use larsks's NetNS here for both IPRoute and icmplib.ping
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
    '''
    Overwrite container's resolv.conf with the specified nameservers and
    optional search path.
    '''
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
    '''
    Main flow for configuring/connecting a single container. Determines its
    netns, checks to see if it already has connectivity, and then configures the
    WireGuard connection if not.
    '''
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
    '''
    Checks first for already running containers, and configures them. Then
    transitions to waiting for docker container start events, and configures
    containers as they start.
    '''
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
