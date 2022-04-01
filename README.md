# wg-docker

The [WireGuard home page](https://www.wireguard.com/#ready-for-containers)
mentions the possibility of making wg0 be a container's only interface, but it
is not something docker can do out of the box. This is a small daemon that makes
that possible. It runs on the docker host, watching for containers with specific
labels. When it finds one, it creates and configures a WireGuard interface in
the container's namespace.

Currently this is specific to Private Internet Access provider, as it uses their
APIs to authenticate and generate a configuration. It could be adapted to use a
static configuration or to work with another provider.

The container can be started with `--network none`, and then the VPN connection
will be the only connectivity. The container can also be started with one or
more networks for communicating with other containers. The WireGuard interface
will then take over as the default route.

## Flow

1. On startup, all running containers are checked for labels
2. After checking existing containers, start watching docker events
3. For each container found during startup or later events:
    1. Check for existing connectivity and skip already connected containers
    2. Create a wireguard interface in the host netns
    3. Move the wireguard interface to the container netns
    4. Authenticate against PIA servers and create wireguard config
    5. Configure the wireguard interface
    6. Set the container's resolv.conf file to the PIA nameservers

## Install

1. `make`
2. Add your PIA_USERNAME and PIA_PASSWORD to /opt/wg-docker/credentials
3. systemctl enable --now wg-docker.service

This currently must be installed and run on the docker host. Would like to
explore running this in a container but anticipating access problems since this
is all happening against the kernel.

## Starting/configuring Containers

The only requirement is setting the label `wg-docker.enable=true` on your
containers. You can also set wg-docker.region to the ID string of one of PIA's
regions. If you don't set a region, `ca_vancouver` will be used.

Here's a minimal example of starting a container with `docker run` and `docker
compose`. On my system, I start receiving replies within 1-2 seconds.

    docker run --rm --label wg-docker.enable=true --network none alpine \
      sh -c "until ping -c2 1.1.1.1 ; do sleep 1 ; done"

docker-compose.yml:

    services:
      vpnclient:
        image: alpine
        network_mode: none
        labels:
          wg-docker.enable: true
        command: sh -c "until ping -c2 1.1.1.1 ; do sleep 1 ; done"

For containers that need to communicate with other local containers but not the
host, I suggest using the ipvlan driver with internal=true. This creates a dummy
interface on the host to be the parent of the ipvlan interface. The host does
not have an address on that network.
      
## TODO
* ipv6 support
* check dns when checking connectivity
* proper logging
* can this all be done in a container? --privileged & CAP_NET_ADMIN?
