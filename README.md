# LazyMesh

![Image](img/lazymesh.avif)

Mesh routing system that supports using an OpenDHT proxy as the backend, so that nodes can communicate directly via the internet. Very early pre alpha, proof of concept, might not actually work, etc.

This is meant for both hobby/HAM use cases, and more typical consumer/commercial IoT work, but specifically does not
try to replace the internet, or to cover large high traffic areas with omnidirectional antennas.  

It does not have Meshtastic-style next hop routing, hence the name LazyMesh.  If you want to use it for offgrid type applications in a dense area, you will probably need directional antennas and manually coordinated route IDs.


## Chat Sketch

Right now this is the only actual application. Open the example Arduino sketch, modify it with your username,
and a secret channel key which must be a strong password.

Type your message in the Arduino serial monitor, and you should be able to chat with all other devices.

Messages should get through as long as nodes are either on the same network, or both have internet access.

## Features

* ESP32 Only at the moment!!
* Arduino Library
* Encryption(AES-GCM 128 bit)
* Authentication (6 byte MACs on all messages)
* Rolling code IDs for privacy(Changing once an hour)
* Replay attack protection (Messages are timestamped)
* Pluggable Routing Backends(UDP and OpenDHT currently)
* Mesh flooding
* Limited source routing abilities, packets have a mesh route number and routers can choose which routes to forward
* Mesh payloads are MessagePack for extensibility and flexibility
* Some kind of time sync within a minute or two is required
* 37 bytes of overhead per packet, 220 bytes max, including the overhead

## Time Sync

Nodes need some way to sync the time to communicate. Currently, if they have never recieved time from a trusted source,
they will set their time from any random packet they see.

This could be a security risk allowing replay attacks, so devices that need security should have a trusted time source.

Once the time has been initially set, the code will adjust it's system time by up to 1 second per day to stay in sync with
other nodes, so drifting out of sync should not be a major issue.

## Channels

In Lazymesh, everything is a channel, there are no direct messages. If you want them, just make a dedicated private channel.

Channels are defined by a password, knowing the password allows read and write access.

Data packets on a channel are Messagepack objects.  If they are an array, they must by a list of alternating data IDs and values, where data IDs are from a reserved list(TBD).

## Route numbers

There are 256 route numbers.  Every packet has one, and repeaters only repeat if  they have enabled a matching
route number.  By default, everything is sent with route number 0, which is enabled by default.

This only affects repeaters, nodes will listen to any mesh route numberif it is directly for them.

## Transports

### OpenDHT Routing

Nodes that are directly connected to the internet can communicate through an OpenDHT Proxy, and no
account or signup is needed. Unlike with MQTT backends, nodes on different proxies can still communicate,
because the entire DHT is a distributed global swarm.

These nodes can forward up to 1 packet per minute from other nodes onto the DHT.

They cannot forward any traffic from the DHT onto the mesh, except for traffic on the channels and groups the gateway device
is specifically configured for.  It doesn't work like a cell tower, but it does allow roaming nodes to send out a few 
packets to a reciever that has internet access.

Packets can only be globally routed if they have the global routing bit set.  Nodes that have already global
routed a packet will unset this bit, so that other nodes don't do it redundantly.

Packets coming from OpenDHT will have the "was global routed" bit set and can never go back on the internet,
only one hop is allowed.

The data format allows for metadata to be added in the future along with the packet.

The OpenDHT keys change hourly, and all traffic to the DHT has an extra layer of encryption.

### UDP Routing

Just the raw packets broadcast on 224.0.0.251:2221

## Packet structure

Nothing about this is finalized!!!

```
All numbers are little-endian.

1 byte header:
  2 bit packet type
  3 bits TTL hops remaining
  1 bit allow slow transport(LoRa etc)
  1 bit allow global routing
  1 bit was already global routed

1 byte mesh route number

1 byte path loss accumulated:
    5 bits total
    3 bits last hop
    
    Every hop is a point of path loss,
    plus whatever extra cost heuristic the transport applies.
    1 extra point of loss should be roughly the same "badness" as
    10dbm extra loss on wifi.

16 bytes routing ID:
    Changes every hour, derived from the channel PSK bye a hash.
    The PSK just the 16 byte SHA256 of the password.

    The routing ID is the SHA256 of:
        The letter 'r'
        The count of hours since 1970 as a 32 bit unsigned int
        the PSK




8 Bytes random entropy:
   Used as part of the IV for the cipher

4 bytes timestamp:
   Also part of the IV, also prevents replay attacks

6 bytes auth tag:
   The auth tag comes before the ciphertext because it(subjectively)
   makes the code simpler.

N bytes ciphertext:
    AES-GCM encrypted.

    The encryption key also changes hourly, and is the SHA256 of:
        The letter 'r'
        The count of hours since 1970 as a 32 bit unsigned int
        the PSK
```

### Announce Packets
Evey hour, a few minutes before the hour, nodes should send an announce of the channels they are interested in.

This should be sent with the rolling codes for the *next* hour rather than the current hour, so that connections
can be set up in advance and everything works even when times are out of sync.