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


## Route numbers

There are 256 route numbers.  Every packet has one, and repeaters only repeat if  they have enabled a matching
route number.  By default, everything is sent with route number 0, which is enabled by default.

This only affects repeaters, nodes will listen to any mesh route number if it is directly for them.

## Payloads

Packet payloads are MessagePack arrays.  They alternate integer data IDs and
data items.  192-256 are reserved for application-specific messages.

ID 32 is for text messages, which can be prefixed with a username and a colon.

ID 2 is used for a unique ID, wich can be a string, bytes, or integer, but must be unique per-channel.  Many applications don't actually need this.

## Transports


### MQTT Routing

Append a metadata length byte and N bytes of metadata.

To create the IV, take 12 random bytes for the IV.
Then encrypt the whole thing.
Prepend the IV and append 4 auth tag bytes.


Then take the first 8 bytes of the routing ID hash and convert to hex.

The MQTT topic will be lazymesh_route_HEX

Note that we use a top-level topic.  This is so you can't use wildcards
to subscribe to all lazymesh channels at once on public brokers,
which would allow you to DoS everyone rather easily.



### UDP Routing

Just the raw packets broadcast on 224.0.0.251:2221

## Packet structure

Nothing about this is finalized!!!

```
All numbers are little-endian.

1 byte header:
  2 bit packet type(Either 1 or 2, depending on if we want ACK)
  3 bits TTL hops remaining
  1 bit allow slow transport(LoRa etc)
  1 bit allow global routing
  1 bit was already global routed

1 byte header 2:
    1 bit first send attempt:
        Whenever we create a  or recieve a packet, set this bit.  After trying to send it,
        clear it.  This way, as long as we assume packet loss is low-ish, we can count the repeaters in the area
        without extra overhead.

    1 bit repeater bit:
        Marks that this packet should be included when counting repeaters.
        Set it if you would repeat the packet or one like it, even if you originated it.

    1 bit location enabled
        If this bit is set, repeaters may add location metadata to the packets forwarded to the internet. This metadata must be encrypted with the routing ID as the key,
        meaning nearby people could track you for 1 hour after you get out of range.

        Not implemented anywhere at the moment.


    5 reserved 0 bits



1 byte mesh route number

1 byte path loss accumulated:
    5 bits total
    3 bits last hop
    
    Every hop is a point of path loss,
    plus whatever extra cost heuristic the transport applies.
    1 extra point of loss should be roughly the same "badness" as
    10dbm extra loss on wifi.

16 bytes routing ID:
    Changes every hour, derived from the channel PSK by a hash.
    The PSK is just the 16 byte SHA256 of the password.

    The routing ID changes hourly, and is the SHA256 of:
        The letter 'cr'
        The count of hours since 1970 as a 32 bit unsigned int
        the PSK
    


8 Bytes random entropy:
   Used as part of the IV for the cipher

4 bytes timestamp:
   Also part of the IV, also prevents replay attacks

N bytes ciphertext:
    AES-GCM encrypted.

    The encryption key changes hourly, and is the SHA256 of:
        The letter 'c'
        The count of hours since 1970 as a 32 bit unsigned int
        the PSK

6 bytes auth tag:
    The last 6 bytes are the GCM tag

```

## ACK Packets and Retries

Some implementations may choose to entirely ignore this.

Ack packets are not repeated or routed or anything, nor are they authenticated.  Every step of mesh repeating has it's own acknowlegement, from the original sender's perspective, it's fire and forget.

Like Meshtastic and most others, the protocol is "semi-reliable", there are, like all networks, edge cases causing failure.  

Real reliability must be done at a higher level.

For every packet, every interested lister to that specific channel sends an channel acknowlege exactly once.

For every packet on a transport that does not support loopback routing, repeaters send a repeater acknowlege the first time they see a packet.

For packets on transports that do support loopback, nodes do not need to send the acknowledge,
because the repeated packet with the "first copy from this node" flag and the "I'm a repeater for packets like this" flag serves as the acknowledge.

This lets a node determine how many other repeaters and channel listeners are in the area.


Nodes may resend a message a few times if they get fewer than expected replies.


```
1 byte header:
   Always 0, packet type is control, and these are not routable or repeatable

1 byte header 2:
   Same as on the data packets. Not really used at the moment

1 byte subtype:
   CONTROL_TYPE_CHANNEL_ACKNOWLEDGE or CONTROL_TYPE_REPEATER_ACKNOWLEDGE
   You can acknowlege as a channel listener or as a repeater,
   so the sender knows how many of each there are.

4 byte message ID:
  just the first 4 bytes of the random IV from the packet we are ACKing

4 byte ack ID:

Random number unique to the node, for debugging only.  More advanced implementations
can use this to better count nodes.  Must not be the same for all channels on a node and must
change periodically for privacy.

```

### Announce Packets
Evey hour, a few minutes before the hour, nodes should send an announce of the channels they are interested in.

This should be sent with the rolling codes for the *next* hour rather than the current hour, so that connections
can be set up in advance and everything works even when times are out of sync.

## Bluetooth

Nodes mesh via bluetooth using an extended advertising packet with service UUID
d1a77e11-420f-9f11-1a00-10a6beef0001, and the payload just being the packet format above.


BLE packets must not ever have the "first copy" flag set, and we do not count repeaters over BLE.
The packet loss is just too high for any simple and scalable scheme I can think of.

Therefore, we just treat it as an inherently lossy channel, which we mitigate somewhat by repeating packets up to 4 times, or until we need to stop doing that so we can send some other packet.

As long as the node doesn't try to send more than a packet or two per second, the pure repeat
scheme will provide some reliability, and if we go past that, then it will back off to
not jam everything.

We also stop sending if we see a too many other nodes in the same area sending too many copies of the packet.