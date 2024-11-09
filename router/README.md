# Simple Router Implementation

## Team Members

-   Arnav Priyadarshi 1007338855

-   Yron Lance Talban 1008372397

## Sections Focused On

Arnav: ICMP Protocol Handling and Setup

Lance: ARP and IP Forwarding

Both of us swapped regularly to debug each other’s work.

## Implementing the required functionality

We will proceed with a high level overview of the problems faced and our solution.

### Core Router Functions

We needed to handle the response differently based on the type of the packet. Here we switched on protocol and handled both cases seperately.

Packet Handling (sr_router.c)

-   sr_handlepacket() - Main entry point for packet processing. Dispatches packets based on type (ARP vs IP).
-   sr_handle_arp() - Handles incoming ARP requests/replies. Sends ARP replies for requests targeting router interfaces.
-   sr_handle_ip() - Processes IP packets. Handles TTL expiry, ICMP messages, and packet forwarding.

### ARP Cache Management (sr_arpcache.c)

Here we simply proceeded with the pseudocode that was laid out in the comments of the header file.
Since we wanted to prevent the router from stalling while doing ARP requests, we tried to keep the code short and hold onto the lock for a minimal amount of time.

-   sr_arpcache_sweepreqs() - Periodically checks pending ARP requests and handles timeouts
-   sr_arpcache_handle_req() - Manages ARP request retries and timeouts (max 5 attempts)
-   sr_arpcache_insert() - Adds IP->MAC mappings to cache with 15 second timeout
-   sr_arpcache_queuereq() - Queues packets waiting for ARP replies

### ICMP Message Generation (sr_utils.c)

From the sr_protocol file we set up functionality to:
Responds to echo requests (ping)
Generates unreachable messages for:
Host unreachable (failed ARP)
Port unreachable (TCP/UDP to router)
Network unreachable (no route)
Handle TTL expired messages for traceroute

-   sr_send_icmp() - Sends ICMP error messages (unreachable, TTL expired, etc)
-   sr_send_icmp_ping() - Handles ICMP echo requests/replies specifically

We had to study the RFC for ICMP to determine that there's a difference in memory layout for ICMP ping which tripped us up but apart from some straightforward memory copying this wasn't too hard to implement.

### IP Forwarding

Here we use the longest prefix match to find the next hop. We then forward packets after ARP resolution.

-   sr_forward_ip() - Implements IP packet forwarding using longest prefix match routing as per CIDR with subnets.

Relatively straightforward since we can rely on the machinery of the ARP handling code we had before. There were some decisions we had to make with respect to handling non direct addresses so we based our solution to the piazza post about non contiguous subnets.

## Test Cases Results and Reproduction Steps

## PING Tests

```
Ping Valid App Server
mininet> client ping -c 8 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=2 ttl=63 time=750 ms
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=1814 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=63 time=60.3 ms
64 bytes from 192.168.2.2: icmp_seq=4 ttl=63 time=40.8 ms
64 bytes from 192.168.2.2: icmp_seq=5 ttl=63 time=19.0 ms
64 bytes from 192.168.2.2: icmp_seq=6 ttl=63 time=82.8 ms
64 bytes from 192.168.2.2: icmp_seq=7 ttl=63 time=13.4 ms
64 bytes from 192.168.2.2: icmp_seq=8 ttl=63 time=40.9 ms

--- 192.168.2.2 ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7022ms
rtt min/avg/max/mdev = 13.380/352.598/1813.697/599.111 ms, pipe 2
```

#### Ping Valid Router Interface

```
mininet> client ping -c 8 172.64.3.10
PING 172.64.3.10 (172.64.3.10) 56(84) bytes of data.
64 bytes from 172.64.3.10: icmp_seq=2 ttl=63 time=428 ms
64 bytes from 172.64.3.10: icmp_seq=1 ttl=63 time=1430 ms
64 bytes from 172.64.3.10: icmp_seq=3 ttl=63 time=9.53 ms
64 bytes from 172.64.3.10: icmp_seq=4 ttl=63 time=29.1 ms
64 bytes from 172.64.3.10: icmp_seq=5 ttl=63 time=92.3 ms
64 bytes from 172.64.3.10: icmp_seq=6 ttl=63 time=21.6 ms
64 bytes from 172.64.3.10: icmp_seq=7 ttl=63 time=57.2 ms
64 bytes from 172.64.3.10: icmp_seq=8 ttl=63 time=67.7 ms

--- 172.64.3.10 ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7010ms
rtt min/avg/max/mdev = 9.530/266.952/1430.105/457.725 ms, pipe 2
```

#### Ping Invalid Address

```
mininet> client ping -c 8 192.168.2.59
PING 192.168.2.59 (192.168.2.59) 56(84) bytes of data.
From 10.0.1.1 icmp_seq=1 Destination Net Unreachable
From 10.0.1.1 icmp_seq=2 Destination Net Unreachable
From 10.0.1.1 icmp_seq=3 Destination Net Unreachable
From 10.0.1.1 icmp_seq=4 Destination Net Unreachable
From 10.0.1.1 icmp_seq=5 Destination Net Unreachable
From 10.0.1.1 icmp_seq=6 Destination Net Unreachable
From 10.0.1.1 icmp_seq=7 Destination Net Unreachable
From 10.0.1.1 icmp_seq=8 Destination Net Unreachable

--- 192.168.2.59 ping statistics ---
8 packets transmitted, 0 received, +8 errors, 100% packet loss, time 7012ms
```

## Traceroute Tests

#### Traceroute Valid App Server

```
mininet> client traceroute 192.168.2.2
traceroute to 192.168.2.2 (192.168.2.2), 30 hops max, 60 byte packets
1 10.0.1.1 (10.0.1.1) 57.759 ms 57.742 ms 57.744 ms
2 \* \* _
3 _ \* _
4 _ \* _
5 _ 192.168.2.2 (192.168.2.2) 1683.133 ms 1684.381 ms
```

#### Traceroute Valid Router Interface

```
mininet> client traceroute 172.64.3.10
traceroute to 172.64.3.10 (172.64.3.10), 30 hops max, 60 byte packets
1 10.0.1.1 (10.0.1.1) 30.656 ms \* _
2 _ \* _
3 _ \* _
4 _ \* _
5 _ 172.64.3.10 (172.64.3.10) 1734.251 ms 1736.098 ms
```

#### Traceroute Invalid Address

```
mininet> client traceroute 172.64.3.55
traceroute to 172.64.3.55 (172.64.3.55), 30 hops max, 60 byte packets
1 10.0.1.1 (10.0.1.1) 31.237 ms 46.241 ms 49.210 ms
2 10.0.1.1 (10.0.1.1) 53.778 ms !N 56.012 ms !N 60.476 ms !N
```

#### Download File

```
mininet> client wget http://192.168.2.2
--2024-11-07 15:07:24-- http://192.168.2.2/
Connecting to 192.168.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 161 [text/html]
Saving to: 'index.html.3'

index.html.3 100%[===================>] 161 --.-KB/s in 0s

2024-11-07 15:07:26 (63.1 MB/s) - 'index.html.3' saved [161/161]
```
