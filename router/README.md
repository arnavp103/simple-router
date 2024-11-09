# Simple Router Implementation

## Team Members
Arnav Priyadarshi 1007338855

## Sections Focused On
Arnav:

## Implementing the required functionality

We will proceed with a high level overview of the problems faced and our solution. 

### Core Router Functions
Packet Handling (sr_router.c)
sr_handlepacket() - Main entry point for packet processing. Dispatches packets based on type (ARP vs IP).
sr_handle_arp() - Handles incoming ARP requests/replies. Sends ARP replies for requests targeting router interfaces.
sr_handle_ip() - Processes IP packets. Handles TTL expiry, ICMP messages, and packet forwarding.
sr_forward_ip() - Implements IP packet forwarding using longest prefix match routing.

### ARP Cache Management (sr_arpcache.c)
sr_arpcache_sweepreqs() - Periodically checks pending ARP requests and handles timeouts
sr_arpcache_handle_req() - Manages ARP request retries and timeouts (max 5 attempts)
sr_arpcache_insert() - Adds IP->MAC mappings to cache with 15 second timeout
sr_arpcache_queuereq() - Queues packets waiting for ARP replies
ICMP Message Generation (sr_utils.c)
sr_send_icmp() - Sends ICMP error messages (unreachable, TTL expired, etc)
sr_send_icmp_ping() - Handles ICMP echo requests/replies specifically
Key Data Structures
ARP Cache (sr_arpcache.h)
struct sr_arpcache - Main ARP cache with entries and request queue
struct sr_arpentry - Individual cache entries mapping IP->MAC
struct sr_arpreq - Tracks pending ARP requests and queued packets
Router State (sr_router.h)
struct sr_instance - Core router state including interfaces and routing table
struct sr_if - Interface information including IP and MAC addresses
Implementation Details
### ARP Handling
Responds to ARP requests targeting router interfaces
Caches ARP replies for 15 seconds
Queues packets waiting for ARP resolution
Retries ARP requests up to 5 times before declaring host unreachable
IP Forwarding
Uses longest prefix match to find next hop
Decrements TTL and recomputes checksum
Handles TTL expiry with ICMP time exceeded messages
Forwards packets after ARP resolution
ICMP Support
Responds to echo requests (ping)
Generates unreachable messages for:
Host unreachable (failed ARP)
Port unreachable (TCP/UDP to router)
Network unreachable (no route)
Handles TTL expired messages for traceroute
The router provides reliable packet forwarding while properly handling error cases through ICMP messaging. The ARP cache implementation ensures efficient address resolution while preventing packet loss during the ARP request process.