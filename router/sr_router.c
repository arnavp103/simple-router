/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include "sr_router.h"

#include <assert.h>
#include <stdio.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_forward_ip(struct sr_instance* sr, uint8_t* packet /* lent */,
                   unsigned int len, char* interface /* lent */);
void sr_handle_ip(struct sr_instance* sr, uint8_t* packet /* lent */,
                  unsigned int len, char* interface /* lent */);

void sr_init(struct sr_instance* sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

void sr_handle_arp(struct sr_instance* sr, uint8_t* packet /* lent */,
                   unsigned int len, char* interface /* lent */) {
  /* sanity check - packet must be at least the size of ethernet and arp header
   */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
    fprintf(stderr, "Dropping ARP packet that is too short\n");
    return;
  }

  /* sanity check - verify the ARP header */
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* check if the ARP request is for us */
  struct sr_if* iface = sr_get_interface(sr, interface);

  if (arp_hdr->ar_tip != iface->ip) {
    fprintf(stderr, "Dropping ARP request that is not for us\n");
    return;
  }

  /* if the ARP request is for us, send an ARP reply */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    printf(">>>>>>>>>>>>>>>>>>>> ARP request for us, we are:\n");
    print_addr_ip_int(iface->ip);

    /* create the ARP reply */
    uint8_t* reply = (uint8_t*)malloc(len + 1);
    memcpy(reply, packet, len);

    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)reply;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));

    /* Check if len is sufficient */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      fprintf(stderr, "Error: packet length is too small\n");
      free(reply);
      return;
    }

    /* | Ethernet header */

    /* Set to requesters MAC */
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);

    /* Set to our MAC */
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    /* | ARP Header */
    arp_hdr->ar_op = htons(arp_op_reply);

    /* Set target hardware address to the sender header from initial packet*/
    memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);

    arp_hdr->ar_tip = arp_hdr->ar_sip;
    arp_hdr->ar_sip = iface->ip;

    /* send the ARP reply */
    sr_send_packet(sr, reply, len, interface);
    printf("Send ARP reply directed to:\n");
    print_addr_ip_int(ntohl(arp_hdr->ar_tip));

    free(reply);
    return;
  }

  /* if the ARP reply is for us, cache the entry */
  printf("ARP reply\n");
  if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    printf("ARP reply for us\n");
    struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

    /* if there are packets waiting on this ARP request, send them */
    if (req) {
      struct sr_packet* packet = req->packets;
      while (packet) {
        sr_forward_ip(sr, packet->buf, packet->len, packet->iface);
        packet = packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);

    } else {
      fprintf(stderr, "Dropping ARP reply that is not for us\n");
    }
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, uint8_t* packet /* lent */,
                     unsigned int len, char* interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n\n*** -> Received packet of length %d \n", len);
  /* print_hdrs(packet, len);
  printf("I AM \n");
  print_addr_ip_int(sr_get_interface(sr, interface)->ip);
   */
  /* dispatch based on what kind of packet this is
from enum sr_ethertype*/
  uint16_t ethtype = ethertype(packet);

  switch (ethtype) {
    case ethertype_arp:
      printf("CLASS: ARP packet\n");
      sr_handle_arp(sr, packet, len, interface);
      break;
    case ethertype_ip:
      printf("CLASS: IP packet\n");
      sr_handle_ip(sr, packet, len, interface);
      break;
    default:
      fprintf(stderr, "Dropping unknown packet type\n");
  }
} /* end sr_handlepacket */

/*
  Before operating on an IP packet, you should verify its checksum and make sure
  it meets the minimum length of an IP packet .You should understand how to find
  the longest prefix match of a destination IP address in the routing table
  described in the ”Getting Started” section.If you determine that a datagram
  should be forwarded, you should correctly decrement the TTL field of the
  header and recompute the checksum over the changed header before forwarding it
  to the next hop
*/
/* IP Forwarding
Given a raw Ethernet frame, if the frame contains an IP packet that is not
destined for one of our interfaces: • Sanity-check the packet (meets minimum
length and has correct checksum).

• Decrement the TTL by 1, and recompute the packet checksum over the modified
header.

• Find out which entry in the routing table has the longest prefix match
with the destination IP address.

• Check the ARP cache for the next-hop MAC
address corresponding to the next-hop IP. If it’s there, send it. Otherwise,
send an ARP request for the next-hop IP (if one hasn’t been sent within the last
second), and add the packet to the queue of packets waiting on this ARP request.
Obviously, this is a very simplified version of the forwarding process, and the
low-level details follow. For example, if an error occurs in any of the above
steps, you will have to send an ICMP message back to the sender notifying them
of an error. You may also get an ARP request or reply, which has to interact
with the ARP cache correctly
*/
void sr_handle_ip(struct sr_instance* sr, uint8_t* packet /* lent */,
                  unsigned int len, char* interface /* lent */) {
  /* sanity check - packet must be at least the size of ethernet and ip header */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "Dropping IP packet that is too short\n");
    return;
  }

  /*  sanity check - verify checksum
   skip the ethernet header which makes up the first set of bytes */
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(sizeof(sr_ethernet_hdr_t) + packet);

  /* set the checksum to 0 and see if we compute the same checksum */
  uint16_t checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (checksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "Dropping IP packet with invalid checksum\n");
    return;
  }

  ip_hdr->ip_sum = checksum; /* restore the checksum */

  /*   -- completed sanity check -- */

  /* loop through interfaces to see if we're the destination
  if we are, handle it and early return */
  struct sr_if* curr;
  for (curr = sr->if_list; curr != NULL; curr = curr->next) {
    if (curr->ip == ip_hdr->ip_dst) {
      /* we are the destination */
      /* TODO: handle the packet for us */

      /* if the packet is an ICMP echo request, send an ICMP echo reply */
      if (ip_hdr->ip_p == ip_protocol_icmp) {
        printf("\tICMP packet\n");
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (icmp_hdr->icmp_type == icmp_type_echo_request) {
          printf("\tICMP echo request\n");
          struct sr_if* iface = sr_get_interface(sr, interface);
          /* sr_send_icmp(sr, icmp_type_echo_reply, icmp_code_echo_reply, packet, iface); */
          sr_send_icmp(sr, icmp_type_echo_reply, NULL, packet, iface);
          return;
        }
      }

      /* If the packet is a TCP or UDP packet, send an ICMP port unreachable message */
      if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
        struct sr_if* iface = sr_get_interface(sr, interface);
        printf("Dropping TCP or UDP packet\n");
        sr_send_icmp(sr, icmp_type_dest_unreachable, icmp_code_port_unreachable, packet, iface);
        return;
      }

      /* if the packet is not an ICMP echo request, drop the packet */
      if (ip_hdr->ip_p != ip_protocol_icmp) {
        fprintf(stderr, "Dropping packet that is not an ICMP echo request\n");
        return;
      }

      return;
    }
  }

  /*   not the destination, forward the packet
  decrement the TTL */
  ip_hdr->ip_ttl--;

  /* if the TTL is 0, send an ICMP TTL exceeded message */
  if (ip_hdr->ip_ttl == 0) {
    printf("TTL is 0\n");
    struct sr_if* iface = sr_get_interface(sr, interface);
    sr_send_icmp(sr, icmp_type_time_exceeded, icmp_code_time_exceeded_transit,
                 packet, iface);
    return;
  }

  /* recompute the checksum */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  sr_forward_ip(sr, packet, len, interface);
}

void sr_forward_ip(struct sr_instance* sr, uint8_t* packet /* lent */,
                   unsigned int len, char* interface /* lent */) {
  struct sr_rt* route = sr->routing_table;

  struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

  struct sr_rt* best_match = NULL;

  /* Longest prefix match */
  while (route != NULL) {
    struct sr_if* iface = sr_get_interface(sr, route->interface);
    if ((route->mask.s_addr & ip_hdr->ip_dst) == route->dest.s_addr) {
      best_match = route;
    }
    route = route->next;
  }

  /* Set route to the best match. */
  route = best_match;

  /* No match -> send an ICMP net unreachable message */
  if (!route) {
    printf("No match in routing table\n");
    struct sr_if* iface = sr_get_interface(sr, interface);
    sr_send_icmp(sr, icmp_type_dest_unreachable, icmp_code_net_unreachable,
                 packet, iface);
    return;
  }

  in_addr_t destination_ip = route->gw.s_addr;

  struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), destination_ip);

  /* if the MAC address is not in the cache, send an ARP request (if last
   request was > 1s ago) and add the packet to the queue of packets waiting on
   this ARP request*/
  if (!entry) {
    /* Check that the last request was sent more than 1 second ago*/

    /* Iterate through the ARP cache requests. */
    struct sr_arpreq* arpReq = sr->cache.requests;
    while (arpReq) {
      printf("ARP REQUEST IP: %d\n", arpReq->ip);

      if (arpReq->ip == destination_ip) {
        break;
      }
      arpReq = arpReq->next;
    }

    /* send ARP request */
    sr_arpcache_queuereq(&(sr->cache), destination_ip, packet, len, interface);
    /*  handle_arpreq(req); */

    return;
  }

  uint8_t* mac = entry->mac;

  /* Get the interface */
  struct sr_if* iface = sr_get_interface(sr, route->interface);

  /* Set the ethernet header */
  struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;

  /* Set the destination MAC address to the next hop MAC address */
  memcpy(eth_hdr->ether_dhost, mac, ETHER_ADDR_LEN);

  /* Set the source MAC address to the MAC address of the outgoing interface */
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* Send the packet */
  sr_send_packet(sr, packet, len, iface->name);

  free(entry);
}