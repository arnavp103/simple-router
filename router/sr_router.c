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

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

  // dispatch based on what kind of packet this is
  // from enum sr_ethertype
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_arp) {
    // TODO: handle ARP
    sr_handle_arp(sr, packet, len, interface);
  } else if (ethtype == ethertype_ip) {
    sr_handle_ip(sr, packet, len, interface);
  } else {
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
header. • Find out which entry in the routing table has the longest prefix match
with the destination IP address. • Check the ARP cache for the next-hop MAC
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
  // sanity check - packet must be at least the size of ethernet and ip header
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "Dropping IP packet that is too short\n");
    return;
  }

  // sanity check - verify checksum
  // skip the ethernet header which makes up the first set of bytes
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  // set the checksum to 0 and see if we compute the same checksum
  uint16_t checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (checksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "Dropping IP packet with invalid checksum\n");
    return;
  }
  ip_hdr->ip_sum = checksum;  // restore the checksum

  // -- completed sanity check --

  // loop through interfaces to see if we're the destination
  // if we are, handle it and early return
  struct sr_if* curr;
  for (curr = sr->if_list; curr != NULL; curr = curr->next) {
    if (curr->ip == ip_hdr->ip_dst) {
      // we are the destination
      // TODO: handle the packet for us
    }
    return;
  }

  // not the destination, forward the packet
  // decrement the TTL
  ip_hdr->ip_ttl--;

  // if the TTL is 0, send an ICMP TTL exceeded message
  if (ip_hdr->ip_ttl == 0) {
    // TODO: send message
    return;
  }

  // recompute the checksum
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  sr_forward_ip(sr, packet, len, interface);
}

void sr_forward_ip(struct sr_instance* sr, uint8_t* packet /* lent */,
                   unsigned int len, char* interface /* lent */) {
  // TODO: find the longest prefix match in the routing table
}