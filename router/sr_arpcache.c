#include "sr_arpcache.h"

#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*
  Based on the pseudocode in the header
  Sends arprequests for the request ip
  if one hasn't been sent in the last second
  and less than 5 requests have been sent
  otherwise sends an icmp host unreachable
*/
void sr_arpcache_handle_req(struct sr_instance *sr, struct sr_arpreq *req) {
  time_t now = time(NULL);
  /* take a lock on the cache since this can be concurrent */
  pthread_mutex_lock(&(sr->cache.lock));

  if (difftime(now, req->sent) < 1.0) {
    /* if a request was sent in the last second, return */
    pthread_mutex_unlock(&(sr->cache.lock));
    return;
  }

  if (req->times_sent >= 5) {
    /* if 5 requests have been sent, send icmp host unreachable */

    /*  walk the packets linked list and send back icmp host unreachable */
    struct sr_packet *packet;

    printf("Exceeded 5 requests\n");
    printf("REQ PACKETS %p\n", req->packets);
    for (packet = req->packets; packet != NULL; packet = packet->next) {
      struct sr_if *packet_iface = sr_get_interface(sr, packet->iface);
      sr_send_icmp(sr, icmp_type_dest_unreachable, icmp_code_host_unreachable,
                   packet->buf, packet_iface);
    }
    printf("Sent ICMP host unreachable\n");
    /* // then destroy the request */
    sr_arpreq_destroy(&(sr->cache), req);
    return;
  }

  req->sent = now;
  req->times_sent++;

  /* Send an ARP request */

  if (req->packets == NULL) {
    fprintf(stderr, "Error: packet or interface is null\n");
    return;
  }

  printf("Sending ARP request\n");

  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(len);

  uint32_t target_ip = req->ip;
  struct sr_if *dest_iface = sr_get_destination_iface(sr, target_ip);

  if (!dest_iface) {
    fprintf(stderr, "No matching interface found for destination IP\n");
    return;
  }

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* // Ethernet header */
  memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /* To BC */
  memcpy(eth_hdr->ether_shost, dest_iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  /* // ARP header */
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = sizeof(uint32_t);
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, dest_iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = dest_iface->ip;
  memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;

  /* // Send the ARP request */
  sr_send_packet(sr, packet, len, dest_iface->name);
  /*free(packet); */
  pthread_mutex_unlock(&(sr->cache.lock));
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look
  like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
  struct sr_arpreq *req, *next_req;
  req = sr->cache.requests;

  while (req != NULL) {
    /* keep a reference to the next request
    since handle req may destroy the current request
    if more than 5 requests have been sent */
    next_req = req->next;
    printf("Handling request for ip: ");
    print_addr_ip_int(req->ip);
    sr_arpcache_handle_req(sr, req);
    req = next_req;
  }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpentry *entry = NULL, *copy = NULL;

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
      entry = &(cache->entries[i]);
    }
  }

  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
    copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
    memcpy(copy, entry, sizeof(struct sr_arpentry));
  }

  pthread_mutex_unlock(&(cache->lock));

  return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache, uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len, char *iface) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpreq *req;
  for (req = cache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      break;
    }
  }

  /* If the IP wasn't found, add it */
  if (!req) {
    req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
    req->ip = ip;
    req->next = cache->requests;
    cache->requests = req;
  }

  /* Add the packet to the list of packets for this request */
  if (packet && packet_len && iface) {
    struct sr_packet *new_pkt =
        (struct sr_packet *)malloc(sizeof(struct sr_packet));

    new_pkt->buf = (uint8_t *)malloc(packet_len);
    memcpy(new_pkt->buf, packet, packet_len);
    new_pkt->len = packet_len;
    new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
    strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
    new_pkt->next = req->packets;
    req->packets = new_pkt;
  }

  pthread_mutex_unlock(&(cache->lock));

  return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac, uint32_t ip) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpreq *req, *prev = NULL, *next = NULL;
  for (req = cache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      if (prev) {
        next = req->next;
        prev->next = next;
      } else {
        next = req->next;
        cache->requests = next;
      }

      break;
    }
    prev = req;
  }

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    if (!(cache->entries[i].valid)) break;
  }

  if (i != SR_ARPCACHE_SZ) {
    memcpy(cache->entries[i].mac, mac, 6);
    cache->entries[i].ip = ip;
    cache->entries[i].added = time(NULL);
    cache->entries[i].valid = 1;
  }

  pthread_mutex_unlock(&(cache->lock));

  return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
  pthread_mutex_lock(&(cache->lock));

  if (entry) {
    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
      if (req == entry) {
        if (prev) {
          next = req->next;
          prev->next = next;
        } else {
          next = req->next;
          cache->requests = next;
        }

        break;
      }
      prev = req;
    }

    struct sr_packet *pkt, *nxt;

    for (pkt = entry->packets; pkt; pkt = nxt) {
      nxt = pkt->next;
      if (pkt->buf) free(pkt->buf);
      if (pkt->iface) free(pkt->iface);
      free(pkt);
    }

    free(entry);
  }

  pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
  fprintf(stderr,
          "\nMAC            IP         ADDED                      VALID\n");
  fprintf(stderr,
          "-----------------------------------------------------------\n");

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    struct sr_arpentry *cur = &(cache->entries[i]);
    unsigned char *mac = cur->mac;
    fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0],
            mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip),
            ctime(&(cur->added)), cur->valid);
  }

  fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
  /* Seed RNG to kick out a random entry if all entries full. */
  srand(time(NULL));

  /* Invalidate all entries */
  memset(cache->entries, 0, sizeof(cache->entries));
  cache->requests = NULL;

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(cache->attr));
  pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

  return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
  return pthread_mutex_destroy(&(cache->lock)) &&
         pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
  struct sr_instance *sr = sr_ptr;
  struct sr_arpcache *cache = &(sr->cache);

  while (1) {
    sleep(1.0);

    pthread_mutex_lock(&(cache->lock));

    time_t curtime = time(NULL);

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
      if ((cache->entries[i].valid) &&
          (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
        cache->entries[i].valid = 0;
      }
    }

    sr_arpcache_sweepreqs(sr);

    pthread_mutex_unlock(&(cache->lock));
  }

  return NULL;
}
