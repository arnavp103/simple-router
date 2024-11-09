

#include "sr_utils.h"

#include "sr_protocol.h"
#include "sr_router.h"

uint16_t cksum(const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0; len >= 2; data += 2, len -= 2) sum += data[0] << 8 | data[1];
  if (len > 0) sum += data[0] << 8;
  while (sum > 0xffff) sum = (sum >> 16) + (sum & 0xffff);
  sum = htons(~sum);
  return sum ? sum : 0xffff;
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

sr_ethernet_hdr_t *sr_extract_eth_hdr(uint8_t *buf) {
  return (sr_ethernet_hdr_t *)buf;
}

sr_ip_hdr_t *sr_extract_ip_hdr(uint8_t *buf) {
  /* skip the ethernet header which goes first */
  return (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + buf);
}

sr_icmp_t3_hdr_t *sr_extract_icmp_t3_hdr(uint8_t *buf) {
  /* skip the ethernet and ip headers */
  return (sr_icmp_t3_hdr_t *)(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                              buf);
}

struct sr_if *sr_get_destination_iface(struct sr_instance *sr,
                                       uint32_t target_ip) {
  /* Get destination iface */
  struct sr_rt *rt_entry = sr->routing_table;
  while (rt_entry) {
    uint32_t masked = rt_entry->mask.s_addr & target_ip;

    if (masked == rt_entry->dest.s_addr) {
      return sr_get_interface(sr, rt_entry->interface);
    }
    rt_entry = rt_entry->next;
  }

  return NULL;
}

/*
  ICMP echo request and reply have a slightly different format header
  than other ICMP messages. Use this for pings and echos replies.
  - sr is the router instance.
  - icmp_type can be either echo request(8) or echo reply(0).
*/
int sr_send_icmp_ping(struct sr_instance *sr, uint8_t icmp_type,
                      uint8_t *raw_frame, struct sr_if *iface) {
  /* allocate a new frame */
  unsigned int new_len =
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t *new_frame = (uint8_t *)calloc(1, new_len);

  /* get pointers to the headers of our frame */
  sr_ethernet_hdr_t *eth_hdr = sr_extract_eth_hdr(new_frame);
  sr_ip_hdr_t *ip_hdr = sr_extract_ip_hdr(new_frame);
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(sizeof(sr_ethernet_hdr_t) +
                                              sizeof(sr_ip_hdr_t) + new_frame);

  /* get orignal headers of the packet */
  sr_ethernet_hdr_t *orig_eth_hdr = sr_extract_eth_hdr(raw_frame);
  sr_ip_hdr_t *orig_ip_hdr = sr_extract_ip_hdr(raw_frame);

  /* get the interface we send the packet out of */
  struct sr_if *out_iface = NULL;
  struct sr_rt *rt_entry;

  /* loop over the routing table entries */
  for (rt_entry = sr->routing_table; rt_entry != NULL;
       rt_entry = rt_entry->next) {
    /* find the entry where the masked original packet's src */
    /* matches the routing table entry's dest */
    if ((rt_entry->mask.s_addr & orig_ip_hdr->ip_src) == rt_entry->dest.s_addr) {
      out_iface = sr_get_interface(sr, rt_entry->interface);
      break;
    }
  }

  if (out_iface == NULL) {
    fprintf(stderr, "Could not find interface to send ICMP message\n");
    return -1;
  }

  /* fill in the ethernet header */
  memcpy(eth_hdr->ether_dhost, orig_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  /* set the ethernet type to IP */
  eth_hdr->ether_type = htons(ethertype_ip);

  /* fill in the ip header */
  ip_hdr->ip_v = orig_ip_hdr->ip_v;     /* reuse the ip version */
  ip_hdr->ip_hl = orig_ip_hdr->ip_hl;   /* reuse the header length */
  ip_hdr->ip_tos = orig_ip_hdr->ip_tos; /* reuse the type of service */
  ip_hdr->ip_len =
      htons(new_len -
            sizeof(sr_ethernet_hdr_t)); /* set the length of the ip header */
  ip_hdr->ip_id = 0;                    /* set the id to 0 since it's not used */
  ip_hdr->ip_off = htons(IP_DF);        /* set the flags to don't fragment */
  ip_hdr->ip_ttl = INIT_TTL;            /* set the time to live to default */
  ip_hdr->ip_p = ip_protocol_icmp;      /* set the protocol to ICMP */
  ip_hdr->ip_src = iface->ip;           /* set source IP to this interface IP */
  ip_hdr->ip_dst = orig_ip_hdr->ip_src; /* set dest IP to the original source */

  ip_hdr->ip_sum = 0; /* start with the checksum as 0 */
  ip_hdr->ip_sum =
      cksum(ip_hdr, sizeof(sr_ip_hdr_t)); /* compute the checksum */

  /* fill in the icmp header */
  icmp_hdr->icmp_type = icmp_type;       /* set the type of the ICMP message */
  icmp_hdr->icmp_code = icmp_code_empty; /* set the code of the ICMP message */
  icmp_hdr->icmp_sum = 0;                /* start with the checksum as 0 */
  icmp_hdr->icmp_sum =
      cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)); /* compute checksum */

  return sr_send_packet(sr, new_frame, new_len, out_iface->name);
}

/*
  Sends an ICMP message where the type is a name in the enum sr_icmp_type and
  code is a name in the enum sr_icmp_code.
  - sr is the router instance.
  - icmp_type is the type of the ICMP message - note this should not be echo
  - icmp_code is the code of the ICMP message.
  - raw_frame is the original frame that caused the error.
  - iface is the interface the frame was received on.
*/
int sr_send_icmp(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code,
                 uint8_t *raw_frame, struct sr_if *iface) {
  /* for integrity we will allocate a new frame and not reuse the buffer */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                     sizeof(sr_icmp_t3_hdr_t);
  uint8_t *frame = (uint8_t *)calloc(1, len);

  /* get pointers to the headers of our frame */
  sr_ethernet_hdr_t *eth_hdr = sr_extract_eth_hdr(frame);
  sr_ip_hdr_t *ip_hdr = sr_extract_ip_hdr(frame);
  sr_icmp_t3_hdr_t *icmp_hdr = sr_extract_icmp_t3_hdr(frame);

  /* get orignal headers of the packet */
  sr_ethernet_hdr_t *orig_eth_hdr = sr_extract_eth_hdr(raw_frame);
  sr_ip_hdr_t *orig_ip_hdr = sr_extract_ip_hdr(raw_frame);

  /* get the interface we send the packet out of */
  struct sr_if *out_iface = sr_get_destination_iface(sr, orig_ip_hdr->ip_src);

  if (out_iface == NULL) {
    fprintf(stderr, "Could not find interface to send ICMP message\n");
    return -1;
  }

  /* fill in the ethernet header */
  /* destination MAC address is the source MAC address of the original frame */
  memcpy(eth_hdr->ether_dhost, orig_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  /* source MAC address is the address of the interface we send the packet from
   */
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  /* set the ethernet type to IP */
  eth_hdr->ether_type = htons(ethertype_ip);

  /* fill in the ip header */
  ip_hdr->ip_v = orig_ip_hdr->ip_v;     /* reuse the ip version */
  ip_hdr->ip_hl = orig_ip_hdr->ip_hl;   /* reuse the header length */
  ip_hdr->ip_tos = orig_ip_hdr->ip_tos; /* reuse the type of service */
  ip_hdr->ip_len = htons(
      len - sizeof(sr_ethernet_hdr_t)); /* set the length of the ip header */
  ip_hdr->ip_id = 0;                    /* set the id to 0 since it's not used */
  ip_hdr->ip_off = htons(IP_DF);        /* set the flags to don't fragment */
  ip_hdr->ip_ttl = INIT_TTL;            /* set the time to live to default */
  ip_hdr->ip_p = ip_protocol_icmp;      /* set the protocol to ICMP */
  ip_hdr->ip_src = iface->ip;           /* set source IP to the interface IP */
  ip_hdr->ip_dst = orig_ip_hdr->ip_src; /* set dest IP to the original source */

  ip_hdr->ip_sum = 0; /* start with the checksum as 0 */
  ip_hdr->ip_sum =
      cksum(ip_hdr, sizeof(sr_ip_hdr_t)); /* compute the checksum */

  /* fill in the icmp header */
  icmp_hdr->icmp_type = icmp_type; /* set the type of the ICMP message */
  icmp_hdr->icmp_code = icmp_code; /* set the code of the ICMP message */
  memcpy(icmp_hdr->data, orig_ip_hdr,
         ICMP_DATA_SIZE); /* copy the header as data */
  icmp_hdr->icmp_sum = 0; /* start with the checksum as 0 */
  icmp_hdr->icmp_sum =
      cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); /* compute checksum */

  printf("Possible err\n");
  print_hdr_ip(frame + sizeof(sr_ethernet_hdr_t));
  print_hdr_icmp(frame + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  return sr_send_packet(sr, frame, len, out_iface->name);
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0) fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr, "inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}

/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {
  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  } else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  } else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}
