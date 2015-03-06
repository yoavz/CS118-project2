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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

static uint16_t IP_ID = 0;

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
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

/* Implicit definitions to silence warnings */

void handle_arp_packet(struct sr_instance *sr,
                       uint8_t *packet,
                       char *interface);
void handle_arp_request(struct sr_instance *sr,
                        sr_arp_hdr_t *hdr,
                        char *interface);
void handle_arp_reply(sr_arp_hdr_t *hdr);
void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet,
                      char *interface);
void process_icmp(struct sr_instance *sr,
                  uint8_t *packet,
                  int icmp_length,
                  char *interface);
void send_icmp_t3(struct sr_instance *sr,
                  uint8_t *packet,
                  char *interface,
                  int code);

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


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* make a copy of the packet */
  uint8_t *packet_cpy = (uint8_t *) malloc (len);
  memcpy( packet_cpy, packet, len );

  /* printf("*** -> Received packet of length %d \n",len); */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet_cpy;

  /* TODO: check dest MAC address lines up? */
  
  /* arp handling */
  switch( ntohs(eth_hdr->ether_type) ) {

    case ethertype_arp: 
      handle_arp_packet(sr, packet_cpy + sizeof(sr_ethernet_hdr_t), interface);
      break;

    case ethertype_ip:
      handle_ip_packet(sr, packet_cpy, interface);
      break;

    default:
      printf("Unknown ethernet header type");
  }

  /* free(packet_cpy); */

}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method: hande_ip_packet(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/

struct sr_rt *find_rt(struct sr_instance *sr, uint32_t ip) 
{
  struct sr_rt *ret = NULL;
  struct sr_rt *curr = NULL;
  int longestPrefix = 0;

  /* go through the routing table */
  for (curr = sr->routing_table; curr != NULL; curr = curr->next)
  {
    /* if the prefix is longer and it matches */
    /* print_addr_ip_int(ip); */
    /* print_addr_ip_int(curr->dest.s_addr); */
    /* printf("network mask: \n"); */
    /* print_addr_ip_int(ntohl(curr->mask.s_addr)); */
    /* printf("network mask len: %d\n", network_mask_len(ntohl(curr->mask.s_addr))); */
    /* printf("\n"); */

    if (network_mask_len(ntohl(curr->mask.s_addr)) > longestPrefix &&
        (ip & curr->mask.s_addr) == (ntohl(curr->dest.s_addr) & curr->mask.s_addr))
    {
      ret = curr;
      longestPrefix = network_mask_len(curr->mask.s_addr);
    }
  }

  return ret;
}

/*
* Returns true if the ip packet destination matches 
* ANY of the IP's in our router- not necessarily the
* interface the packet was recieved in !
*/
bool ip_matches_router(struct sr_instance *sr,
                       const sr_ip_hdr_t *ip_pkt)
{
  struct sr_if *curr = NULL;

  for (curr = sr->if_list; curr != NULL; curr = curr->next)
    if (curr->ip == ip_pkt->ip_dst) /* both are network order */
      return true;

  return false;
}


void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet,
                      char *interface)
{
    
  uint8_t *ip_pkt = packet + sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) ip_pkt;
  int ip_pkt_len = ntohs(ip_hdr->ip_len);
  /* print_hdr_ip(ip_pkt); */
  /* printf("ip packet len: %d\n", ip_pkt_len); */
  /* printf("ip header len: %d\n", ntoip_hdr->ip_hl); */
  /* printf("icmp header len: %d\n", sizeof(sr_icmp_hdr_t)); */
  /* printf("icmp3 header len: %d\n", sizeof(sr_icmp_t3_hdr_t)); */

  if (!ip_cksum(ip_pkt)) {
    printf("IP checksum failed, dropping packet\n");  
  }

  /* if destined to this router */
  if ( ip_matches_router(sr, ip_hdr) ) {
    printf("Detected packet destined for this router:\n");

    if ( ip_hdr->ip_p == ip_protocol_icmp )
      process_icmp(sr, packet, ip_pkt_len - sizeof(sr_ip_hdr_t), interface);

    else {
      printf("Recieved non-ICMP IP packet destined for this router, sending port unreachable\n");
      send_icmp_t3(sr, packet, interface, 3);
    }

  }

  /* needs to be forwarded to another router */
  else {
    printf("Forwarding to (not fully implemented): \n");
    print_addr_ip_int(ntohl(ip_hdr->ip_dst));
    /* printf("\n"); */
    
    /* decrease TTL by 1 */
    if (--ip_hdr->ip_ttl <= 0) {
      /* TODO: send icmp time exceeded
       *
      */
      return;
    } 

    /* search for the IP in the router table with the longest prefix (mask) */
    struct sr_rt *rt_entry;
    /* TODO: is this network order? */
    if ((rt_entry = find_rt(sr, ip_hdr->ip_dst)) == NULL) {
      printf("Could not find IP in the RT, sending ICMP network unreachable\n");
      send_icmp_t3(sr, packet, interface, 0);
      return;
    }

    /* now that we have the next-hop IP, use ARP to look up the MAC */
    /* TODO: is the next hop ip network order? */
    struct sr_arpentry *arp_entry;
    if ((arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->dest.s_addr)) == NULL) {
      /* TODO: no ARP entry found, send ARP request and add to queue */
      printf("No ARP entry found, not yet implemented\n");
      return;
    } else {
      /* ARP found, forward the IP Packet */
      uint8_t *forward = (uint8_t *) malloc (sizeof(sr_ethernet_hdr_t) +
                                             ip_pkt_len);

      sr_ethernet_hdr_t *resp_eth_hdr = (sr_ethernet_hdr_t *)forward;
      resp_eth_hdr->ether_type = htons(ethertype_ip);
      /* iface address is already in network order */
      memcpy( resp_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN); 
      /* TODO: is the arp_entry address in network order? */
      memcpy( resp_eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

      sr_ip_hdr_t *resp_ip_hdr = (sr_ip_hdr_t *)(forward + sizeof(sr_ethernet_hdr_t));
      /* IP packet should be the exact same */
      memcpy( (uint8_t *)resp_ip_hdr, ip_pkt, ip_pkt_len );
      /* BUT, we do need to recalculate the check sum */
      resp_ip_hdr->ip_sum = 0;
      resp_ip_hdr->ip_sum = cksum( (uint8_t *)resp_ip_hdr, sizeof(sr_ip_hdr_t) );

      printf("Forwarding IP packet:\n");
      print_hdr_ip( (uint8_t *)resp_ip_hdr);
      sr_send_packet(sr, forward, sizeof(sr_ethernet_hdr_t) + ip_pkt_len, interface);

    }
  }
}

void process_icmp(struct sr_instance *sr,
                  uint8_t *packet,
                  int icmp_length,
                  char *interface)
{
  /* TODO: untested */
  uint8_t *icmp_pkt = packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)icmp_pkt;

  uint16_t hdr_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t calculated_cksum = cksum(icmp_pkt, icmp_length);

  if (hdr_cksum != calculated_cksum) {
    printf("ICMP Checksum failed\n");
  }

  /* reply with a icmp echo */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet; 
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  uint8_t *resp = (uint8_t *) malloc (sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len));
  sr_ethernet_hdr_t *resp_eth_hdr = (sr_ethernet_hdr_t *) resp; 
  sr_ip_hdr_t *resp_ip_hdr = (sr_ip_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *resp_icmp_hdr = (sr_icmp_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* eth header */
  memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
  memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
  resp_eth_hdr->ether_type = htons(ethertype_ip);

  /* ip header */
  resp_ip_hdr->ip_v = 4; /* IPv4 */
  resp_ip_hdr->ip_hl = 5; /* minimum header length */
  resp_ip_hdr->ip_tos = ip_hdr->ip_tos; 
  resp_ip_hdr->ip_off = htons(IP_DF);
  resp_ip_hdr->ip_len = htons((uint16_t) sizeof(sr_ip_hdr_t) + icmp_length); /* TODO: check this? */ 
  resp_ip_hdr->ip_id = htons(IP_ID++);
  resp_ip_hdr->ip_ttl = 64;
  resp_ip_hdr->ip_p = ip_protocol_icmp;
  resp_ip_hdr->ip_src = ip_hdr->ip_dst;
  resp_ip_hdr->ip_dst = ip_hdr->ip_src;

  /* icmp packet should be exactly the same */
  resp_icmp_hdr->icmp_type = 0;
  resp_icmp_hdr->icmp_code = 0;
  /* place the old payload in the new one */ 
  memcpy(((uint8_t *) resp_icmp_hdr) + sizeof(sr_icmp_hdr_t), 
         ((uint8_t *) icmp_hdr) + sizeof(sr_icmp_hdr_t),
         icmp_length - sizeof(sr_icmp_hdr_t));

  /* calculate checksums */
  resp_ip_hdr->ip_sum = 0;
  resp_ip_hdr->ip_sum = cksum(resp_ip_hdr, sizeof(sr_ip_hdr_t));
  resp_icmp_hdr->icmp_sum = 0;
  resp_icmp_hdr->icmp_sum = cksum(resp_icmp_hdr, icmp_length);

  /* TODO: icmp checksum? */
  sr_send_packet(sr, resp, sizeof(sr_ethernet_hdr_t) + ntohs(resp_ip_hdr->ip_len), interface);

  printf("Sent ICMP echo reply\n");

  free(resp);
}

void send_icmp_t3(struct sr_instance *sr,
                  uint8_t *packet,
                  char *interface,
                  int code)
{
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet; 
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  uint8_t *resp = (uint8_t *) malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  sr_ethernet_hdr_t *resp_eth_hdr = (sr_ethernet_hdr_t *) resp; 
  sr_ip_hdr_t *resp_ip_hdr = (sr_ip_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *resp_icmp_hdr = (sr_icmp_t3_hdr_t *) resp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

  /* eth header */
  memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
  memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
  resp_eth_hdr->ether_type = htons(ethertype_ip);

  /* icmp header */
  resp_icmp_hdr->icmp_type = htons(1);
  resp_icmp_hdr->icmp_code = htons(code);
  resp_icmp_hdr->unused = 0; /* these two fields aren't used */
  resp_icmp_hdr->next_mtu = 0; /* fill with 0's to standardize */

  /* the data field of the icmp contains the entire IP header that
   * caused the error message */
  memcpy( resp_icmp_hdr->data, (uint8_t *)ip_hdr, ICMP_DATA_SIZE );

  /* ip header */
  resp_ip_hdr->ip_v = htons(4); /* IPv4 */
  resp_ip_hdr->ip_hl = htons(5); /* minimum header length */
  resp_ip_hdr->ip_tos = 0; 
  resp_ip_hdr->ip_id = htons(IP_ID++);
  resp_ip_hdr->ip_off = htons(IP_DF);
  resp_ip_hdr->ip_ttl = htons(64);
  resp_ip_hdr->ip_p = htons(ip_protocol_icmp);
  resp_ip_hdr->ip_src = ip_hdr->ip_dst; /* already in network order */
  resp_ip_hdr->ip_dst = ip_hdr->ip_src; /* already in network order */
  resp_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  /* icmp cksum is it's entire header (including data field) */
  resp_icmp_hdr->icmp_sum = 0;
  resp_icmp_hdr->icmp_sum = cksum( (uint8_t *)resp_icmp_hdr, sizeof(sr_icmp_t3_hdr_t) );

  /* ip cksum is it's header */
  resp_ip_hdr->ip_sum = 0;
  resp_ip_hdr->ip_sum = cksum( (uint8_t *)resp_ip_hdr, sizeof(sr_ip_hdr_t) );

  sr_send_packet(sr, resp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);

  free(resp);

  return;
}

/*---------------------------------------------------------------------
 * Method: hande_arp_packet(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/

void handle_arp_packet(struct sr_instance *sr,
                       uint8_t *packet,
                       char *interface)
{
    sr_arp_hdr_t *hdr = (sr_arp_hdr_t *)packet;    

    if (ntohs(hdr->ar_op) == arp_op_request) {
        printf("Recieved ARP Request\n");
        handle_arp_request(sr, hdr, interface);
    } else if (ntohs(hdr->ar_op) == arp_op_reply) {
        printf("Recieved ARP Reply\n");
        handle_arp_reply(hdr);
    } else {
        printf("Unrecognized arp oper\n");
    }
}

/*---------------------------------------------------------------------
 * Method: hande_arp_request(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/

void handle_arp_request(struct sr_instance *sr,
                        sr_arp_hdr_t *hdr,
                        char *interface)
{
    struct sr_if* iface = sr_get_interface(sr, interface);

    /* compare target address to our address (both are in NETWORK order) */
    if ( iface->ip == hdr->ar_tip ) {
        /* printf("Address match\n"); */

        uint8_t *resp = (uint8_t *) malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) resp; 
        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t));

        /* length/format of addresses is the same */
        arp_hdr->ar_hrd = hdr->ar_hrd;
        arp_hdr->ar_pro = hdr->ar_pro;
        arp_hdr->ar_hln = hdr->ar_hln;
        arp_hdr->ar_pln = hdr->ar_pln;
        /* this should be a reply, not request */
        arp_hdr->ar_op = htons(arp_op_reply);
        /* reverse the direction towards sender */
        arp_hdr->ar_sip = hdr->ar_tip; 
        arp_hdr->ar_tip = hdr->ar_sip; 
        memcpy( arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN );
        memcpy( arp_hdr->ar_tha, hdr->ar_sha, ETHER_ADDR_LEN );

        /* fill out the ethernet header as well */
        memcpy( eth_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN );
        memcpy( eth_hdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN );
        eth_hdr->ether_type = htons(ethertype_arp);

        /* send the packet */
        sr_send_packet(sr, resp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);

        printf("Sent ARP Reply\n");

        /* free(resp); */

    } else {
        printf("No address match\n");
        print_addr_ip_int(ntohl(hdr->ar_tip));
    }
}

/*---------------------------------------------------------------------
 * Method: hande_arp_reply(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/

void handle_arp_reply(sr_arp_hdr_t *hdr)
{
  /* TODO */
}
