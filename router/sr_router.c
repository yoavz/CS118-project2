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
void handle_arp_reply(struct sr_instance *sr,
                        sr_arp_hdr_t *hdr,
                        char *interface);
void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet,
                      char *interface);
void process_icmp(struct sr_instance *sr,
                  uint8_t *packet,
                  int icmp_length,
                  char *interface);
void send_icmp_time_exceeded(struct sr_instance *sr,
                  uint8_t *packet,
                  char *interface);

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

    if (network_mask_len(ntohl(curr->mask.s_addr)) > longestPrefix &&
        ((ntohl(ip) & ntohl(curr->mask.s_addr)) == (ntohl(curr->dest.s_addr) & ntohl(curr->mask.s_addr))))
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

  if (!ip_cksum(ip_pkt)) {
    printf("IP checksum failed, dropping packet\n");  
  }

  /* if destined to this router */
  if ( ip_matches_router(sr, ip_hdr) ) {
    printf("Detected packet destined for this router:\n");
    print_hdr_ip(ip_pkt);

    if ( ip_hdr->ip_p == ip_protocol_icmp ) {
      process_icmp(sr, packet, ip_pkt_len - sizeof(sr_ip_hdr_t), interface);
      return;
    }

    else {
      printf("packet is not ICMP type, sending port unreachable\n");
      send_icmp_t3(sr, packet, interface, 3);
      return;
    }

  }

  /* needs to be forwarded to another router */
  else {
    printf("Forwarding to:\n");
    print_addr_ip_int(ntohl(ip_hdr->ip_dst));
    /* printf("\n"); */
    
    /* decrease TTL by 1 */
    if (--ip_hdr->ip_ttl <= 0) {
      printf("TTL expired, sending ICMP Time Exceeded\n");
      send_icmp_time_exceeded(sr, packet, interface);
      return;
    } 

    /* recalculate checksum since wwe updated the header */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* search for the IP in the router table with the longest prefix (mask) */
    struct sr_rt *rt_entry;
    if ((rt_entry = find_rt(sr, ip_hdr->ip_dst)) == NULL) {
      printf("Could not find IP in the RT, sending ICMP network unreachable\n");
      send_icmp_t3(sr, packet, interface, 0);
      return;
    }

    uint32_t next_hop_ip = ntohl(rt_entry->gw.s_addr);

    /* now that we have the next-hop IP, update the ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rt_entry->interface)->addr, ETHER_ADDR_LEN);

    /* use ARP to look up the dest MAC */
    struct sr_arpentry *arp_entry;
    if ((arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip)) == NULL) {
      /* no ARP entry found, add the packet to the queue */
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, 
                                                       next_hop_ip,
                                                       packet,
                                                       sizeof(sr_ethernet_hdr_t) + ip_pkt_len,
                                                       rt_entry->interface);
      printf("No ARP entry found, added to queue\n");

      /* If the request for this IP hasn't been sent already, send it immediately */
      if (arp_req->times_sent <= 0) {
        printf("First entry for this arp req, sent ARP request\n");
        send_arp_request(sr, next_hop_ip, rt_entry->interface);
        arp_req->sent = time(NULL);
        arp_req->times_sent++;
      }

      return;

    } else {
      /* ARP found, forward the IP Packet */
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t *) packet, sizeof(sr_ethernet_hdr_t) + ip_pkt_len, rt_entry->interface);
      printf("Found ARP entry, forwarded immediately\n");
      /* free(arp_entry); */
    }
  }
}

void process_icmp(struct sr_instance *sr,
                  uint8_t *packet,
                  int icmp_length,
                  char *interface)
{
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
  resp_ip_hdr->ip_len = htons((uint16_t) sizeof(sr_ip_hdr_t) + icmp_length); 
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

  sr_send_packet(sr, resp, sizeof(sr_ethernet_hdr_t) + ntohs(resp_ip_hdr->ip_len), interface);

  printf("Sent ICMP echo reply\n");

  /* free(resp); */
}

/*---------------------------------------------------------------------
 * Method: send_icmp_t3 
 * Scope: Global 
 *
 * Sends an icmp message type 3 with the specified code in response to the 
 * provided packet
 *
 *---------------------------------------------------------------------*/
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
  sr_icmp_t3_hdr_t *resp_icmp_hdr = (sr_icmp_t3_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* eth header */
  memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
  memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
  resp_eth_hdr->ether_type = htons(ethertype_ip);

  /* icmp header */
  resp_icmp_hdr->icmp_type = 1;
  resp_icmp_hdr->icmp_code = code;
  resp_icmp_hdr->unused = 0; /* these two fields aren't used */
  resp_icmp_hdr->next_mtu = 0; /* fill with 0's to standardize */

  /* the data field of the icmp contains the entire IP header and
   * first 8 bytes of the payload that caused the error message */
  memcpy( resp_icmp_hdr->data, ((uint8_t *) ip_hdr), ICMP_DATA_SIZE );

  /* ip header */
  resp_ip_hdr->ip_v = 4; /* IPv4 */
  resp_ip_hdr->ip_hl = 5; /* minimum header length */
  resp_ip_hdr->ip_tos = ip_hdr->ip_tos; 
  resp_ip_hdr->ip_off = htons(IP_DF);
  resp_ip_hdr->ip_len = htons((uint16_t) sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  resp_ip_hdr->ip_id = htons(IP_ID++);
  resp_ip_hdr->ip_ttl = 64;
  resp_ip_hdr->ip_p = ip_protocol_icmp;
  resp_ip_hdr->ip_src = ip_hdr->ip_dst;
  resp_ip_hdr->ip_dst = ip_hdr->ip_src;

  /* icmp cksum is it's entire header (including data field) */
  resp_icmp_hdr->icmp_sum = 0;
  resp_icmp_hdr->icmp_sum = cksum( (uint8_t *)resp_icmp_hdr, sizeof(sr_icmp_t3_hdr_t) );

  /* ip cksum is it's header */
  resp_ip_hdr->ip_sum = 0;
  resp_ip_hdr->ip_sum = cksum( (uint8_t *)resp_ip_hdr, sizeof(sr_ip_hdr_t) );

  /* print_hdr_eth(resp_eth_hdr); */
  /* print_hdr_ip(resp_ip_hdr); */
  /* print_hdr_icmp(resp_icmp_hdr); */

  sr_send_packet(sr, resp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);

  /* free(resp); */

  return;
}

/*---------------------------------------------------------------------
 * Method: send_icmp_time_exceeded
 * Scope: Local 
 *
 * Sends an icmp message type 3 with the specified code in response to the 
 * provided packet
 *
 *---------------------------------------------------------------------*/

void send_icmp_time_exceeded(struct sr_instance *sr,
                  uint8_t *packet,
                  char *interface)
{
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet; 
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  uint8_t *resp = (uint8_t *) malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  sr_ethernet_hdr_t *resp_eth_hdr = (sr_ethernet_hdr_t *) resp; 
  sr_ip_hdr_t *resp_ip_hdr = (sr_ip_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *resp_icmp_hdr = (sr_icmp_t3_hdr_t *) (resp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* eth header */
  memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
  memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
  resp_eth_hdr->ether_type = htons(ethertype_ip);

  /* icmp header */
  resp_icmp_hdr->icmp_type = 11;
  resp_icmp_hdr->icmp_code = 0;
  resp_icmp_hdr->unused = 0; /* these two fields aren't used */
  resp_icmp_hdr->next_mtu = 0; /* fill with 0's to standardize */

  /* the data field of the icmp contains the entire IP header and
   * first 8 bytes of the payload that caused the error message */
  memcpy( resp_icmp_hdr->data, (uint8_t *)ip_hdr, ICMP_DATA_SIZE );

  /* ip header */
  resp_ip_hdr->ip_v = 4; /* IPv4 */
  resp_ip_hdr->ip_hl = 5; /* minimum header length */
  resp_ip_hdr->ip_tos = ip_hdr->ip_tos; 
  resp_ip_hdr->ip_off = htons(IP_DF);
  resp_ip_hdr->ip_len = htons((uint16_t) sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  resp_ip_hdr->ip_id = htons(IP_ID++);
  resp_ip_hdr->ip_ttl = 64;
  resp_ip_hdr->ip_p = ip_protocol_icmp;
  resp_ip_hdr->ip_src = ip_hdr->ip_dst;
  resp_ip_hdr->ip_dst = ip_hdr->ip_src;

  /* icmp cksum is it's entire header (including data field) */
  resp_icmp_hdr->icmp_sum = 0;
  resp_icmp_hdr->icmp_sum = cksum( (uint8_t *)resp_icmp_hdr, sizeof(sr_icmp_t3_hdr_t) );

  /* ip cksum is it's header */
  resp_ip_hdr->ip_sum = 0;
  resp_ip_hdr->ip_sum = cksum( (uint8_t *)resp_ip_hdr, sizeof(sr_ip_hdr_t) );

  sr_send_packet(sr, resp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);

  /* free(resp); */

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
      handle_arp_reply(sr, hdr, interface);
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
        printf("ARP Request dropped due to address mismatch\n");
    }
}

/*---------------------------------------------------------------------
 * Method: hande_arp_reply(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/

void handle_arp_reply(struct sr_instance *sr,
                      sr_arp_hdr_t *hdr,
                      char *interface)
{
  struct sr_if* iface = sr_get_interface(sr, interface);

  if ( iface->ip == hdr->ar_tip ) {

    /* enter the new mac/ip mapping and retrieve the request */
    struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, hdr->ar_sha, ntohl(hdr->ar_sip));

    /* iterate through all of the waiting packets and send them */
    struct sr_packet *curr;
    int counter = 0;

    for (curr = arp_req->packets; curr != NULL; curr = curr->next) {
      /* update the dest mac address now that we know it */
      sr_ethernet_hdr_t *curr_eth_hdr = (sr_ethernet_hdr_t *) curr->buf;
      memcpy(curr_eth_hdr->ether_dhost, hdr->ar_sha, ETHER_ADDR_LEN);

      /* send the packet */
      sr_send_packet(sr, curr->buf, curr->len, curr->iface);
      counter++;

      /* TODO: free */
    }

    sr_arpreq_destroy(&sr->cache, arp_req);

    printf("Sent %d packet(s) waiting on that ARP Request\n", counter);

  } else {
    printf("ARP Reply dropped due to address mismatch\n");
  }
}

/*---------------------------------------------------------------------
 * Method: send_arp_request
 * Scope: Global 
 *
 *---------------------------------------------------------------------*/

void send_arp_request(struct sr_instance *sr, 
                      uint32_t target_ip, /* for consistency, target ip should be in host order */
                      char *interface)
{
    uint8_t *req = (uint8_t *) malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) req; 
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (req + sizeof(sr_ethernet_hdr_t));

    struct sr_if *iface = sr_get_interface(sr, interface);

    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IP_ADDR_LEN;
    arp_hdr->ar_op = htons(arp_op_request);

    arp_hdr->ar_sip = iface->ip;
    arp_hdr->ar_tip = htonl(target_ip);
    memcpy( arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN );

    /* we don't know the target mac address, so set it to 0 */
    memset( arp_hdr->ar_tha, 0, ETHER_ADDR_LEN );

    /* eth header */
    eth_hdr->ether_type = htons(ethertype_arp);
    memcpy( eth_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN );
    /* destination is the broadcast ethernet address */
    uint8_t broadcast[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    memcpy( eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN ); 

    /* send the packet */
    sr_send_packet(sr, req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);

    /* free(req); */
}

