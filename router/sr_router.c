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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

void handle_arp_packet(struct sr_if* iface, uint8_t* packet, int len);
void handle_arp_request(struct sr_if *iface, sr_arp_hdr_t *hdr);
void handle_arp_reply(sr_arp_hdr_t *hdr);

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

  printf("*** -> Received packet of length %d \n",len);
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) packet;
  struct sr_if* iface = sr_get_interface(sr, interface);
  print_addr_ip_int(ntohl(iface->ip));

  /* TODO: check dest MAC address lines up? */
  
  /* arp handling */
  if ( ntohs(ethernet_hdr->ether_type) == ethertype_arp ) {
      printf("Detected ARP packet\n");
      uint8_t *arp_packet = packet + sizeof(sr_ethernet_hdr_t);
      handle_arp_packet(iface, arp_packet, len - sizeof(sr_ethernet_hdr_t));
  } 

  /* ip handling */
  else if ( ntohs(ethernet_hdr->ether_type) == ethertype_ip ) {
      printf("Detected IP packet\n");
  }

  else {
      printf("Unknown ethernet header type");
      return;
  }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: hande_ip_packet(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/

void handle_ip_packet(uint8_t* packet, int len)
{
}

/*---------------------------------------------------------------------
 * Method: hande_arp_packet(uint8_t* p,char* interface)
 * Scope: Local 
 *
 *---------------------------------------------------------------------*/


void handle_arp_packet(struct sr_if *iface, uint8_t *packet, int len)
{
    print_hdr_arp(packet);
    sr_arp_hdr_t *hdr = (sr_arp_hdr_t *)packet;    

    if (ntohs(hdr->ar_op) == arp_op_request) {
        printf("ARP Request\n");
        handle_arp_request(iface, hdr);
    } else if (ntohs(hdr->ar_op) == arp_op_reply) {
        printf("ARP Reply\n");
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

void handle_arp_request(struct sr_if *iface, sr_arp_hdr_t *hdr)
{
    /* compare target address to our address (both are in NETWORK order) */
    if ( iface->ip == hdr->ar_tip ) {
        printf("Address match\n");

        /* create a copy of the arp header to send back */ 
        sr_arp_hdr_t *resp = (sr_arp_hdr_t *) malloc (sizeof(sr_arp_hdr_t));

    /* unsigned short  ar_hrd;             #<{(| format of hardware address   |)}># */
    /* unsigned short  ar_pro;             #<{(| format of protocol address   |)}># */
    /* unsigned char   ar_hln;             #<{(| length of hardware address   |)}># */
    /* unsigned char   ar_pln;             #<{(| length of protocol address   |)}># */
    /* unsigned short  ar_op;              #<{(| ARP opcode (command)         |)}># */
    /* unsigned char   ar_sha[ETHER_ADDR_LEN];   #<{(| sender hardware address      |)}># */
    /* uint32_t        ar_sip;             #<{(| sender IP address            |)}># */
    /* unsigned char   ar_tha[ETHER_ADDR_LEN];   #<{(| target hardware address      |)}># */
    /* uint32_t        ar_tip;             #<{(| target IP address            |)}># */

        /* length/format of addresses is the same */
        resp->ar_hrd = hdr->ar_hrd;
        resp->ar_pro = hdr->ar_pro;
        resp->ar_hln = hdr->ar_hln;
        resp->ar_pln = hdr->ar_pln;

        /* this should be a reply, not request */
        resp->ar_op = arp_op_reply;

        /* reverse the direction */
        resp->ar_sha = hdr->tha; 
        resp->ar_sip = iface->ip; 
        resp->ar_tha = hdr->sha; 
        resp->ar_tip = hdr->sip; 

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
}
