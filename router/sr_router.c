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
#include <stdlib.h>
#include <string.h>


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

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */




      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */



      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*
	* Method: rtLookUp
	* This method looks up the specified packet's destination in the sr instance's routing table
*/
rtP rtLookUp(rtP rtHead, sr_ip_hder_t* ipHeader)
{
	rtP rtNode = rtHead;
	rtP rtLongest = rtNode;
	char longestLen = 0;
	char prefixBit, dstBit, maskBit, currentLen;
	while(rtNode)
	{
		currentLen = 0;
		for(bit = 31; bit >= 0; bit--)
		{
			dstBit = ((ipHeader->ip_dst & (1 << bit)) >> bit);
			prefixBit = ((rtNode->dest & (1<< bit)) >> bit);
			maskBit = ((rtNode->mask & (1 << bit)) >> bit);
			if((maskBit == 1) && (dstBit == prefixBit))
			{
				currentLen++;
				if(currentLen > longestLen)
				{
					longestLen = currentLen;
					rtLongest = rtNode;
				}
			}
			else
			{
				break;
			}
		}
		rtNode = rtNode->next;
	}
	if(longestLen) //not zero
	{
		return rtLongest;
	}
	else
	{
		return NULL;
	}
}

/*
 * Method: icmpSendNetUnR
 * This method takes the provided packet and returns first 8 bytes it to its sender in an ICMP Net Unreachable packet
*/
void icmpSendNetUnR(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	unsigned char* icmpPacket = malloc(70);
	memset(icmpPacket,0,70); //fill with zeros
	//source packet
	sr_ethernet_hdr_t* sEtherHdr = (sr_ethernet_hdr_t *) (packet);
	sr_ip_hdr_t* sIpHeader = (sr_ip_hdr_t *) (packet + 14);
	
	//new packet
	sr_ethernet_hdr_t* nEtherHdr = (sr_ethernet_hdr_t *) (icmpPacket);
	sr_ip_hdr_t* nIpHdr = (sr_ip_hdr_t*) (icmpPacket+14); //ethernet hdr is 14 bytes long
	sr_icmp_t3_hdr_t* nIcmpHdr = (sr_icmp_t3_hdr_t *) (icmpPacket+34); //ip hdr is 20 bytes long + ehternet hdr (14) = 34 
	unsigned char nIcmpData = (unsigned char*)(icmpPacket+42) //icmp hdr is 8 bytes long & ip(20) & ethernet(14) headers = 42
	memcpy(nIcmpData, sIpHeader, 28) //need first 28 bytes of message data for ICMP data response
	sr_if* receivingIf = sr_get_interface(sr, interface);
	//make icmp header
	nIcmpHdr->icmp_type = 3; //unreachable
	nIcmpHdr->icmp_code = 0; //network code
	nIcmpHdr->icmp_checksum = 0x0000;
	nIcmpHdr->icmp_checksum = cksum((void *)(nIcmpHdr),36); //36 is length from header start (34) to end of data (70)
	//make ip header
	nIpHdr->ip_tos = 0;
	nIpHdr->ip_len = htons(70-14); //(length of packet - ethernet header)
	nIpHdr->ip_id = 0;
	nIpHdr->ip_off = htons(0x4000); //don't fragment flag set
	nIpHdr->ip_ttl = 64;
	nIpHdr->ip_p = 1; //icmp protocol code is 1
	nIpHdr->ip_src = receivingIf->ip;
	nIpHdr->ip_dst = sIpHeader->ip_src;
	nIpHdr->ip_sum = 0x0000;
	nIpHdr->ip_sum = cksum((void*)(nIpHdr), 20); //ip checksum is only over header
	//make ethernet header
	char MACbyte;
	for(MACbyte = 0; MACbyte < ETHER_ADDR_LEN; MACbyte++)
	{	
		etherHdr->ether_dhost[MACbyte] = etherHdr->ether_shost[MACbyte]; //put original sender's MAC into the destination field
		etherHdr->ether_shost[MACbyte] = receivingIf->addr[MACbyte]; //put the arriving interface's MAC in the source field
	}
	sr_send_packet(sr, icmpPacket, 70, interface);
	free(icmpPacket);
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
typedef struct sr_rt* rtP;
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

  /*************************************************************************/
  /* TODO: Handle packets                           
  /*************************************************************************/
  
  
// BEGIN TASK 2 : Assumes IP packet len has been checked and has good checksum, also ttls of 1 should have been returned as 'time exceeded'
	sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t *)(packet+14);
	ipHdr->ip_ttl--; //decrement ttl
	ipHdr->ip_sum = 0; //zero checksum to recalculate
	ipHdr->ip_sum = cksum((void*)(ipHdr),20); //recalculate checksum
	rtP rtMatch = rtLookUp(sr->routing_table, ipHdr); //14 is size of ethernet header, offsetting past this to ipHdr
	if(!rtMatch) //if null then no match made
	{
		icmpSendNetUnR(sr, packet, len, interface);
		return; //packet has been handled
	}
	else //routing table match found, do something with this interface (interface) and next hop ip (gw)
	{
		rtMatch->gw.s_addr; //gets an in_addr element of gw and gives the ip addr element of it(next hop ip)
		sr_get_interface(sr, rtMatch->interface); //gives the interface record from this routers interface list that rtMatch uses
//END TASK 2 : Interface and IP address provided here for ARP calls
	}
}/* end sr_ForwardPacket */
