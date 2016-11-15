/*
 ============================================================================
 Name        : ICMP_Error.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>



int main(void) {

}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)

        uint8_t* packet,
        unsigned int len,
        char* interface,
        uint8_t type)

{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
    	 uint8_t* icmpPacket = malloc(70 * sizeof(uint8_t));

    	 if (icmpPacket == NULL)
    	    {
    	        fprintf(stderr, "Error: malloc could not find memory for packet storage\n");
    	        return;
    	    }

    	 memset(icmpPacket, 0, 70 * sizeof(uint8_t));

    	    /* organize our src packet */
    	    struct sr_ethernet_hdr* srcethernetHdr = (struct sr_ethernet_hdr*)packet;
    	    struct ip* srcipHdr = (struct ip*)(packet+14);

    	    /* organize pointers for our new packet */
    	    struct sr_ethernet_hdr* newEthHdr = (struct sr_ethernet_hdr*)icmpPacket;
    	    struct ip* newipHdr = (struct ip*)(icmpPacket+14);
    	    struct icmp_hdr* newicmpHdr = (struct icmp_hdr*)(icmpPacket+34);
    	    uint8_t* newicmpData = (uint8_t*)(icmpPacket+42);

    	    /* copy src ip header + tcp/udp ports to icmp data */
    	    memcpy(newicmpData, srcipHdr, 28);

    	    /* create icmp, ip and ethernet headers on our new packet */
    	    makeicmp(newicmpHdr, ICMP_DST_UNREACHABLE, type, 36);
    	    makeip(newipHdr, 70-14, IP_DF, 64, IPPROTO_ICMP,
    	            sr_get_interface(sr, interface)->ip, srcipHdr->ip_src.s_addr);
    	    makeethernet(newEthHdr, ETHERTYPE_IP,
    	            sr_get_interface(sr, interface)->addr, srcethernetHdr->ether_shost);

    	    /* send away */
    	    sr_send_packet(sr, icmpPacket, 70, interface);

    	    // log on send
    	    if (type == ICMP_PORT_UNREACHABLE)
    	        printf("<-- ICMP Destination Port Unreachable sent to %s\n", inet_ntoa(newipHdr->ip_dst));
    	    if (type == ICMP_HOST_UNREACHABLE)
    	        printf("<-- ICMP Destination Host Unreachable sent to %s\n", inet_ntoa(newipHdr->ip_dst));

    	    free(icmpPacket);

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

