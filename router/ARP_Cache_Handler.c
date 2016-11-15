/*
 ============================================================================
 Name        : ARP_Cache_Handler.c
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

void checkCachedPackets(struct sr_instance* sr, int cachedArp)
{
    int i, arpMatch;
    for (i = 0; i < PACKET_CACHE_SIZE; i++) {
        if (packetCache[i].len > 0) {
            // if we have a packet waiting
            if (packetCache[i].arps <= 5) {
                // and we have not sent 5 arps for this packet yet
                if ((arpMatch = arpSearchCache(packetCache[i].tip)) > -1) {
                    // and we have an arp match for our packet's next hop
                    forwardPacket(sr, (uint8_t*)&packetCache[i].packet, packetCache[i].len,
                            // send it along
                            packetCache[i].nexthop->interface, arpReturnEntryMac(arpMatch));
                    packetCache[i].len = 0;
                } else {
                    /* wait three seconds between each arp request */
                    if ((int)(difftime(time(NULL), packetCache[i].timeCached))%3 < 1) {
                        arpSendRequest(sr, sr_get_interface(sr, packetCache[i].nexthop->interface),
                                packetCache[i].nexthop->gw.s_addr);
                        packetCache[i].arps++;
                    }
                }
            } else {
                /* then */
                icmpSendUnreachable(sr, (uint8_t*)&packetCache[i].packet, packetCache[i].len,
                        packetCache[i].nexthop->interface, ICMP_HOST_UNREACHABLE);
                packetCache[i].len = 0;
            }
        }
    }
}

/*-----------------------------------------------------------------------------
 * Method void initPacketCache()
 *
 * zero's the len field for all entries of our packet cache. if len is ever
 * greater than zero that means there is a packet waiting to be forwarded
 *---------------------------------------------------------------------------*/
void initPacketCache()
{
    int i;
    for (i = 0; i < PACKET_CACHE_SIZE; i++)
        packetCache[i].len = 0;
}