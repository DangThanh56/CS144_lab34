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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define DEFAULT_TTL 64
#define IP_ADDR_LEN 4
#define ETHER_ADDR_LEN 6
#define MIN_IP_HEADER_LENGTH 5
#define IP_VERSION 4

/*#define GET_ETHERNET_DEST_ADDR(packet)  (((sr_ethernet_hdr_t*)packet)->ether_dhost)*/

static uint16_t identify_num_iphdr = 0;

static const uint8_t broadcast_ehdr[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define GET_ETHERNET_DEST_ADDR(pktPtr)    (((sr_ethernet_hdr_t*)pktPtr)->ether_dhost)


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
static void handle_arp_pkt_recv(struct sr_instance* sr, sr_arp_hdr_t* packet,
                              unsigned int len, struct sr_if* interface);

static void handle_ip_pkt_recv(struct sr_instance* sr, sr_ip_hdr_t* packet,
                           unsigned int length,  struct sr_if* interface);

bool IP_for_router(struct sr_instance* sr, const sr_ip_hdr_t* const packet);

bool IcmpPerformIntegrityCheck(sr_icmp_hdr_t * const icmpPacket, unsigned int length);

void IpHandleReceivedPacketToUs(struct sr_instance* sr, sr_ip_hdr_t* packet,
                     unsigned int length, sr_if_t const * const interface);

static void networkHandleIcmpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
                        unsigned int length, const struct sr_if* const interface);

static void networkSendIcmpEchoReply(struct sr_instance* sr, sr_ip_hdr_t* echoRequestPacket,
                           unsigned int length);

sr_rt_t* IpGetPacketRoute(struct sr_instance* sr, in_addr_t destIp);

static int networkGetMaskLength(uint32_t mask);

static void linkArpAndSendPacket(sr_instance_t *sr, sr_ethernet_hdr_t* packet, 
   unsigned int length, sr_rt_t*  route);

void LinkSendArpRequest(struct sr_instance* sr, struct sr_arpreq* request);

void IpSendTypeThreeIcmpPacket(struct sr_instance* sr, sr_icmp_code_t icmpCode,
   sr_ip_hdr_t* originalPacketPtr);

static bool networkIpSourceIsUs(struct sr_instance* sr, const sr_ip_hdr_t* const packet);

void IpForwardIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const receivedInterface);

static void networkSendIcmpTtlExpired(struct sr_instance* sr, sr_ip_hdr_t* originalPacket,
      unsigned int length, sr_if_t const * const receivedInterface);

uint16_t getIpHeaderLength(sr_ip_hdr_t const * const pktPtr);

sr_icmp_hdr_t * getIcmpHeaderFromIpHeader(sr_ip_hdr_t * packetPtr);




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

  /* fill in code here */
  /*print_hdrs(packet, len);*/
  if(len < sizeof(sr_ethernet_hdr_t))
  {
    fprintf(stderr, "***Receive invalid raw Ethernet\n");
    return;
  }
  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
  struct sr_if* recv_iface = NULL;

  recv_iface = sr_get_interface(sr, interface);

  sr_print_if(recv_iface);
  /*if((memcmp(ehdr->ether_dhost, recv_iface->addr, ETHER_ADDR_LEN) != 0) 
  || (memcmp(ehdr->ether_dhost, broadcast_ehdr, ETHER_ADDR_LEN) != 0))
  {
    fprintf(stderr, "***Invalid Ethernet\n");
    return;
  }*/
  if ((recv_iface == NULL)
  || ((memcmp(GET_ETHERNET_DEST_ADDR(packet), recv_iface->addr, ETHER_ADDR_LEN) != 0)
     && (memcmp(GET_ETHERNET_DEST_ADDR(packet), broadcast_ehdr, ETHER_ADDR_LEN) != 0)))
   {
   fprintf(stderr, "***Invalid receive Ethernet\n");
   return;
   }

  switch (ethertype(packet))
  {
  case ethertype_arp:
    /* code */
    handle_arp_pkt_recv(sr, (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t), recv_iface);
    break;
  case ethertype_ip:
    handle_ip_pkt_recv(sr, (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t), recv_iface);
    break;
  default:
    fprintf(stderr, "***Invalid type of Ethernet\n");
    return;
  }

}/* end sr_ForwardPacket */

/*Handle arp packet receive*/
static void handle_arp_pkt_recv(struct sr_instance* sr, sr_arp_hdr_t* packet,
unsigned int len, struct sr_if* interface)
{
  if(len < sizeof(sr_arp_hdr_t))
  {
    fprintf(stderr, "Invalid ARP packet\n");
    return;
  }

  if((ntohs(packet->ar_pro) != ethertype_ip) || (ntohs(packet->ar_hrd) != arp_hrd_ethernet)
  || (packet->ar_pln != IP_ADDR_LEN) || (packet->ar_hln != ETHER_ADDR_LEN))
  {
    fprintf(stderr, "Invalid ARP packet\n");
    return;
  }

  switch (ntohs(packet->ar_op))
  {
    case arp_op_request:
     {
        if (packet->ar_tip == interface->ip)
        {
           /*Send ARP reply*/
           uint8_t* replyPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
           sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)replyPacket;
           sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(replyPacket + sizeof(sr_ethernet_hdr_t));
                      
           /* Ethernet Header */
           memcpy(ethernetHdr->ether_dhost, packet->ar_sha, ETHER_ADDR_LEN);
           memcpy(ethernetHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
           ethernetHdr->ether_type = htons(ethertype_arp);
           
           /* ARP Header */
           arpHdr->ar_hrd = htons(arp_hrd_ethernet);
           arpHdr->ar_pro = htons(ethertype_ip);
           arpHdr->ar_hln = ETHER_ADDR_LEN;
           arpHdr->ar_pln = IP_ADDR_LEN;
           arpHdr->ar_op = htons(arp_op_reply);
           memcpy(arpHdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
           arpHdr->ar_sip = interface->ip;
           memcpy(arpHdr->ar_tha, packet->ar_sha, ETHER_ADDR_LEN);
           arpHdr->ar_tip = packet->ar_sip;
           
           sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
              interface->name);
           
           free(replyPacket);
        }
        break;
     }
     
     case arp_op_reply:
     {
        if (packet->ar_tip == interface->ip)
        {
           struct sr_arpreq* requestPointer = sr_arpcache_insert(
              &sr->cache, packet->ar_sha, ntohl(packet->ar_sip));
           
           if (requestPointer != NULL)
           {
              /*Receive ARP reply, send all packets*/              
              while (requestPointer->packets != NULL)
              {
                 struct sr_packet* curr = requestPointer->packets;
                 
                 memcpy(((sr_ethernet_hdr_t*) curr->buf)->ether_dhost,
                    packet->ar_sha, ETHER_ADDR_LEN);
                 
                 sr_send_packet(sr, curr->buf, curr->len, curr->iface);
                 
                 /* Send list of packets. */
                 requestPointer->packets = requestPointer->packets->next;
                 
                 free(curr->buf);
                 free(curr->iface);
                 free(curr);
              }
              sr_arpreq_destroy(&sr->cache, requestPointer);
           }
           else
           {
            fprintf(stderr, "***No packet found with reply\n");
          }
        }
        break;
     }
     
     default:
     {
      fprintf(stderr, "Invalid ARP type\n");
      break;
     }
  }  
}

static void handle_ip_pkt_recv(struct sr_instance* sr, sr_ip_hdr_t* packet,
  unsigned int length,  struct sr_if* interface)
{
  if (length < sizeof(sr_ip_hdr_t))
  {
     fprintf(stderr, "***Invalid IP packet\n");
     return;
  }
  /*checksum packet, assume receive ip header length is 20*/
  if (packet->ip_hl >= MIN_IP_HEADER_LENGTH)
  {
     uint16_t headerChecksum = packet->ip_sum;
     uint16_t calculatedChecksum = 0;
     packet->ip_sum = 0;
     
     calculatedChecksum = cksum(packet, getIpHeaderLength(packet));
     
     if (headerChecksum != calculatedChecksum)
     {
        fprintf(stderr, "*** Fail checksum, drop packet\n");
        return;
     }
     else
     {
        packet->ip_sum = headerChecksum;
     }
  }
  else
  {
     fprintf(stderr, "***Receive invalid length of IP packet\n");
     return;
  }
  
  if (packet->ip_v != IP_VERSION)
  {
     fprintf(stderr, "*** Not IPv4 packet\n");
     return;
  }

  /*Verify and handle packet*/
  if (IP_for_router(sr, packet))
  {
    IpHandleReceivedPacketToUs(sr, packet, length, interface);
  }
  else
  {
    IpForwardIpPacket(sr, packet, length, interface);
  }
}

/*Check IP for router*/
bool IP_for_router(struct sr_instance* sr, const sr_ip_hdr_t* const packet)
{
   struct sr_if* interfaceIterator;
   
   for (interfaceIterator = sr->if_list; interfaceIterator != NULL; interfaceIterator =
      interfaceIterator->next)
   {
      if (packet->ip_dst == interfaceIterator->ip)
      {
         return true;
      }
   }
   return false;
}

/*Check integrity ICMP packet*/
bool IcmpPerformIntegrityCheck(sr_icmp_hdr_t * const icmpPacket, unsigned int length)
{
   uint16_t headerChecksum = icmpPacket->icmp_sum;
   uint16_t calculatedChecksum = 0;
   icmpPacket->icmp_sum = 0;
   
   calculatedChecksum = cksum(icmpPacket, length);
   icmpPacket->icmp_sum = headerChecksum;
   
   if (headerChecksum != calculatedChecksum)
   {
      return false;
   }
   return true;
}

void IpHandleReceivedPacketToUs(struct sr_instance* sr, sr_ip_hdr_t* packet,
  unsigned int length, sr_if_t const * const interface)
{
  /*Receive ICMP packet*/
  if (packet->ip_p == (uint8_t) ip_protocol_icmp)
  {
     networkHandleIcmpPacket(sr, packet, length, interface);
  }
  else
  {
    /*Receive TCP/UCP packet*/
     IpSendTypeThreeIcmpPacket(sr, icmp_code_destination_port_unreachable, packet);
  }
}

/*Handle receive ICMP packet*/
static void networkHandleIcmpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
  unsigned int length, const struct sr_if* const interface)
{
  sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (((uint8_t*) packet) + getIpHeaderLength(packet));
  int icmpLength = length - getIpHeaderLength(packet);
  
  if (!IcmpPerformIntegrityCheck(icmpHeader, icmpLength))
  {
    fprintf(stderr, "***Invalid ICMP packet\n");
     return;
  }
  
  if (icmpHeader->icmp_type == icmp_type_echo_request)
  {
     /* Send an echo Reply */
     networkSendIcmpEchoReply(sr, packet, length);
  }
  else
  {
    fprintf(stderr, "***Receive invalid ICMP packet\n");
  }
}

/*Send ICMP Echo reply*/
static void networkSendIcmpEchoReply(struct sr_instance* sr, sr_ip_hdr_t* echoRequestPacket,
  unsigned int length)
{
  int icmpLength = length - getIpHeaderLength(echoRequestPacket);
  uint8_t* replyPacket = malloc(icmpLength + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* replyIcmpHeader =
     (sr_icmp_hdr_t*) ((uint8_t*) replyIpHeader + sizeof(sr_ip_hdr_t));
  assert(replyPacket);
  
  /*Fill IP header*/
  replyIpHeader->ip_v = IP_VERSION;
  replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
  replyIpHeader->ip_tos = 0;
  replyIpHeader->ip_len = htons((uint16_t) length);
  replyIpHeader->ip_id = htons(identify_num_iphdr);
  identify_num_iphdr++;
  replyIpHeader->ip_off = htons(IP_DF);
  replyIpHeader->ip_ttl = DEFAULT_TTL;
  replyIpHeader->ip_p = ip_protocol_icmp;
  replyIpHeader->ip_sum = 0;
  replyIpHeader->ip_src = echoRequestPacket->ip_dst; /* Already in network byte order. */
  replyIpHeader->ip_dst = echoRequestPacket->ip_src; /* Already in network byte order. */
  replyIpHeader->ip_sum = cksum(replyIpHeader, getIpHeaderLength(replyIpHeader));
  
  /* Fill  ICMP fields. */
  replyIcmpHeader->icmp_type = icmp_type_echo_reply;
  replyIcmpHeader->icmp_code = 0;
  replyIcmpHeader->icmp_sum = 0;
  
  /* Copy payload into new packet*/
  memcpy(((uint8_t*) replyIcmpHeader) + sizeof(sr_icmp_hdr_t),
     ((uint8_t*) echoRequestPacket) + getIpHeaderLength(echoRequestPacket) + sizeof(sr_icmp_hdr_t), 
     icmpLength - sizeof(sr_icmp_hdr_t));
  
  /*Update checksum*/
  replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, icmpLength);
  
  /* Reply payload built. Ship it! */
  linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket, length + sizeof(sr_ethernet_hdr_t),
     IpGetPacketRoute(sr, ntohl(echoRequestPacket->ip_src)));
  
  free(replyPacket);
}

/*Find longest prefix match*/
sr_rt_t* IpGetPacketRoute(struct sr_instance* sr, in_addr_t destIp)
{
   struct sr_rt* routeIter;
   int networkMaskLength = -1;
   struct sr_rt* ret = NULL;
   
   for (routeIter = sr->routing_table; routeIter; routeIter = routeIter->next)
   {
      if (networkGetMaskLength(routeIter->mask.s_addr) > networkMaskLength)
      {
         if ((destIp & routeIter->mask.s_addr) 
            == (ntohl(routeIter->dest.s_addr) & routeIter->mask.s_addr))
         {
            /* Longer prefix match found. */
            ret = routeIter;
            networkMaskLength = networkGetMaskLength(routeIter->mask.s_addr);
         }
      }
   }
   return ret;
}

/*Get length of IPv4 subnet mask*/
static int networkGetMaskLength(uint32_t mask)
{
   int ret = 0;
   uint32_t bitScanner = 0x80000000;
   
   while ((bitScanner != 0) && ((bitScanner & mask) != 0))
   {
      bitScanner >>= 1;
      ret++;
   }
   
   return ret;
}

static void linkArpAndSendPacket(sr_instance_t *sr, sr_ethernet_hdr_t* packet, 
  unsigned int length, sr_rt_t* route)
{
  uint32_t nextHopIpAddress;
  sr_arpentry_t *arpEntry;
  
  assert(route);
  
  /* Lookup in ARP cache */
  nextHopIpAddress = ntohl(route->gw.s_addr);
  arpEntry = sr_arpcache_lookup(&sr->cache, nextHopIpAddress);
  
  packet->ether_type = htons(ethertype_ip);
  memcpy(packet->ether_shost, sr_get_interface(sr, route->interface)->addr, ETHER_ADDR_LEN);
  
  if (arpEntry != NULL)
  {
     memcpy(packet->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
     sr_send_packet(sr, (uint8_t*) packet, length, route->interface);
     
     /* Lookup made a copy, so we must free it to prevent leaks*/
     free(arpEntry);
  }
  else
  {
    /*Send ARP to next-hop*/
    struct sr_arpreq* arpRequestPtr = sr_arpcache_queuereq(&sr->cache, nextHopIpAddress,
        (uint8_t*) packet, length, route->interface);
     
     if (arpRequestPtr->times_sent == 0)
     {
        /* New request*/
        arpRequestPtr->request_interface = sr_get_interface(sr, route->interface);
        
        LinkSendArpRequest(sr, arpRequestPtr);
        
        arpRequestPtr->times_sent = 1;
        arpRequestPtr->sent = time(NULL);
     }
  }
}

/*Function to send ARP request*/
void LinkSendArpRequest(struct sr_instance* sr, struct sr_arpreq* request)
{
   uint8_t* arpPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
   sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) arpPacket;
   sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*) (arpPacket + sizeof(sr_ethernet_hdr_t));
   assert(arpPacket);

   /* Ethernet Header */
   memcpy(ethernetHdr->ether_dhost, broadcast_ehdr, ETHER_ADDR_LEN);
   memcpy(ethernetHdr->ether_shost, request->request_interface->addr, ETHER_ADDR_LEN);
   ethernetHdr->ether_type = htons(ethertype_arp);
   
   /* ARP Header */
   arpHdr->ar_hrd = htons(arp_hrd_ethernet);
   arpHdr->ar_pro = htons(ethertype_ip);
   arpHdr->ar_hln = ETHER_ADDR_LEN;
   arpHdr->ar_pln = IP_ADDR_LEN;
   arpHdr->ar_op = htons(arp_op_request);
   memcpy(arpHdr->ar_sha, request->request_interface->addr, ETHER_ADDR_LEN);
   arpHdr->ar_sip = request->request_interface->ip;
   memset(arpHdr->ar_tha, 0, ETHER_ADDR_LEN); /* Not strictly necessary by RFC 826 */
   arpHdr->ar_tip = htonl(request->ip);
   
   /*Send ARP packet*/
   sr_send_packet(sr, arpPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
      request->request_interface->name);
   free(arpPacket);
}

/*Send ICMP type 3*/
void IpSendTypeThreeIcmpPacket(struct sr_instance* sr, sr_icmp_code_t icmpCode,
  sr_ip_hdr_t* originalPacketPtr)
{
  struct sr_rt* icmpRoute;
  struct sr_if* destinationInterface;
  
  uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
     + sizeof(sr_icmp_t3_hdr_t));
  sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
     + sizeof(sr_ip_hdr_t));
  
  assert(originalPacketPtr);
  assert(sr);
  assert(replyPacket);
  
  if (networkIpSourceIsUs(sr, originalPacketPtr))
  {
     free(replyPacket);
     return;
  }
  
  /* Fill in IP header */
  replyIpHeader->ip_v = IP_VERSION;
  replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
  replyIpHeader->ip_tos = 0;
  replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  replyIpHeader->ip_id = htons(identify_num_iphdr);
  identify_num_iphdr++;
  replyIpHeader->ip_off = htons(IP_DF);
  replyIpHeader->ip_ttl = DEFAULT_TTL;
  replyIpHeader->ip_p = ip_protocol_icmp;
  replyIpHeader->ip_sum = 0;
  replyIpHeader->ip_dst = originalPacketPtr->ip_src; /* Already in network byte order. */
  
  icmpRoute = IpGetPacketRoute(sr, ntohl(replyIpHeader->ip_dst));
  assert(icmpRoute);
  destinationInterface = sr_get_interface(sr, icmpRoute->interface);
  assert(destinationInterface);
  
  replyIpHeader->ip_src = destinationInterface->ip;
  replyIpHeader->ip_sum = cksum(replyIpHeader, getIpHeaderLength(replyIpHeader));
  
  /* Fill in ICMP */
  replyIcmpHeader->icmp_type = icmp_type_desination_unreachable;
  replyIcmpHeader->icmp_code = icmpCode;
  replyIcmpHeader->icmp_sum = 0;
  memcpy(replyIcmpHeader->data, originalPacketPtr, ICMP_DATA_SIZE);
  replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
  
  linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket,
     sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
     IpGetPacketRoute(sr, ntohl(replyIpHeader->ip_dst)));
  
  free(replyPacket);
}

static bool networkIpSourceIsUs(struct sr_instance* sr, const sr_ip_hdr_t* const packet)
{
   struct sr_if* interfaceIterator;
   
   for (interfaceIterator = sr->if_list; interfaceIterator != NULL; interfaceIterator =
      interfaceIterator->next)
   {
      if (packet->ip_src == interfaceIterator->ip)
      {
         return true;
      }
   }
   
   return false;
}

/*Function forward packet*/
void IpForwardIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
  unsigned int length, const struct sr_if* const receivedInterface)
{
  struct sr_rt* forwardRoute = IpGetPacketRoute(sr, ntohl(packet->ip_dst));
  /* Decrement TTL and forward. */
  uint8_t packetTtl = packet->ip_ttl - 1;
  if (packetTtl == 0)
  {
     networkSendIcmpTtlExpired(sr, packet, length, receivedInterface);
     return;
  }
  else
  {
     /* Recalculate checksum since we altered the packet header. */
     packet->ip_ttl = packetTtl;
     packet->ip_sum = 0;
     packet->ip_sum = cksum(packet, getIpHeaderLength(packet));
  }
  
  if (forwardRoute != NULL)
  {
     uint8_t* forwardPacket = malloc(length + sizeof(sr_ethernet_hdr_t));
     memcpy(forwardPacket + sizeof(sr_ethernet_hdr_t), packet, length);
     
     linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*)forwardPacket,
        length + sizeof(sr_ethernet_hdr_t), forwardRoute);
     free(forwardPacket);
  }
  else
  {
    fprintf(stderr, "***Sending ICMP network unreachable");
     IpSendTypeThreeIcmpPacket(sr, icmp_code_network_unreachable, packet);
  }
}

static void networkSendIcmpTtlExpired(struct sr_instance* sr, sr_ip_hdr_t* originalPacket,
  unsigned int length, sr_if_t const * const receivedInterface)
{
  uint8_t* replyPacket = malloc(
     sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
     + sizeof(sr_ip_hdr_t));
    
  /* Fill in IP header */
  replyIpHeader->ip_v = IP_VERSION;
  replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
  replyIpHeader->ip_tos = 0;
  replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  replyIpHeader->ip_id = htons(identify_num_iphdr);
  identify_num_iphdr++;
  replyIpHeader->ip_off = htons(IP_DF);
  replyIpHeader->ip_ttl = DEFAULT_TTL;
  replyIpHeader->ip_p = ip_protocol_icmp;
  replyIpHeader->ip_sum = 0;
  replyIpHeader->ip_src = receivedInterface->ip;
  replyIpHeader->ip_dst = originalPacket->ip_src; /* Already in network byte order. */
  replyIpHeader->ip_sum = cksum(replyIpHeader, getIpHeaderLength(replyIpHeader));
  
  /* Fill in ICMP fields. */
  replyIcmpHeader->icmp_type = icmp_type_time_exceeded;
  replyIcmpHeader->icmp_code = 0;
  replyIcmpHeader->icmp_sum = 0;
  memcpy(replyIcmpHeader->data, originalPacket, ICMP_DATA_SIZE);
  replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
  
  linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket,
     sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
     IpGetPacketRoute(sr, ntohl(originalPacket->ip_src)));
  
  free(replyPacket);
}

uint16_t getIpHeaderLength(sr_ip_hdr_t const * const pktPtr)
{
   return (pktPtr->ip_hl) * 4;
}

sr_icmp_hdr_t * getIcmpHeaderFromIpHeader(sr_ip_hdr_t * packetPtr)
{
   return (sr_icmp_hdr_t*) (((uint8_t*) packetPtr) + getIpHeaderLength(packetPtr));
}