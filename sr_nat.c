#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"

static const char internalInterfaceName[] = "eth1";

/*Get internal interface*/
static inline sr_if_t* getInternalInterface(sr_instance_t *sr)
{
   return sr_get_interface(sr, internalInterfaceName);
}

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->nextIcmpIdentNumber = STARTING_PORT_NUMBER;
  nat->nextTcpPortNumber = STARTING_PORT_NUMBER;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  while (nat->mappings)
  {
     sr_nat_destroy_mapping(nat, nat->mappings);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
      sr_nat_mapping_t *mappingWalker = nat->mappings;
      
      while (mappingWalker)
      {
         if (mappingWalker->type == nat_mapping_icmp)
         {
            if (difftime(curtime, mappingWalker->last_updated) > nat->icmpTimeout)
            {
               sr_nat_mapping_t* next = mappingWalker->next;
               mappingWalker = next;
            }
            else
            {
               mappingWalker = mappingWalker->next;
            }
         }
         else if (mappingWalker->type == nat_mapping_tcp)
         {
            sr_nat_connection_t * connectionIterator = mappingWalker->conns;
            while (connectionIterator)
            {
               if ((connectionIterator->connectionState == nat_conn_connected)
                  && (difftime(curtime, connectionIterator->lastAccessed)
                     > nat->tcpEstablishedTimeout))
               {
                  sr_nat_connection_t* next = connectionIterator->next;
                  sr_nat_destroy_connection(mappingWalker, connectionIterator);
                  connectionIterator = next;
               }
               else if (((connectionIterator->connectionState == nat_conn_outbound_syn)
                  || (connectionIterator->connectionState == nat_conn_time_wait))
                  && (difftime(curtime, connectionIterator->lastAccessed)
                     > nat->tcpTransitoryTimeout))
               {
                  sr_nat_connection_t* next = connectionIterator->next;
                  sr_nat_destroy_connection(mappingWalker, connectionIterator);
                  connectionIterator = next;
               }
               else if ((connectionIterator->connectionState == nat_conn_inbound_syn_pending)
                  && (difftime(curtime, connectionIterator->lastAccessed)
                     > nat->tcpTransitoryTimeout))
               {
                  sr_nat_connection_t* next = connectionIterator->next;
                  if (connectionIterator->queuedInboundSyn)
                  {
                     IpSendTypeThreeIcmpPacket(nat->routerState,
                        icmp_code_destination_port_unreachable,
                        connectionIterator->queuedInboundSyn);
                  }
                  sr_nat_destroy_connection(mappingWalker, connectionIterator);
                  connectionIterator = next;
               }
               else
               {
                  connectionIterator = connectionIterator->next;
               }
            }
            
            if (mappingWalker->conns == NULL)
            {
               sr_nat_mapping_t* next = mappingWalker->next;
               sr_nat_destroy_mapping(nat, mappingWalker);
               mappingWalker = next;
            }
            else
            {
               mappingWalker = mappingWalker->next;
            }
         }
         else
         {
            mappingWalker = mappingWalker->next;
         }
      }
      pthread_mutex_unlock(&(nat->lock));
   }
   return NULL;
}



/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  sr_nat_mapping_t *lookupResult = natTrustedLookupExternal(nat, aux_ext, type); 
   
  if (lookupResult != NULL)
  {
     lookupResult->last_updated = time(NULL);
     copy = malloc(sizeof(sr_nat_mapping_t));
     memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  sr_nat_mapping_t * lookupResult = natTrustedLookupInternal(nat, ip_int, aux_int, type);
    
  if (lookupResult != NULL)
  {
    lookupResult->last_updated = time(NULL);
    copy = malloc(sizeof(sr_nat_mapping_t));
    assert(copy);
    memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int,
  sr_nat_mapping_type type)
{
  pthread_mutex_lock(&(nat->lock));
  
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = natTrustedCreateMapping(nat, ip_int, aux_int, type);
  struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping_t));
  
  memcpy(copy, mapping, sizeof(sr_nat_mapping_t));
  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/*Called by router program when an IP packet 
is received and NAT functionality is enabled*/
void NatHandleRecievedIpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
  sr_if_t const * const receivedInterface)
{
  if (ipPacket->ip_p == ip_protocol_tcp)
  {
     natHandleTcpPacket(sr, ipPacket, length, receivedInterface);
  }
  else if (ipPacket->ip_p == ip_protocol_icmp)
  {
     natHandleIcmpPacket(sr, ipPacket, length, receivedInterface);
  }
  else
  {
    /*Drop*/
  }
}

/*Called by the router code when an IP datagram needs its NAT 
            translation undone (like when TTL is exceeded)*/
void NatUndoPacketMapping(sr_instance_t* sr, sr_ip_hdr_t* mutatedPacket, unsigned int length, 
  sr_if_t const * const receivedInterface)
{
  sr_nat_mapping_t * natMap;
  if (getInternalInterface(sr)->ip == receivedInterface->ip)
  {
     /* Undo an outbound conversion. */
     if (mutatedPacket->ip_p == ip_protocol_icmp)
     {
        sr_icmp_t0_hdr_t * icmpHeader = (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(
           mutatedPacket);
        natMap = sr_nat_lookup_external(sr->nat, icmpHeader->ident, nat_mapping_icmp);
        if (natMap != NULL)
        {
           icmpHeader->ident = natMap->aux_int;
           icmpHeader->icmp_sum = 0;
           icmpHeader->icmp_sum = cksum(icmpHeader, length - getIpHeaderLength(mutatedPacket));
           
           mutatedPacket->ip_src = natMap->ip_int;
           mutatedPacket->ip_sum = 0;
           mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
        }
        free(natMap);
     }
     else if (mutatedPacket->ip_p == ip_protocol_tcp)
     {
        sr_tcp_hdr_t * tcpHeader = getTcpHeaderFromIpHeader(mutatedPacket);
        natMap = sr_nat_lookup_external(sr->nat, tcpHeader->sourcePort, nat_mapping_tcp);
        if (natMap != NULL)
        {
           tcpHeader->sourcePort = natMap->aux_int;
           mutatedPacket->ip_src = natMap->ip_int;
           
           natRecalculateTcpChecksum(mutatedPacket, length);
           
           mutatedPacket->ip_sum = 0;
           mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
        }
        free(natMap);
     }
  }
  else
  {
     /* Undo an potential inbound conversion. If the lookup fails, we can 
      * assume this packet did not cross through the NAT. */
     if (mutatedPacket->ip_p == ip_protocol_icmp)
     {
        sr_icmp_t0_hdr_t * icmpHeader = (sr_icmp_t0_hdr_t *) (((uint8_t *) mutatedPacket)
           + getIpHeaderLength(mutatedPacket));
        natMap = sr_nat_lookup_internal(sr->nat, ntohl(mutatedPacket->ip_dst), 
           ntohs(icmpHeader->ident), nat_mapping_icmp);
        if (natMap != NULL)
        {
           icmpHeader->ident = htons(natMap->aux_ext);
           icmpHeader->icmp_sum = 0;
           icmpHeader->icmp_sum = cksum(icmpHeader, length - getIpHeaderLength(mutatedPacket));
           
           mutatedPacket->ip_dst = sr_get_interface(sr,
              IpGetPacketRoute(sr, mutatedPacket->ip_src)->interface)->ip;
           mutatedPacket->ip_sum = 0;
           mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
           
           free(natMap);
        }
     }
     else if (mutatedPacket->ip_p == ip_protocol_tcp)
     {
        sr_tcp_hdr_t * tcpHeader = (sr_tcp_hdr_t *) (((uint8_t *) mutatedPacket)
           + getIpHeaderLength(mutatedPacket));
        natMap = sr_nat_lookup_internal(sr->nat, ntohl(mutatedPacket->ip_dst), 
           ntohs(tcpHeader->destinationPort), nat_mapping_icmp);
        if (natMap != NULL)
        {
           tcpHeader->destinationPort = htons(natMap->aux_ext);
           mutatedPacket->ip_dst = sr_get_interface(sr,
              IpGetPacketRoute(sr, mutatedPacket->ip_src)->interface)->ip;
           
           natRecalculateTcpChecksum(mutatedPacket, length);
           
           mutatedPacket->ip_sum = 0;
           mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
           
           free(natMap);
        }
     }
  }
}

static uint16_t natNextMappingNumber(sr_nat_t* nat, sr_nat_mapping_type mappingType)
{
   uint16_t startIndex;
   sr_nat_mapping_t * mappingIterator = nat->mappings;
   if (mappingType == nat_mapping_icmp)
   {
      startIndex = nat->nextIcmpIdentNumber;
   }
   else if (mappingType == nat_mapping_tcp)
   {
      startIndex = nat->nextTcpPortNumber;
   }
   
   /* Look to see if a mapping already exists for this port number */
   while (mappingIterator)
   {
      if ((mappingIterator->type == mappingType) && (htons(startIndex) == mappingIterator->aux_ext))
      {
         /* Mapping already exists for this value. Go to the next one and start the search over. */
         startIndex = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
         mappingIterator = nat->mappings;
      }
      else
      {
         mappingIterator = mappingIterator->next;
      }
   }
   
   /* Setup the next search start location for the next mapping */
   if (mappingType == nat_mapping_icmp)
   {
      nat->nextIcmpIdentNumber = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
   }
   else if (mappingType == nat_mapping_tcp)
   {
      nat->nextTcpPortNumber = (startIndex == LAST_PORT_NUMBER) ? STARTING_PORT_NUMBER : (startIndex + 1);
   }
   
   return startIndex;
}

/*
removes a mapping from the linked list. Based off of ARP cache implementation.
 */
static void sr_nat_destroy_mapping(sr_nat_t* nat, sr_nat_mapping_t* natMapping)
{
   if (natMapping)
   {
      sr_nat_mapping_t *req, *prev = NULL, *next = NULL;
      for (req = nat->mappings; req != NULL; req = req->next)
      {
         if (req == natMapping)
         {
            if (prev)
            {
               next = req->next;
               prev->next = next;
            }
            else
            {
               next = req->next;
               nat->mappings = next;
            }
            
            break;
         }
         prev = req;
      }
      
      while (natMapping->conns != NULL)
      {
         sr_nat_connection_t * curr = natMapping->conns;
         natMapping->conns = curr->next;
         
         free(curr);
      }
      
      free(natMapping);
   }
}

/*
 destroys a specified connection in the specified natMapping.
 */
static void sr_nat_destroy_connection(sr_nat_mapping_t* natMapping, sr_nat_connection_t* connection)
{
   sr_nat_connection_t *req, *prev = NULL, *next = NULL;
   
   if (natMapping && connection)
   {
      for (req = natMapping->conns; req != NULL; req = req->next)
      {
         if (req == connection)
         {
            if (prev)
            {
               next = req->next;
               prev->next = next;
            }
            else
            {
               next = req->next;
               natMapping->conns = next;
            }
            
            break;
         }
         prev = req;
      }
      
      if(connection->queuedInboundSyn)
      {
         free(connection->queuedInboundSyn);
      }
      
      free(connection);
   }
}

/*
creates a nat mapping in the NAT state structure.
 */
static sr_nat_mapping_t * natTrustedCreateMapping(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   struct sr_nat_mapping *mapping = malloc(sizeof(sr_nat_mapping_t));
   
   mapping->aux_ext = htons(natNextMappingNumber(nat, type));
   mapping->conns = NULL;
   
   /* Store mapping information */
   mapping->aux_int = aux_int;
   mapping->ip_int = ip_int;
   mapping->last_updated = time(NULL);
   mapping->type = type;
   
   /* Add mapping to the front of the list. */
   mapping->next = nat->mappings;
   nat->mappings = mapping;
   
   return mapping;
}

/*Performs a NAT internal lookup returning a shared pointer into the NAT mapping list.*/
static sr_nat_mapping_t * natTrustedLookupInternal(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   sr_nat_mapping_t *mappingWalker;
      
   for (mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
   {
      if ((mappingWalker->type == type) && (mappingWalker->ip_int == ip_int)
         && (mappingWalker->aux_int == aux_int))
      {
         return mappingWalker;
      }
   }
   
   return NULL;
}

/*Performs a NAT external lookup returning a shared pointer into the NAT mapping list.*/
static sr_nat_mapping_t * natTrustedLookupExternal(sr_nat_t * nat, uint16_t aux_ext,
   sr_nat_mapping_type type)
{
   for (sr_nat_mapping_t * mappingWalker = nat->mappings; mappingWalker != NULL ; mappingWalker =
      mappingWalker->next)
   {
      if ((mappingWalker->type == type) && (mappingWalker->aux_ext == aux_ext))
      {
         return mappingWalker;
      }
   }
   return NULL;
}

/*Finds the associated TCP connection in a NAT mapping given an external IP:Port pair.*/
static sr_nat_connection_t * natTrustedFindConnection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
   uint16_t port_ext)
{
   sr_nat_connection_t * connectionIterator = natEntry->conns;
   while (connectionIterator != NULL)
   {
      if ((connectionIterator->external.ipAddress == ip_ext) 
         && (connectionIterator->external.portNumber == port_ext))
      {
         connectionIterator->lastAccessed = time(NULL);
         break;
      }
      
      connectionIterator = connectionIterator->next;
   }
   return connectionIterator;
}

/*Function processes a TCP packet when NAT functionality is enabled. */
static void natHandleTcpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface)
{
   sr_tcp_hdr_t* tcpHeader = getTcpHeaderFromIpHeader(ipPacket);
   
   if (!TcpPerformIntegrityCheck(ipPacket, length))
   {
      return;
   }
   
   if ((getInternalInterface(sr)->ip == receivedInterface->ip) && (IpDestinationIsUs(sr, ipPacket)))
   {
      IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
   }
   else if (getInternalInterface(sr)->ip == receivedInterface->ip)
   {
      sr_nat_mapping_t * natMapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
         tcpHeader->sourcePort, nat_mapping_tcp);
      
      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_M)
      {
         if (natMapping == NULL)
         {
            /* Outbound SYN with no prior mapping. Create one! */
            pthread_mutex_lock(&(sr->nat->lock));
            sr_nat_connection_t *firstConnection = malloc(sizeof(sr_nat_connection_t));
            sr_nat_mapping_t *sharedNatMapping;
            natMapping = malloc(sizeof(sr_nat_mapping_t));
            assert(firstConnection); assert(natMapping);
            
            sharedNatMapping = natTrustedCreateMapping(sr->nat, ipPacket->ip_src,
               tcpHeader->sourcePort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            /* Fill in first connection information. */
            firstConnection->connectionState = nat_conn_outbound_syn;
            firstConnection->lastAccessed = time(NULL);
            firstConnection->queuedInboundSyn = NULL;
            firstConnection->external.ipAddress = ipPacket->ip_dst;
            firstConnection->external.portNumber = tcpHeader->destinationPort;
            
            /* Add to the list of connections. */
            firstConnection->next = sharedNatMapping->conns;
            sharedNatMapping->conns = firstConnection;
            
            /* Create a copy so we can keep using it after we unlock the NAT table. */
            memcpy(natMapping, sharedNatMapping, sizeof(sr_nat_mapping_t));
            
            pthread_mutex_unlock(&(sr->nat->lock));
            
         }
         else
         {
            /* Outbound SYN with prior mapping. Add the connection if one doesn't exist */
            pthread_mutex_lock(&(sr->nat->lock));
            sr_nat_mapping_t *sharedNatMapping = natTrustedLookupInternal(sr->nat, ipPacket->ip_src,
               tcpHeader->sourcePort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = natTrustedFindConnection(sharedNatMapping,
               ipPacket->ip_dst, tcpHeader->destinationPort);
            
            if (connection == NULL)
            {
               /* Connection does not exist. Create it. */
               connection = malloc(sizeof(sr_nat_connection_t));
               assert(connection);
               
               /* Fill in connection information. */
               connection->connectionState = nat_conn_outbound_syn;
               connection->external.ipAddress = ipPacket->ip_dst;
               connection->external.portNumber = tcpHeader->destinationPort;
               
               /* Add to the list of connections. */
               connection->next = sharedNatMapping->conns;
               sharedNatMapping->conns = connection;
               
            }
            else if (connection->connectionState == nat_conn_time_wait)
            {
               /* Give client opportunity to reopen the connection. */
               connection->connectionState = nat_conn_outbound_syn;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
               connection->connectionState = nat_conn_connected;
               
               /* As per lab instructions, silently drop the original 
                * unsolicited inbound SYN */
               if (connection->queuedInboundSyn) { free(connection->queuedInboundSyn); }
            }
            /* Only other options are connected and outbound syn, in which we 
             * assume this is a retried packet. */
            
            pthread_mutex_unlock(&(sr->nat->lock));
         }
      }
      else if (natMapping == NULL)
      {
         /* TCP packet attempted to traverse the NAT on an unopened 
          * connection. What to do? Silently drop the packet. */
         return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_M)
      {
         /* Outbound FIN detected. Put connection into TIME_WAIT state. */
         pthread_mutex_lock(&(sr->nat->lock));
         sr_nat_mapping_t *sharedNatMapping = natTrustedLookupInternal(sr->nat, ipPacket->ip_src,
            tcpHeader->sourcePort, nat_mapping_tcp);
         sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, 
            ipPacket->ip_dst, tcpHeader->destinationPort);
         
         if (associatedConnection)
         {
            associatedConnection->connectionState = nat_conn_time_wait;
         }
         
         pthread_mutex_unlock(&(sr->nat->lock));
      }
      
      /* All NAT state updating done by this point. Translate and forward. */
      natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface, natMapping);
      
      if (natMapping) { free(natMapping); }
   }
   else /* Inbound TCP packet */
   {
      sr_nat_mapping_t * natMapping = sr_nat_lookup_external(sr->nat, tcpHeader->destinationPort,
         nat_mapping_tcp);
      
      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_M)
      {
         /* Inbound SYN received. */
         if (natMapping == NULL)
         {
            /* In the case that there is no mapping, no hole can be blown 
             * through the NAT for simultaneous open. Thus we immediately call 
             * the port as closed. */
            IpSendTypeThreeIcmpPacket(sr, icmp_code_destination_port_unreachable, ipPacket);
            return;
         }
         else
         {
            /* Potential simultaneous open */
            pthread_mutex_lock(&(sr->nat->lock));
            
            sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, 
               tcpHeader->destinationPort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = natTrustedFindConnection(sharedNatMapping,
               ipPacket->ip_src, tcpHeader->sourcePort);
            
            if (connection == NULL)
            {
               /* Potential simultaneous open. */
               connection = malloc(sizeof(sr_nat_connection_t));
               assert(connection);
               
               /* Fill in connection information. */
               connection->connectionState = nat_conn_inbound_syn_pending;
               connection->queuedInboundSyn = malloc(length);
               memcpy(connection->queuedInboundSyn, ipPacket, length);
               connection->external.ipAddress = ipPacket->ip_src;
               connection->external.portNumber = tcpHeader->sourcePort;
               
               /* Add to the list of connections. */
               connection->next = sharedNatMapping->conns;
               sharedNatMapping->conns = connection;
               
               return;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
               /* Retry of inbound SYN. Silently drop. */
               return;
            }
            else if (connection->connectionState == nat_conn_outbound_syn)
            {
               /* Connection UP! */
               connection->connectionState = nat_conn_connected;
            }
            
            pthread_mutex_unlock(&(sr->nat->lock));
         }
      }
      else if (natMapping == NULL)
      {
         /* TCP packet attempted to traverse the NAT on an unopened 
          * connection. What to do? LOUDLY drop the packet. */
         IpSendTypeThreeIcmpPacket(sr, icmp_code_destination_port_unreachable, ipPacket);
         return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_M)
      {
         /* Inbound FIN detected. Put connection into TIME_WAIT state. */
         pthread_mutex_lock(&(sr->nat->lock));
         sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, 
            tcpHeader->destinationPort, nat_mapping_tcp);
         sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, 
            ipPacket->ip_src, tcpHeader->sourcePort);
         
         if (associatedConnection)
         {
            associatedConnection->connectionState = nat_conn_time_wait;
         }
         
         pthread_mutex_unlock(&(sr->nat->lock));
      }
      else
      {
         /* Lookup the associated connection to "touch" it and keep it alive. */
         pthread_mutex_lock(&(sr->nat->lock));
         sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, 
            tcpHeader->destinationPort, nat_mapping_tcp);
         sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, 
            ipPacket->ip_src, tcpHeader->sourcePort);
         
         if (associatedConnection == NULL)
         {
            /* Received unsolicited non-SYN packet when no active connection was found. */
            pthread_mutex_unlock(&(sr->nat->lock));
            
            return;
         }
         else
         {
            pthread_mutex_unlock(&(sr->nat->lock));
         }
      }
      
      /* If the packet made it here, it's okay to traverse. */
      natHandleReceivedInboundIpPacket(sr, ipPacket, length, receivedInterface, natMapping);
      
      if (natMapping) { free(natMapping); }
   }
}

/*Function processes an ICMP packet when NAT functionality is enabled. */
static void natHandleIcmpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface)
{
   sr_icmp_hdr_t * icmpHeader = getIcmpHeaderFromIpHeader(ipPacket);
   
   if (!IcmpPerformIntegrityCheck(icmpHeader, length - getIpHeaderLength(ipPacket)))
   {
      return;
   }
   
   if ((getInternalInterface(sr)->ip == receivedInterface->ip) && (IpDestinationIsUs(sr, ipPacket)))
   {
      IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
   }
   else if (getInternalInterface(sr)->ip == receivedInterface->ip)
   {
      if ((icmpHeader->icmp_type == icmp_type_echo_request)
         || (icmpHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t * icmpPingHdr = (sr_icmp_t0_hdr_t *) icmpHeader;
         sr_nat_mapping_t * natLookupResult = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src, 
            icmpPingHdr->ident, nat_mapping_icmp);
         
         /* No mapping? Make one! */
         if (natLookupResult == NULL)
         {
            natLookupResult = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src, icmpPingHdr->ident,
               nat_mapping_icmp);
         }
         
         natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface, natLookupResult);
         free(natLookupResult);
      }
      else 
      {
         sr_ip_hdr_t * embeddedIpPacket = NULL;
         sr_nat_mapping_t * natLookupResult = NULL;
         
         if (icmpHeader->icmp_type == icmp_type_desination_unreachable)
         {
            sr_icmp_t3_hdr_t * unreachableHeader = (sr_icmp_t3_hdr_t *) icmpHeader;
            embeddedIpPacket = (sr_ip_hdr_t *) unreachableHeader->data;
         }
         else if (icmpHeader->icmp_type == icmp_type_time_exceeded)
         {
            sr_icmp_t11_hdr_t * timeExceededHeader = (sr_icmp_t11_hdr_t *) icmpHeader;
            embeddedIpPacket = (sr_ip_hdr_t *) timeExceededHeader->data;
         }
         else
         {
            /* By RFC, no other ICMP types have to support NAT traversal (SHOULDs 
             * instead of MUSTs). It's not that I'm lazy, it's just that this 
             * assignment is hard enough as it is. */
            return;
         }
         
         assert(embeddedIpPacket);
         
         if (embeddedIpPacket->ip_p == ip_protocol_icmp)
         {
            sr_icmp_t0_hdr_t * embeddedIcmpHeader =
               (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(embeddedIpPacket);
            if ((embeddedIcmpHeader->icmp_type == icmp_type_echo_request)
               || (embeddedIcmpHeader->icmp_type == icmp_type_echo_reply))
            {
               natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst, 
                  embeddedIcmpHeader->ident, nat_mapping_icmp);
            }
            /* Otherwise, we will not have a mapping for this ICMP type. 
             * Either way, echo request and echo reply are the only ICMP 
             * packet types that can generate another ICMP packet. */
         }
         else if (embeddedIpPacket->ip_p == ip_protocol_tcp)
         {
            sr_tcp_hdr_t * embeddedTcpHeader = getTcpHeaderFromIpHeader(embeddedIpPacket);
            natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
               embeddedTcpHeader->destinationPort, nat_mapping_tcp);
         }
         else
         {
            /* No way we have a mapping for an unsupported protocol. 
             * Silently drop the packet. */
            return;
         }
         
         if (natLookupResult != NULL)
         {
            natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface,
               natLookupResult);
            free(natLookupResult);
         }
      }
   }
   else /* Inbound ICMP packet */
   {
      if (!IpDestinationIsUs(sr, ipPacket))
      {
         if (getInternalInterface(sr)->ip
            != sr_get_interface(sr, IpGetPacketRoute(sr, ntohl(ipPacket->ip_dst))->interface)->ip)
         {
            /* Sender not attempting to traverse the NAT. Allow the packet to 
             * be routed without alteration. */
            IpForwardIpPacket(sr, ipPacket, length, receivedInterface);
         }
         else
         {
            fprintf(stderr, "Unsolicited inbound ICMP packet received attempting to send to internal IP. Dropping.\n");
         }
         return;
      }
      else if (ipPacket->ip_dst == getInternalInterface(sr)->ip)
      {
         /* Disallow sending packet to our internal interface. */
         fprintf(stderr, "Received ICMP packet to our internal interface. Dropping.\n");
         //TODO: Type 3 ICMP response?
         return;
      }
      else if ((icmpHeader->icmp_type == icmp_type_echo_request)
         || (icmpHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t * icmpPingHdr = (sr_icmp_t0_hdr_t *) icmpHeader;
         sr_nat_mapping_t * natLookupResult = sr_nat_lookup_external(sr->nat, icmpPingHdr->ident, 
            nat_mapping_icmp);
         
         if (natLookupResult == NULL)
         {
            /* No mapping exists. Assume ping is actually for us. */
            IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
         }
         else
         {
            natHandleReceivedInboundIpPacket(sr, ipPacket, length, receivedInterface,
               natLookupResult);
            free (natLookupResult);
         }
      }
      else 
      {
         sr_ip_hdr_t * embeddedIpPacket = NULL;
         sr_nat_mapping_t * natLookupResult = NULL;
         
         if (icmpHeader->icmp_type == icmp_type_desination_unreachable)
         {
            sr_icmp_t3_hdr_t * unreachableHeader = (sr_icmp_t3_hdr_t *) icmpHeader;
            embeddedIpPacket = (sr_ip_hdr_t *) unreachableHeader->data;
         }
         else if (icmpHeader->icmp_type == icmp_type_time_exceeded)
         {
            sr_icmp_t11_hdr_t * timeExceededHeader = (sr_icmp_t11_hdr_t *) icmpHeader;
            embeddedIpPacket = (sr_ip_hdr_t *) timeExceededHeader->data;
         }
         else
         {
            /* By RFC, no other ICMP types have to support NAT traversal (SHOULDs 
             * instead of MUSTs). It's not that I'm lazy, it's just that this 
             * assignment is hard enough as it is. */
            fprintf(stderr, "Dropping unsupported inbound ICMP packet Type: %u Code: %u.\n",
               icmpHeader->icmp_type, icmpHeader->icmp_code);
            return;
         }
         
         assert(embeddedIpPacket);
         
         if (embeddedIpPacket->ip_p == ip_protocol_icmp)
         {
            sr_icmp_t0_hdr_t * embeddedIcmpHeader =
               (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(embeddedIpPacket);
            if ((embeddedIcmpHeader->icmp_type == icmp_type_echo_request)
               || (embeddedIcmpHeader->icmp_type == icmp_type_echo_reply))
            {
               natLookupResult = sr_nat_lookup_external(sr->nat, embeddedIcmpHeader->ident, 
                  nat_mapping_icmp);
            }
            /* Otherwise, we will not have a mapping for this ICMP type. 
             * Either way, echo request and echo reply are the only ICMP 
             * packet types that can generate another ICMP packet. */
         }
         else if (embeddedIpPacket->ip_p == ip_protocol_tcp)
         {
            sr_tcp_hdr_t * embeddedTcpHeader = getTcpHeaderFromIpHeader(embeddedIpPacket);
            natLookupResult = sr_nat_lookup_external(sr->nat, embeddedTcpHeader->sourcePort, nat_mapping_tcp);
         }
         else
         {
            /* No way we have a mapping for an unsupported protocol. 
             * Silently drop the packet. */
            return;
         }
         
         if (natLookupResult != NULL)
         {
            natHandleReceivedInboundIpPacket(sr, ipPacket, length, receivedInterface,
               natLookupResult);
            free(natLookupResult);
         }
      }
   }
}

/*Function takes an outbound (internal -> external) IP datagram, 
 *        performs any necessary NAT translation, and forwards the packet. */
static void natHandleReceivedOutboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const receivedInterface, sr_nat_mapping_t * natMapping)
{
   if (packet->ip_p == ip_protocol_icmp)
   {
      sr_icmp_hdr_t *icmpPacketHeader = (sr_icmp_hdr_t *) (((uint8_t*) packet)
         + getIpHeaderLength(packet));

      if ((icmpPacketHeader->icmp_type == icmp_type_echo_request)
         || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t* rewrittenIcmpHeader = (sr_icmp_t0_hdr_t*) icmpPacketHeader;
         int icmpLength = length - getIpHeaderLength(packet);
         
         assert(natMapping);
         
         /* Handle ICMP identify remap and validate. */
         rewrittenIcmpHeader->ident = natMapping->aux_ext;
         rewrittenIcmpHeader->icmp_sum = 0;
         rewrittenIcmpHeader->icmp_sum = cksum(rewrittenIcmpHeader, icmpLength);
         
         /* Handle IP address remap and validate. */
         packet->ip_src = sr_get_interface(sr,
            IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
      else
      {
         int icmpLength = length - getIpHeaderLength(packet);
         sr_ip_hdr_t * originalDatagram;
         if (icmpPacketHeader->icmp_type == icmp_type_desination_unreachable)
         {
            /* This packet is actually associated with a stream. */
            sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
         else if (icmpPacketHeader->icmp_type == icmp_type_time_exceeded)
         {
            sr_icmp_t11_hdr_t *unreachablePacketHeader = (sr_icmp_t11_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
            
         assert(natMapping);
         
         if (originalDatagram->ip_p == ip_protocol_tcp)
         {
            sr_tcp_hdr_t *originalTransportHeader = getTcpHeaderFromIpHeader(originalDatagram);
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->destinationPort = natMapping->aux_ext;
            originalDatagram->ip_dst = sr_get_interface(sr,
               IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
         }
         else if (originalDatagram->ip_p == ip_protocol_icmp)
         {
            sr_icmp_t0_hdr_t *originalTransportHeader =
               (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(originalDatagram);
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->ident = natMapping->aux_ext;
            originalDatagram->ip_dst = sr_get_interface(sr,
               IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
         }
         
         /* Update ICMP checksum */
         icmpPacketHeader->icmp_sum = 0;
         icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);
         
         /* Rewrite actual packet header. */
         packet->ip_src = sr_get_interface(sr,
            IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
   }
   else if (packet->ip_p == ip_protocol_tcp)
   {
      sr_tcp_hdr_t* tcpHeader = (sr_tcp_hdr_t *) (((uint8_t*) packet) + getIpHeaderLength(packet));
      
      tcpHeader->sourcePort = natMapping->aux_ext;
      packet->ip_src = sr_get_interface(sr,
         IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
      
      natRecalculateTcpChecksum(packet, length);
      IpForwardIpPacket(sr, packet, length, receivedInterface);
   }
   /* If another protocol, should have been dropped by now. */
}

/*Function takes an inbound (external -> internal) IP datagram, 
 *        performs any necessary NAT translation, and forwards the packet. */
static void natHandleReceivedInboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, 
   unsigned int length, const struct sr_if* const receivedInterface, sr_nat_mapping_t * natMapping)
{
   if (packet->ip_p == ip_protocol_icmp)
   {
      sr_icmp_hdr_t *icmpPacketHeader = getIcmpHeaderFromIpHeader(packet);
      
      if ((icmpPacketHeader->icmp_type == icmp_type_echo_request)
         || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t *echoPacketHeader = (sr_icmp_t0_hdr_t *) icmpPacketHeader;
         int icmpLength = length - getIpHeaderLength(packet);
         
         assert(natMapping);
         
         /* Handle ICMP identify remap and validate. */
         echoPacketHeader->ident = natMapping->aux_int;
         echoPacketHeader->icmp_sum = 0;
         echoPacketHeader->icmp_sum = cksum(echoPacketHeader, icmpLength);
         
         /* Handle IP address remap and validate. */
         packet->ip_dst = natMapping->ip_int;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
      else 
      {
         int icmpLength = length - getIpHeaderLength(packet);
         sr_ip_hdr_t * originalDatagram;
         if (icmpPacketHeader->icmp_type == icmp_type_desination_unreachable)
         {
            /* This packet is actually associated with a stream. */
            sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
         else if (icmpPacketHeader->icmp_type == icmp_type_time_exceeded)
         {
            sr_icmp_t11_hdr_t *unreachablePacketHeader = (sr_icmp_t11_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
            
         assert(natMapping);
         
         if (originalDatagram->ip_p == ip_protocol_tcp)
         {
            sr_tcp_hdr_t *originalTransportHeader = getTcpHeaderFromIpHeader(originalDatagram);
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->sourcePort = natMapping->aux_int;
            originalDatagram->ip_src = natMapping->ip_int;
         }
         else if (originalDatagram->ip_p == ip_protocol_icmp)
         {
            sr_icmp_t0_hdr_t *originalTransportHeader =
               (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(originalDatagram);
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->ident = natMapping->aux_int;
            originalDatagram->ip_src = natMapping->ip_int;
         }
         
         /* Update ICMP checksum */
         icmpPacketHeader->icmp_sum = 0;
         icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);
         
         /* Rewrite actual packet header. */
         packet->ip_dst = natMapping->ip_int;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
   }
   else if (packet->ip_p == ip_protocol_tcp)
   {
      sr_tcp_hdr_t* tcpHeader = (sr_tcp_hdr_t *) (((uint8_t*) packet) + getIpHeaderLength(packet));
            
      tcpHeader->destinationPort = natMapping->aux_int;
      packet->ip_dst = natMapping->ip_int;
      
      natRecalculateTcpChecksum(packet, length);
      IpForwardIpPacket(sr, packet, length, receivedInterface);
   }
}

/*Helper function for recalculating a TCP packet checksum after it has been altered.*/
static void natRecalculateTcpChecksum(sr_ip_hdr_t * tcpPacket, unsigned int length)
{
   unsigned int tcpLength = length - getIpHeaderLength(tcpPacket);
   uint8_t *packetCopy = malloc(sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   sr_tcp_ip_pseudo_hdr_t * checksummedHeader = (sr_tcp_ip_pseudo_hdr_t *) packetCopy;
   sr_tcp_hdr_t * const tcpHeader = (sr_tcp_hdr_t * const ) (((uint8_t*) tcpPacket)
      + getIpHeaderLength(tcpPacket));
   
   /* I wish there was a better way to do this with pointer magic, but I don't 
    * see it. Make a copy of the packet and prepend the IP pseudo-header to 
    * the front. */
   memcpy(packetCopy + sizeof(sr_tcp_ip_pseudo_hdr_t), tcpHeader, tcpLength);
   checksummedHeader->sourceAddress = tcpPacket->ip_src;
   checksummedHeader->destinationAddress = tcpPacket->ip_dst;
   checksummedHeader->zeros = 0;
   checksummedHeader->protocol = ip_protocol_tcp;
   checksummedHeader->tcpLength = htons(tcpLength);
   
   tcpHeader->checksum = 0;
   tcpHeader->checksum = cksum(packetCopy, sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   
   free(packetCopy);
}