
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_arpcache.h"

#define START_PORT_NUMBER  10000
#define LAST_PORT_NUMBER      19999

#define SIMULTANIOUS_OPEN_WAIT_TIME 6

struct sr_instance;
struct sr_if;

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum
{
   nat_conn_outbound_syn, /* outbound SYN sent. */
   nat_conn_inbound_syn_pending, /* inbound SYN received (and queued). */
   nat_conn_connected, /* SYNs sent in both directions. Connection established. */
   nat_conn_time_wait /* One of the endpoints has sent a FIN. */
} sr_nat_tcp_conn_state_t;

typedef struct sr_nat_connection
{
   /* add TCP connection state data members here */
   sr_nat_tcp_conn_state_t connectionState;
   time_t lastAccessed;
   sr_ip_hdr_t * queuedInboundSyn;
   
   struct
   {
      uint32_t ipAddress;
      uint16_t portNumber;
   } external;
   
   struct sr_nat_connection *next;
} sr_nat_connection_t;


typedef struct sr_nat_mapping
{
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
}sr_nat_mapping_t;

typedef struct sr_nat
{
   /* add any fields here */
   struct sr_nat_mapping *mappings;
   struct sr_instance * routerState;
   
   uint16_t nextTcpPortNumber;
   uint16_t nextIcmpIdentNumber;
   
   unsigned int tcpTransitoryTimeout;
   unsigned int tcpEstablishedTimeout;
   unsigned int icmpTimeout;
   
   /* threading */
   pthread_mutex_t lock;
   pthread_mutexattr_t attr;
   pthread_attr_t thread_attr;
   pthread_t thread;
} sr_nat_t;


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

#endif

/* Add functions.*/
void natHandleRecievedIpPacket(struct sr_instance* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
                                       sr_if_t *receivedInterface);
void natNotdonePacketMapping(struct sr_instance* sr, sr_ip_hdr_t* ipDatagram, unsigned int length, 
                                                            sr_if_t *receivedInterface);
                                                                                                   