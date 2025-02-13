#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/

/*send arp request */
void send_arp_request(struct sr_instance sr, uint8_t packet, unsigned int len,
                                                                char *interface)
{
  struct sr_if* iface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t ehdr = (sr_ethernet_hdr_t)packet;
  sr_ip_hdr_t iphdr = (sr_ip_hdr_t)(packet + sizeof(sr_ethernet_hdr_t));
  
  /create new arp packet/
  struct sr_packet new_arp_pkt = (struct sr_packet)malloc(sizeof(struct sr_packet));
  new_arp_pkt->buf = (uint8_t *)malloc(len);
  memcpy(new_arp_pkt->buf, packet, len);
  new_arp_pkt->len = len;
  new_arp_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
  strncpy(new_arp_pkt->iface, interface, sr_IFACE_NAMELEN);
  
  sr_arp_hdr_t arphdr = (sr_arp_hdr_t)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  
  /handle ethernet header/
  memset(ehdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  ehdr->ether_type = ntohs(ethertype_arp);
  
  /arp setup/
  arphdr->ar_hrd = ntohs(arp_hrd_ethernet);
  arphdr->ar_pro = ntohs(ethertype_arp);
  arphdr->ar_op = ntohs(arp_op_request);
  memcpy(arphdr->ar_tha, ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(arphdr->ar_sha, ehdr->ether_shost, ETHER_ADDR_LEN);
  arphdr->ar_tip = iphdr->ip_dst;
  arphdr->ar_sip = iface->ip;

  /send arp reply packet/
  sr_send_packet(sr, new_arp_pkt->buf, len, interface);
}

void handle_arpreq(struct sr_instance sr, struct sr_arpreq *req, uint8_t packet,
                                                unsigned int len, char* interface)
{   
    unsigned char *mac;
    uint32_t ip;

    /Get time now in second/
    time_t current_time;
    time(&current_time);
    if(current_time == -1){
        printf("Error time retrive\n");
        return;
    }
    
    /Check if no ARP request/
    if(req->sent == 0){
        printf("ARP request never sent\n");
        return;
    }

    /Handle sending ARP request/
    if(difftime(current_time, req->sent) >= 1.0){
        if(req->times_sent >= 5){ 
            /*req->times_sent = 0; */

            /send icmp host unreachable/
            sr_send_icmp(sr, packet, len, interface, 3, 1);
            sr_arpreq_destroy(&(sr->cache), req);
        }
        else{
            /send arp request/
            send_arp_request(sr, packet, len, interface);

            /handle arp reply give us IP->MAC mapping/
            sr_arp_hdr_t *arp_hdr = 0;
            arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
            if(arp_hdr->ar_op == htons(arp_op_reply))
            {
                mac = arp_hdr->ar_sha;
                ip = arp_hdr->ar_sip;
                /insert arp reply to cache/
                req = sr_arpcache_insert(&(sr->cache), mac, ip);
                if(req)
                {
                    while(req->packets)
                    {
                        /send all packets on req->packets in linked list/
                        sr_send_packet(sr, req->packets->buf, req->packets->len, req->packets->iface);
                        req->packets = req->packets->next;
                    }
                    sr_arpreq_destroy(&(sr->cache), req);
                }
            }
            req = req->next;
            req->sent = current_time;
            req->times_sent++;
        }
    }
}
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */

    /after check match prefix longest match is valid then check arp cache/
        /lookup ip->mac mapping in cache entry/
            /if it has then send the packet and free entry/
            /if not then add request to queue, add packet to queue/
                /*handle arp request, save the next pointer before calling function
                handle_arpreq*/
                    /*send >5 time arp request then send icmp host unreachable
                    to all packets on arp request*/
                    /handle if it has arp reply: move entry from queue to cache/
                        /send packets on req->packets linked list and destroy arpreq/

    struct sr_arpreq* req = (struct sr_arpreq*)calloc(1, sizeof(struct sr_arpreq));
    struct sr_arpreq next_req = (struct sr_arpreq)calloc(1, sizeof(struct sr_arpreq));
    next_req = NULL;

    while(sr->cache.requests)
    {
        uint32_t ip = sr->cache.requests->ip;
        struct sr_arpentry* entry = (struct sr_arpentry*)calloc(1, sizeof(struct sr_arpentry));
        entry = sr_arpcache_lookup(&(sr->cache), ip);    


        /if have entry in cache ip->mac mapping/
        if(entry)
        {
            /have ip->mac mapping then send all packets/
            while(sr->cache.requests->packets)
            {   
                uint8_t* packet = sr->cache.requests->packets->buf;
                unsigned int len = sr->cache.requests->packets->len;
                char *iface = sr->cache.requests->packets->iface;
                if(sr_send_packet(sr, packet, len, iface) != 0)
                {
                    fprintf(stderr, "fail to send packet with entry\n");
                }
                sr->cache.requests->packets = sr->cache.requests->packets->next;
            }
            free(entry);
        }
        else{
            
            req = sr_arpcache_queuereq(&(sr->cache), ip, sr->cache.requests->packets->buf, 
                    sr->cache.requests->packets->len, sr->cache.requests->packets->iface);
            if(next_req != NULL)
            {
                req = next_req;
            }
            next_req = req->next;
            handle_arpreq(sr, req, req->packets->buf, req->packets->len, req->packets->iface);
        }
        sr->cache.requests = sr->cache.requests->next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t packet,           / borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}
         
/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}