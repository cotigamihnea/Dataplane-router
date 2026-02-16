#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "list.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define ICMP_ECHO        8
#define ICMP_ECHOREPLY   0
#define INTERFACE_COUNT 4
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#define ETHERTYPE_ARP 0x0806

// declarare route table
struct route_table_entry *rtable;
int rtable_len = 0;

// structura trie
struct trie_node {
	struct trie_node *children[2];
	struct route_table_entry *route;
};
struct trie_node *trie_root = NULL;

// declarare ARP table
struct arp_table_entry *arp_table;
int arp_table_len = 0;

// structura folosita pentru pachete
struct packet_queue_entry {
	char buf[MAX_PACKET_LEN];
	size_t len;
	int interface;
	uint32_t next_hop;
};
queue packet_queue;

// inserez ruta in arbore
void insert_route(struct route_table_entry *entry) {
	struct trie_node *node = trie_root;
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);
	int prefix_len = __builtin_popcount(mask);
	for (int i = 31; i >= 32 - prefix_len; i--) {
		int bit = (prefix >> i) & 1;
		if (!node->children[bit]) {
			node->children[bit] = calloc(1, sizeof(struct trie_node));
		}
		node = node->children[bit];
	}
	node->route = entry;
}

// LPM eficient prin trie
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct trie_node *node = trie_root;
	struct route_table_entry *best = NULL;
	ip_dest = ntohl(ip_dest);

	for (int i = 31; i >= 0; i--) {
		if (!node) break;
		if (node->route) best = node->route;
		int bit = (ip_dest >> i) & 1;
		node = node->children[bit];
	}
	return best;
}

// protocolul ICMP
void send_icmp_error(char *buf, size_t len, size_t interface, uint8_t type) {
	char icmp_buf[MAX_PACKET_LEN];
	struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	size_t icmp_len = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;

	/* construiesc un pachet nou pentru a evita modificarea pachetului original,
	lucru care ar putea duce la probleme de suprascriere, de aceea il evit */
	struct ether_hdr *new_eth_hdr = (struct ether_hdr *) icmp_buf;
	struct ip_hdr *new_ip_hdr = (struct ip_hdr *)(icmp_buf + sizeof(struct ether_hdr));
	struct icmp_hdr *new_icmp_hdr = (struct icmp_hdr *)(icmp_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	get_interface_mac(interface, new_eth_hdr->ethr_shost);
	new_eth_hdr->ethr_type = htons(ETHERTYPE_IP);

	// initializea lui
	new_ip_hdr->tos = 0;
	new_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	new_ip_hdr->id = htons(4);
	new_ip_hdr->frag = htons(0);
	new_ip_hdr->ttl = 64;
	new_ip_hdr->proto = IPPROTO_ICMP;
	new_ip_hdr->checksum = 0;
	new_ip_hdr->source_addr = ip_hdr->dest_addr;
	new_ip_hdr->dest_addr = ip_hdr->source_addr;
	new_ip_hdr->checksum = checksum((uint16_t *)new_ip_hdr, sizeof(struct ip_hdr));

	new_icmp_hdr->mtype = type;
	new_icmp_hdr->mcode = 0;
	new_icmp_hdr->check = 0;
	memcpy(new_icmp_hdr + 1, ip_hdr, sizeof(struct ip_hdr) + 8);
	new_icmp_hdr->check = checksum((uint16_t *)new_icmp_hdr, icmp_len);

	// trimiterea erorii
	send_to_link(icmp_len + sizeof(struct ether_hdr), icmp_buf, interface);
}

void send_icmp_echo_reply(char *buf, size_t len, size_t interface) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// initializarea raspunsului
	icmp_hdr->mtype = ICMP_ECHOREPLY;
	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

	// aici schimb adresele IP pentru a sti unde sa trimit raspunsul
	uint32_t temp_ip = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = temp_ip;

	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	uint8_t temp_mac[6];
	memcpy(temp_mac, eth_hdr->ethr_shost, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	memcpy(eth_hdr->ethr_dhost, temp_mac, 6);

	// trimiterea reply-ului ICMP
	send_to_link(len, buf, interface);
}

// protocolul ARP
void send_arp_request(uint32_t target_ip, int interface) {
	char buf[MAX_PACKET_LEN];
	struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *) (buf + sizeof(struct ether_hdr));

	get_interface_mac(interface, eth_hdr->ethr_shost);
	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	eth_hdr->ethr_type = htons(ETHERTYPE_ARP);

	// initializarea pachetului ARP
	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(ETHERTYPE_IP);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1);
	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	memset(arp_hdr->thwa, 0, 6);
	arp_hdr->tprotoa = target_ip;

	// trimiterea pachetului ARP
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
}

void handle_arp_request(char *buf, size_t len, int interface) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	// verific daca adresa IP tinta este egala cu una din interfetele routerului
	for (int i = 0; i < INTERFACE_COUNT; i++) {
		if (arp_hdr->tprotoa == inet_addr(get_interface_ip(i))) {
			char reply_buf[MAX_PACKET_LEN];
			struct ether_hdr *reply_eth_hdr = (struct ether_hdr *)reply_buf;
			struct arp_hdr *reply_arp_hdr = (struct arp_hdr *)(reply_buf + sizeof(struct ether_hdr));

			memcpy(reply_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
			get_interface_mac(interface, reply_eth_hdr->ethr_shost);
			reply_eth_hdr->ethr_type = htons(ETHERTYPE_ARP);

			// initializarea reply-ului ARP
			reply_arp_hdr->hw_type = htons(1);
			reply_arp_hdr->proto_type = htons(ETHERTYPE_IP);
			reply_arp_hdr->hw_len = 6;
			reply_arp_hdr->proto_len = 4;
			reply_arp_hdr->opcode = htons(2);
			get_interface_mac(interface, reply_arp_hdr->shwa);
			reply_arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
			memcpy(reply_arp_hdr->thwa, arp_hdr->shwa, 6);
			reply_arp_hdr->tprotoa = arp_hdr->sprotoa;

			// trimiterea reply-ului ARP
			send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), reply_buf, interface);
			return;
		}
	}
}

void handle_arp_reply(char *buf) {
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	/* aici este cache-ul ARP, unde verific daca adresa IP este deja inregistrata,
	iar daca nu este, o aduag */
	int found = 0;
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == arp_hdr->sprotoa) {
			found = 1;
			break;
		}
	}
	if (!found) {
		arp_table[arp_table_len].ip = arp_hdr->sprotoa;
		memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
		arp_table_len++;
	}

	// coada temporara pentru pachetele care asteapta raspunsul ARP
	queue temp_queue = create_queue();

	while (!queue_empty(packet_queue)) {
		struct packet_queue_entry *entry = (struct packet_queue_entry *) queue_deq(packet_queue);
		if (entry->next_hop == arp_hdr->sprotoa) {
			// am gasit adresa
			struct ether_hdr *eth_hdr_fwd = (struct ether_hdr *) entry->buf;
			get_interface_mac(entry->interface, eth_hdr_fwd->ethr_shost);
			memcpy(eth_hdr_fwd->ethr_dhost, arp_hdr->shwa, 6);
			// trimiterea pachetului
			send_to_link(entry->len, entry->buf, entry->interface);
			free(entry);
		} else {
			// pachetul nu este destinat adresei, il mut in coada temporara
			queue_enq(temp_queue, entry);
		}
	}

	// aici mut pachetele care nu au fost trimise in coada principala
	while (!queue_empty(temp_queue)) {
		struct packet_queue_entry *entry = (struct packet_queue_entry *) queue_deq(temp_queue);
		queue_enq(packet_queue, entry);
	}
	free(temp_queue);
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];
	init(argv + 2, argc - 2);

	// coada pentru pachetele care asteapta raspunsul ARP
	packet_queue = create_queue();

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = malloc(sizeof(struct arp_table_entry) * 1000);
	DIE(arp_table == NULL, "memory");

	// citirea route table-ului
	rtable_len = read_rtable(argv[1], rtable);
	trie_root = calloc(1, sizeof(struct trie_node));
	for (int i = 0; i < rtable_len; i++) {
		insert_route(&rtable[i]);
	}

	while (1) {
		size_t interface, len;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv");

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

		// daca protocolul pachetului este ARP
		if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_ARP) {
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			if (ntohs(arp_hdr->opcode) == 1) { 
				// vorbim despre un ARP request
				handle_arp_request(buf, len, interface);
			} else if (ntohs(arp_hdr->opcode) == 2) { 
				// vorbim despre un ARP reply
				handle_arp_reply(buf);
			}
			continue;
		}

		// daca protocolul pachetului este IPv4
		if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_IP) {
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			uint16_t check = ip_hdr->checksum;
			ip_hdr->checksum = 0;
			uint16_t newcheck = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
			// verific checksum-ul!!!
			if (check != htons(newcheck)) continue;

			struct route_table_entry *best = get_best_route(ip_hdr->dest_addr);
			if (!best) {
				// nu am gasit ruta
				send_icmp_error(buf, len, interface, ICMP_DEST_UNREACH);
				continue;
			}

			if (ip_hdr->ttl <= 1) {
				// TTL-ul a expirat
				send_icmp_error(buf, len, interface, ICMP_TIME_EXCEEDED);
				continue;
			}

			uint32_t interface_ip = inet_addr(get_interface_ip(interface));
			if (ip_hdr->dest_addr == interface_ip) {
				// routerul da un raspuns
				send_icmp_echo_reply(buf, len, interface);
				continue;
			}
			ip_hdr->ttl--;
			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			// aici verific daca adresa MAC este cunoscuta
			int found_mac = 0;
			uint8_t mac[6];
			for (int i = 0; i < arp_table_len; i++) {
				if (arp_table[i].ip == best->next_hop) {
					memcpy(mac, arp_table[i].mac, 6);
					found_mac = 1;
					break;
				}
			}

			if (!found_mac) {
				// adresa MAC nu este cunoscuta, trimit ARP request
				send_arp_request(best->next_hop, best->interface);

				// pachetul este adaugat in coada de asteptare
				struct packet_queue_entry *entry = malloc(sizeof(struct packet_queue_entry));
				memcpy(entry->buf, buf, len);
				entry->len = len;
				entry->interface = best->interface;
				entry->next_hop = best->next_hop;
				queue_enq(packet_queue, entry);
				continue;
			}

			get_interface_mac(best->interface, eth_hdr->ethr_shost);
			memcpy(eth_hdr->ethr_dhost, mac, 6);
			// aici se face trimiterea
			send_to_link(len, buf, best->interface);
		}
	}
}
