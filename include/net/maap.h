#ifndef _MAAP_H
#define _MAAP_H

#include <linux/types.h>

#define MAC_ADDR_LEN	6

/* Message Type */
#define RSV0		0
#define MAAP_PROBE	1
#define MAAP_DEFEND	2
#define MAAP_ANNOUNCE	3
#define RSV4		4
#define RSV5		5

/* State */
#define INITIAL		1
#define PROBE		2
#define DEFEND		3

struct maaphdr {
  	unsigned	cd			:	1;
  	unsigned	subtype			:	7;
  	unsigned	sv			:	1;
  	unsigned	version			:	3;
  	unsigned	message_type		:	4;
  	unsigned	maap_version		:	5;
  	unsigned	maap_data_length	:	11;
  	uint8_t		stream_id[8];
  	uint8_t		requested_start_address[6];
  	u16		requested_count;
  	uint8_t		conflict_start_address[6];
  	u16		conflict_count;
};

void generate_address(unsigned char* requestor_address);

void init_maap_probe_count(void);

void dec_maap_probe_count(void);

int compare_MAC(unsigned char* current_mac_address, unsigned char* received_mac_address);

void sProbe(void);

void sDefend(struct maaphdr *rcv_maap);

void sAnnounce(void);

static int maap_rcv(struct maaphdr *rcv_maap);

int maap_init_timer(struct timer_list *timer, void (*function)(void), int second, int millisecond);
void maap_cleanup_timer(struct timer_list *timer);


#endif
