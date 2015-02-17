#ifndef _MAAP_H
#define _MAAP_H

#include <linux/types.h>

/* Message Type */
#define rsv0		0
#define MAAP_PROBE	1
#define MAAP_DEFEND	2
#define MAAP_ANNOUNCE	3
#define rsv4		4
#define rsv5		5

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
  	uint8_t		requested_count[2];
  	uint8_t		conflict_start_address[6];
  	uint8_t		conflict_count[2];
}






#endif
