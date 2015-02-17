#ifndef _AVTP_CTR_H
#define _AVTP_CTR_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <time.h>
#include <ktime.h>
#include <ptp.h>

/*
// MAC Address Acquisition Protocol message types
#define MAAP_PROBE 1	// probe MAC address PDU
#define MAAP_DEFEND 2	// defend address response PDU
#define MAAP_ANNOUNCE 3	// announce MAC address acquired PDU
*/


// AVTP subtype values
#define IIDC_66883_SUBTYPE	0x00
#define MMA_SUBTYPE		0x01
#define MAAP			0x7E
#define EXPERIMENTAL_SUBTYPE	0x7F

struct avtp_common_hdr{
	unsigned	cd		:	1;
  	unsigned	subtype		: 	7;
  	unsigned	sv		: 	1;
	unsigned	version		: 	3;
	uint8_t		stream_id[8];
};

struct avtp_ctr_hdr{
  	avtp_common_hdr	common_hdr;     
	unsigned	ctr_data	: 	4;
	unsigned	status		: 	5;
	unsigned	ctr_data_len	: 	11;
};

struct avtp_str_hdr{
  	avtp_common_hdr	common_hdr;
	unsigned	mr		:	1;
	unsigned	r		:	1;
  	unsigned	gv		:	1;
  	unsigned	tv		:	1;
  	uint8_t		sequence_num;
  	unsigned	reserved	:	7;
  	unsigned	tu		:	1;
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	stream_data_length;
  	uint16_t	protocol_specific_header;
	unsigned char	*stream_data_payload;
};

/*
static inline struct avtp_ctr_hdr *avtp_ctr_hdr(const struct sk_buff *skb) {
  	return (struct avtp_ctr_hdr *)skb_network_header(skb); 
}
*/

/*
 * need to check hdr size
 * why dev->addr_len and sizeof(u32) need to be multiplied 2 times
 */
static inline int avtp_ctr_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_ctr_hdr) + (dev->addr_len + sizeof(u32)) * 2;
	}
}


#endif
