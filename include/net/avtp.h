#ifndef _AVTP_CTR_H
#define _AVTP_CTR_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <net/ptp.h>
#include <net/eth.h>

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
  	unsigned 	type_speci_data	:	20;
	uint8_t		stream_id[8];
};

struct avtp_ctr_hdr{
	unsigned	cd		:	1;
  	unsigned	subtype		: 	7;
  	unsigned	sv		: 	1;
	unsigned	version		: 	3;
	unsigned	ctr_data	: 	4;
	unsigned	status		: 	5;
	unsigned	ctr_data_len	: 	11;
	uint8_t		stream_id[8];
	unsigned char	*ctr_data_payload;       
};

struct avtp_str_hdr{
	unsigned	cd		:	1;
  	unsigned	subtype		: 	7;
  	unsigned	sv		: 	1;
	unsigned	version		: 	3;
	unsigned	mr		:	1;
	unsigned	r		:	1;
  	unsigned	gv		:	1;
  	unsigned	tv		:	1;
  	uint8_t		sequence_num;
  	unsigned	reserved	:	7;
  	unsigned	tu		:	1;
	uint8_t		stream_id[8];
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	stream_data_length;
  	uint16_t	protocol_specific_header;
	unsigned char	*stream_data_payload;
};

struct avtp_maap_hdr{
	unsigned	cd		:	1;
	unsigned 	subtype		:	7;
	unsigned	sv		:	1;
	unsigned	version		:	3;
	unsigned	message_type	:	4;
	unsigned	maap_version	:	5;
	unsigned	maap_data_length:	11;
  	uint8_t		stream_id[8];
	uint8_t		requested_start_address[6];
  	uint16_t	requested_count;
  	uint8_t		conflict_start_address[6];
  	uint16_t	conflict_count;
};

// need to check if this is used or not
// later, these may be united
static inline struct avtp_common_hdr *avtp_common_hdr(const struct sk_buff *skb) {
  	return (struct avtp_common_hdr *)skb_network_header(skb); 
}
static inline struct avtp_ctr_hdr *avtp_ctr_hdr(const struct sk_buff *skb) {
  	return (struct avtp_ctr_hdr *)skb_network_header(skb); 
}
static inline struct avtp_str_hdr *avtp_str_hdr(const struct sk_buff *skb) {
  	return (struct avtp_str_hdr *)skb_network_header(skb); 
}
static inline struct avtp_maap_hdr *avtp_maap_hdr(const struct sk_buff *skb) {
  	return (struct avtp_maap_hdr *)skb_network_header(skb); 
}


/*
 * need to check if this is used or not
 * what is dev-> addr_len ?
 * later, this two may be united
 * why dev->addr_len and sizeof(u32) need to be multiplied 2 times
 */
static inline int avtp_ctr_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_ctr_hdr) + (dev->addr_len + sizeof(u32)) * 2;
	}
}
static inline int avtp_str_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_str_hdr) + (dev->addr_len + sizeof(u32)) * 2;
	}
}
static inline int avtp_maap_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_maap_hdr) + (dev->addr_len + sizeof(u32)) * 2;
	}
}

extern void avtp_init(void);

extern struct sk_buff* avtp_create(uint8_t type,
			    unsigned message_type,
			    struct net_device *dev,
			    const uint8_t* req_start_addr,
			    uint16_t req_count,
			    const uint8_t* conflict_start_addr,
			    uint16_t conflict_count,
			    const unsigned char* src_hw,
				   const unsigned char* dest_hw);

#endif
