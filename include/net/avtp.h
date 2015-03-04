#ifndef _AVTP_CTR_H
#define _AVTP_CTR_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <net/ptp.h>
#include <net/eth.h>
#include <net/maap.h>


// AVTP subtype values
#define IIDC_66883_SUBTYPE	0x00
#define MMA_SUBTYPE		0x01
#define MAAP			0x7E
#define EXPERIMENTAL_SUBTYPE	0x7F

/*
struct avtp_common_hdr{

  	uint8_t		d_type;
  //	unsigned	cd		:	1;
  //	unsigned	subtype		: 	7;
  	unsigned	sv		: 	1;
	unsigned	version		: 	3;
  	unsigned 	type_speci_data	:	20;
	u64		stream_id;
	unsigned char	*ctr_data_payload;    
};
*/

struct avtp_ctr_hdr{
	unsigned	cd		:	1;
  	unsigned	subtype		: 	7;
  	unsigned	sv		: 	1;
	unsigned	version		: 	3;
	unsigned	ctr_data	: 	4;
	unsigned	status		: 	5;
	unsigned	ctr_data_len	: 	11;
	u64		stream_id;
	unsigned char	*ctr_data_payload;       
};

struct avtp_maap_hdr{
  	uint8_t		d_type;
  //unsigned	cd		:	1;
  //unsigned 	subtype		:	7;

  	uint8_t		sv_ver_m_type;
  //unsigned	sv		:	1;
  //unsigned	version		:	3;
  //unsigned	message_type	:	4;

  	uint16_t	mver_mlen;
  //unsigned	maap_version	:	5;
  //unsigned	maap_data_length:	11;

  	uint8_t		stream_id[8];
  //  	u64		stream_id;
	uint8_t		requested_start_address[6];
  	uint16_t	requested_count;
  	uint8_t		conflict_start_address[6];
  	uint16_t	conflict_count;
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
	u64		stream_id;
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	stream_data_length;
  	uint16_t	protocol_specific_header;
	unsigned char	*stream_data_payload;
};

struct avtp_mma_hdr{
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
	u64		stream_id;
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	packet_data_length;
  	uint16_t	mma_payload_form_version;
	unsigned char	*mma_data_payload;
};

struct avtp_iidc_str_hdr{
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
	u64		stream_id;
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	stream_data_length;
  	unsigned	tag		:	2;
  	unsigned	channel		:	6;
  	unsigned	tcode		:	4;
  	unsigned	sy		:	4;
	unsigned char	*video_data_payload;
};

struct avtp_iec_str_hdr{
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
	u64		stream_id;
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	stream_data_length;
  	unsigned	tag		:	2;
  	unsigned	channel		:	6;
  	unsigned	tcode		:	4;
  	unsigned	sy		:	4;
  	unsigned	first_qi	:	2;
  	unsigned	sid		:	6;
  	uint8_t		dbs;
  	unsigned	fn		:	2;
  	unsigned	qpc		:	3;
  	unsigned 	sph		:	1;
  	unsigned 	rsv		:	2;
  	uint8_t 	dbc;
  	unsigned 	second_qi	:	2;
  	unsigned 	fmt		:	6;
  	unsigned 	fdf		:	8;
  	uint16_t 	syt;
	unsigned char	*cip_packet_data;
};

struct avtp_iec_str_hdr_sph{
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
	u64		stream_id;
  	uint32_t	avtp_timestamp;
  	uint32_t	gateway_info;
  	uint16_t	stream_data_length;
  	unsigned	tag		:	2;
  	unsigned	channel		:	6;
  	unsigned	tcode		:	4;
  	unsigned	sy		:	4;
  	unsigned	first_qi	:	2;
  	unsigned	sid		:	6;
  	uint8_t		dbs;
  	unsigned	fn		:	2;
  	unsigned	qpc		:	3;
  	unsigned 	sph		:	1;
  	unsigned 	rsv		:	2;
  	uint8_t 	dbc;
  	unsigned 	second_qi	:	2;
  	unsigned 	fmt		:	6;
  	unsigned 	fdf		:	24;
  	uint32_t	avbtp_src_packet_hdr_tstamp;
	unsigned char	*source_packet_data_tstamps;
};



// need to check if this is used or not
// later, these may be united

/*
static inline struct avtp_common_hdr *avtp_common_hdr(const struct sk_buff *skb) {
  	return (struct avtp_common_hdr *)skb_network_header(skb); 
}
*/
static inline struct avtp_ctr_hdr *avtp_ctr_hdr(const struct sk_buff *skb) {
  	return (struct avtp_ctr_hdr *)skb_network_header(skb); 
}
static inline struct avtp_str_hdr *avtp_str_hdr(const struct sk_buff *skb) {
  	return (struct avtp_str_hdr *)skb_network_header(skb); 
}
static inline struct avtp_maap_hdr *avtp_maap_hdr(const struct sk_buff *skb) {
  	return (struct avtp_maap_hdr *)skb_network_header(skb); 
}


// need to check if this is used or not
static inline int avtp_ctr_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_ctr_hdr);
	}
}
static inline int avtp_str_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_str_hdr);
	}
}
static inline int avtp_maap_hdr_len(struct net_device *dev) {
  	switch(dev->type) {
	default:
	  return sizeof(struct avtp_maap_hdr);
	}
}

extern void avtp_init(void);

extern struct sk_buff* avtp_create(struct avtp_maap_hdr *avtp_maap,
			    	struct net_device *dev,
			    	const unsigned char* src_hw,
				const unsigned char* dest_hw);

int avtp_timer_init_module(void);
void avtp_timer_cleanup_module(void);
void avtp_timer_callback(unsigned long arg);

static inline bool is_ctr_avtp_packet(const u8* addr){
  	return 0x80 & addr[0];
}

static inline unsigned char identify_avtp_packet(const u8* addr){
  	return 0x7F & addr[0];
}

#endif
