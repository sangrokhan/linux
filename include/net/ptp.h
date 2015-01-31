#ifndef _PTP_H
#define _PTP_H

#include <linux/types.h>
#include <linux/kernel.h>

struct ptphdr{
  unsigned 	messageType		:	4;
  unsigned 	transportSpecific	:	4;
  unsigned 	versionPTP		:	4;
  unsigned 	reserved		:	4;
  uint16_t 	messageLength;
  uint8_t	domainNumber;
  uint8_t	domainNumberrsv;
  uint16_t	flags;
  uint8_t	correctionField[8];
  uint8_t	Fieldrsv[4];
  uint8_t	sourcePortIdentity[10];
  uint16_t	sequenceId;
  uint8_t	control;
  uint8_t	logMessageInterval;
};

static inline struct ptphdr *ptp_hdr(const struct sk_buff *skb) {
  return (struct ptphdr *)skb_network_header(skb); 
}

/*
 * need to check hdr size
 * why dev->addr_len and sizeof(u32) need to be multiplied 2 times
 */
static inline int ptp_hdr_len(struct net_device *dev) {
  switch(dev->type) {
  default:
    return sizeof(struct ptphdr) + (dev->addr_len + sizeof(u32)) * 2;
  }
}

#endif
