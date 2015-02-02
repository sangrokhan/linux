#ifndef _PTP_H
#define _PTP_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/ktime.h>

#define SYN 0 /* Sync message */
#define PDELAY_REQ 2 /* Pdelay_Req message */
#define PDELAY_RESP 3 /* Pdelay_Resp message */
#define FOLLOW_UP 8 /* Follow_Up message */
#define PDELAY_RESP_FOLLOW_UP 10 /* Pdelay_Resp_Follow_Up message */

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
  ktime_t   timestamp;
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

struct portIdentity {
   uint8_t clockIdentity[8];
   uint8_t portNumber[4];
};

/*
struct SynMsg {
   ptphdr header;
   timespec originTimestamp;
};

struct FollowUpMsg {
   ptphdr header;
   timespec preciseOriginTimestamp;
};

struct PdelayReqMsg {
   ptphdr header;
   timespec originTimestamp;
   uint8_t reserved[10];
};

struct PdelayRespMsg {
   ptphdr header;
   timespec requestReceiptTimestamp;
   portIdentity requestingPortIdentity;
};

struct PdelayRespFollowUpMsg {
   ptphdr header;
   timespec responseOriginTimestamp;
   portIdentity requestingPortIdentity;
}; */

#endif
