#ifndef _PTP_H
#define _PTP_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <net/route.h>

#define SYN 0 /* Sync message */
#define PDELAY_REQ 2 /* Pdelay_Req message */
#define PDELAY_RESP 3 /* Pdelay_Resp message */
#define FOLLOW_UP 8 /* Follow_Up message */
#define PDELAY_RESP_FOLLOW_UP 10 /* Pdelay_Resp_Follow_Up message */

//typedef uint64_t Octet8;
typedef struct _ClockIdentity{
	unsigned char B0 : 8;
	unsigned char B1 : 8;
	unsigned char B2 : 8;
	unsigned char B3 : 8;
	unsigned char B4 : 8;
	unsigned char B5 : 8;
	unsigned char B6 : 8;
	unsigned char B7 : 8;
}ClockIdentity;

typedef struct _flagField {
   unsigned alternateMasterFlag  :  1;
   unsigned twoStepFlag :  1;
   unsigned unicastFlag :  1;
   unsigned noDefinition    :  2;    // The bit is not defined
   unsigned PTPprofileSpecific1  :  1;
   unsigned PTPprofileSpecific2  :  1;
   unsigned reserved    :  1;
   unsigned leap61   :  1;
   unsigned leap59   :  1;
   unsigned currentUtcOffsetValid   :  1;
   unsigned ptpTimescale   :  1;
   unsigned timeTraceable  :  1;
   unsigned frequencyTraceable   :  1;
   unsigned reservedForAnnexK    :  2;    // This bit is reserved for the experimental security mechanism of Annex K
}flagField;

typedef struct _portIdentity {
   ClockIdentity clockIdentity;
   uint16_t portNumber;
}portIdentity;

// * For example (about Timestamp),
// * +2,000000001 seconds is represented by seconds = 0x0000 0000 0002 and nanoseconds = 0x000 0001
 

typedef struct _Timestamp {
  uint8_t seconds[6];
  uint8_t nanoseconds[4];   // The nanoseconds member is always less than 10e9
}Timestamp;

struct ptphdr{
  unsigned 	messageType		:	4;
  unsigned 	transportSpecific	:	4;
  unsigned 	versionPTP		:	4;
  unsigned 	reserved		:	4;
  uint16_t 	messageLength;
  uint8_t	domainNumber;
  uint8_t	domainNumberrsv;
  flagField	flags;
  uint8_t	correctionField[8];
  uint8_t	Fieldrsv[4];
  portIdentity	sourcePortIdentity;
  uint16_t	sequenceId;
  uint8_t	control;
  uint8_t	logMessageInterval;
  Timestamp     timestamp;
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

/*
struct dst_entry {
   struct net_device *dev;
   int         (*input)(struct sk_buff *);
   int         (*output)(struct sk_buff *);

   unsigned short    flags;
#define DST_HOST     0x0001
#define DST_NOXFRM      0x0002
#define DST_NOPOLICY    0x0004
#define DST_NOHASH      0x0008
#define DST_NOCACHE     0x0010
#define DST_NOCOUNT     0x0020
#define DST_NOPEER      0x0040
#define DST_FAKE_RTABLE    0x0080
#define DST_XFRM_TUNNEL    0x0100
#define DST_XFRM_QUEUE     0x0200
};

struct rtable {
   struct dst_entry  dst;
};
*/

#endif
