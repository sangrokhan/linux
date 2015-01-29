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

#endif
