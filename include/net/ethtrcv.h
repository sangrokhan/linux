#ifndef _ETHTRCV_H
#define _ETHTRCV_H

#include <linux/types.h>
#include <linux/std_types.h>
#include <net/eth_generaltypes.h>

typedef enum {
  ETHTRCV_STATE_UNINIT = 0x00,
  ETHTRCV_STATE_INIT,
  ETHTRCV_STATE_ACTIVE
} EthTrcv_StateType;

typedef enum {
  ETHTRCV_WUR_NONE = 0x00,
  ETHTRCV_WUR_BUS,
  ETHTRCV_WUR_INTERNAL,
  ETHTRCV_WUR_RESET,
  ETHTRCV_WUR_POWER_ON,
  ETHTRCV_WUR_PIN,
  ETHTRCV_WUR_SYSERR
} EthTrcv_WakeupReasonType;

#endif
