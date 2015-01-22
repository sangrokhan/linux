#ifndef _ETHTRCV_H
#define _ETHTRCV_H

#include <linux/types.h>
#include <linux/std_types.h>

typedef struct {
  
} EthTrcv_ConfigType;

typedef enum {
  ETHTRCV_MODE_DOWN = 0x00,
  ETHTRCV_MODE_ACTIVE
} EthTrcv_ModeType;

typedef enum {
  ETHTRCV_LINK_STATE_DOWN = 0x00,
  ETHTRCV_LINK_STATE_ACTIVE
} EthTrcv_LinkStateType;

typedef enum {
  ETHTRCV_STATE_UNINIT = 0x00,
  ETHTRCV_STATE_INIT,
  ETHTRCV_STATE_ACTIVE
} EthTrcv_StateType;

typedef enum {
  ETHTRCV_BAUD_RATE_10MBIT = 0x00,
  ETHTRCV_BAUD_RATE_100MBIT,
  ETHTRCV_BAUD_RATE_1000MBIT
} EthTrcv_BaudRateType;

typedef enum {
  ETHTRCV_DUPLEX_MODE_HALF = 0x00, 
  ETHTRCV_DUPLEX_MODE_FULL
} EthTrcv_DuplexModeType;

typedef enum {
  ETHTRCV_WUM_DISABLE = 0x00,
  ETHTRCV_WUM_ENABLE,
  ETHTRCV_WUM_CLEAR
} EthTrcv_WakeupModeType;

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
