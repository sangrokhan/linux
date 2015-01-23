#ifndef _ETH_GENERALTYPES_H
#define _ETH_GENERALTYPES_H

#include <linux/types.h>
#include <linux/std_types.h>

typedef uint32_t Eth_BufIdxType;
typedef uint16_t Eth_FrameType;
//based on cpu bit definition 
//Needo to be fixed for support 8bit CPU, 16bit CPU
typedef uint32_t Eth_DataType;

typedef struct {

} Eth_ConfigType;

typedef struct {
  
} EthTrcv_ConfigType;

typedef enum {
  ETH_ADD_TO_FILTER,
  ETH_REMOVE_FROM_FILTER
} Eth_FilterActionType;

typedef enum {
  ETH_MODE_DOWN,
  ETH_MODE_ACTIVE
} Eth_ModeType;

typedef struct {
  uint32_t nanoseconds;
  uint32_t seconds;
  uint16_t secondsHi;
} Eth_TimeStampType;

typedef struct {
  Eth_TimeStampType diff;
  bool sign;	//positive True / negative false
} Eth_TimeIntDiffType;

typedef struct {
  Eth_TimeIntDiffType IngressTimeStampDelta;
  Eth_TimeIntDiffType OriginTimeStampDelta;
} Eth_RateRatioType;

typedef enum {
  ETH_RECEIVED,
  ETH_NOT_RECEIVED,
  ETH_RECEIVED_MORE_DATA_AVAILABLE
} Eth_RxStatusType;

typedef enum {
  ETH_VALID, 
  ETH_INVALID,
  ETH_UNCERTAIN
} Eth_TimeStampQualType;

typedef enum {
  ETHTRCV_MODE_DOWN = 0x00,
  ETHTRCV_MODE_ACTIVE
} EthTrcv_ModeType;

typedef enum {
  ETHTRCV_LINK_STATE_DOWN = 0x00,
  ETHTRCV_LINK_STATE_ACTIVE
} EthTrcv_LinkStateType;

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



#endif
