#ifndef _ETH_GENERALTYPES_H
#define _ETH_GENERALTYPES_H

#include <linux/types.h>
#include <linux/std_types.h>

typedef struct {

} Eth_ConfigType;

enum {
  ETH_OK,
  ETH_E_NOT_OK,
  ETH_E_NO_ACCESS
} Eth_ReturnType;

enum {
  ETH_MODE_DOWN,
  ETH_MODE_ACTIVE
} Eth_ModeType;

enum {
  ETH_STATE_UNINIT,
  ETH_STATE_INIT,
  ETH_STATE_ACTIVE
} Eth_StateType;

typedef uint16_t Eth_FrameType;

//based on cpu bit definition 
//Needo to be fixed for support 8bit CPU, 16bit CPU
typedef uint32_t Eth_DataType;

typedef uint32_t Eth_BufIdxType;

enum {
  ETH_RECEIVED,
  ETH_NOT_RECEIVED,
  ETH_RECEIVED_MORE_DATA_AVAILABLE
} Eth_RxStatusType;

enum {
  ETH_ADD_TO_FILTER,
  ETH_REMOVE_FROM_FILTER
} Eth_FilterActionType;

enum {
  ETH_VALID, 
  ETH_INVALID,
  ETH_UNCERTAIN
} Eth_TimeStampQualType;

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



#endif
