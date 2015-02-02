#ifndef _COMSTACK_TYPES_H
#define _COMSTACK_TYPES_H

#include <linux/types.h>
#include <linux/std_types.h>
#include <net/comstack_cfg.h>

typedef struct {
  uint8_t* 	SduDataPtr;
  PduLengthType sduLength;
} PduInfoType;

typedef uint8_t PNCHandleType;

typedef enum {
  TP_STMIN = 0x00,
  TP_BS,
  TP_BC
} TPParameterType;

typedef enum {
  BUFREQ_OK,
  BUFREQ_E_NOT_OK,
  BUFREQ_E_BUSY,
  BUFREQ_E_OVFL
} BufReq_ReturnType;

typedef uint8_t BusTrcvErrorType;

#define BUSTRCV_OK	0x00
#define BUSTRCV_E_ERROR 0x01

typedef enum {
  TP_DATACONF = 0x00,
  TP_DATARETRY,
  TP_CONFPENDING
} TpDataStateType;

typedef struct {
  TpDataStateType	TpDataState;
  PduLengthType		TxTpDataCnt;
} RetryInfoType;

typedef uint8_t NetworkHandleType;

typedef uint8_t IcomConfigIdType;

typedef enum {
  ICOM_SWITCH_E_OK,
  ICOM_SWITCH_E_FAILED
} IcomSwitch_ErrorType;

#endif
