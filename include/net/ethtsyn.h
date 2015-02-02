#ifndef _ETHTSYN_H
#define _ETHTSYN_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/stddef.h>
#include <net/eth.h>
#include <net/ethtrcv.h>
#include <net/stbm.h>

typedef enum {
   INITIALIZING = 1,
   FAULTY = 2,
   DISABLED = 3,
   LISTENING = 4,
   PRE_MASTER = 5,
   MASTER = 6,
   PASSIVE = 7,
   UNCALIBRATED = 8,
   SLAVE = 9
} EthTSyn_ConfigType;

typedef enum {
  	ETHTSYN_TX_OFF = 0,
	ETHTSYN_TX_ON
} EthTSyn_TransmissionModeType;

typedef enum {
	ETHTSYN_SYNC = 0,
	ETHTSYN_UNSYNC,
	ETHTSYN_UNCERTAIN,
	ETHTSYN_NEVERSYNC
} EthTSyn_SyncStateType;

typedef struct {
	unsigned Pdelay_Req		:	1;
	unsigned Pdelay_Resp		:	1;
  	unsigned Pdelay_Resp_Follow_Up	:	1;
  	unsigned Sync			:	1;
  	unsigned Follow_up		:	1;
  	unsigned rsv			:	3;
} EthTSyn_MessageType;

/* EthTSynGeneral */
extern bool EthTSynDevErrorDetect;
extern bool EthTSynHardwareTimestampSupport;
extern uint32_t EthTSynMainFunctionPeriod;	/* Standard using floating point to present INF */
extern bool EthTSynVersionInfo;
extern time_t EthTSynTime1, EthTSynTime2, EthTSynTime3, EthTSynTime4;

/* EthTSynGlobalTimeDomain */
extern uint32_t EthTSynGlobalTimeDomainId;
extern uint32_t EthTSynGlobalTimeFollowUpTimeout;
//extern Unknown EthTSynSynchronizedTimeBaseRef; /* Reference to StbMSynchronizedTimeBase */

/* EthTSynGlobalTimeMaster & EthTSynGlobalTimeSlave */
extern uint32_t EthTSynGlobalTimeTxFollowUpOffset; /* Standard using floating point to present INF */
extern uint32_t EthTSynGlobalTimeTxPdelayReqPeriod; /* Standard using floating point to present INF */
extern uint32_t EthTSynGlobalTimeTxPeriod; /* Standard using floating point to present INF */
//extern Unknown EthTSynGlobalTimeEthIfRef; /* Reference to EthIfController */

extern void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr);
extern void 		EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo);
extern Std_ReturnType 	EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId, 
					       StbM_TimeStampType* timeStampPtr,
					       EthTSyn_SyncStateType* syncState);
extern Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
					      StbM_TimeStampType* timeStampPtr);
extern Std_ReturnType	EthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
						    EthTSyn_TransmissionModeType Mode);
extern void		EthTSyn_RxIndication(uint8_t CtrlIdx,
				     Eth_FrameType FrameType,
				     bool IsBroadcast,
				     uint8_t* PhyAddrPtr,
				     uint8_t* DataPtr,
				     uint16_t LenByte);
extern void		EthTSyn_TxConfirmation(uint8_t CtrlIdx,
				       uint8_t BufIdx);
extern Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState);
extern void 		EthTSyn_MainFunction(void);

#endif
