#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/posix-clock.h>
#include <linux/std_types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/ptp.h>
#include <net/eth_generaltypes.h>
#include <net/eth.h>
#include <net/ethif.h>


static struct packet_type stbm_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_1588),
	.func = Eth_Receive_linux,
};

//EthCtrlConfig
bool		EthCtrlEnableMii;
bool		EthCtrlEnableRxInterrupt;
bool		EthCtrlEnableTxInterrupt;
uint8_t		EthCtrlIdx;
uint8_t*	EthCtrlPhyAddress;
#define MAX_ETH_PHY_ADDR_LENTH 17
uint16_t	EthCtrlRxBufLenByte;
uint16_t 	EthCtrlTxBufLenByte;
uint8_t		EthRxBufTotal;
uint8_t		EthTxBufTotal;

//EthGeneral
bool		EthDevErrorDetect;
bool		EthGetDropCountApi;
bool		EthGetEtherStatsApi;
bool		EthGlobalTimeSupport;
uint8_t		EthIndex;
uint32_t 	EthMainFunctionPeriod; /* Standard using floating point to present from 0 to INF */
uint8_t		EthMaxCtrlsSupported;
bool		EthUpdatePhysAddrFilter;
bool		EthVersionInfoApi;

struct timespec EthCurrTime;
struct timespec	EthRxTime;
struct timespec	EthTxTime;

void 			Eth_Init(const Eth_ConfigType* CfgPtr) {
  	EthCtrlEnableMii = false;
	EthCtrlEnableRxInterrupt = false;
	EthCtrlEnableTxInterrupt = false;
	EthCtrlIdx = 0;
	EthCtrlPhyAddress = NULL;
	EthCtrlRxBufLenByte = 0;
	EthCtrlTxBufLenByte = 0;
	EthRxBufTotal = 0;
	EthTxBufTotal = 0;

	EthDevErrorDetect = false;
	EthGetDropCountApi = false;
	EthGetEtherStatsApi = false;
	EthGlobalTimeSupport = false;
	EthIndex = 0;
	EthMainFunctionPeriod = 0;
	EthMaxCtrlsSupported = 0;
	EthUpdatePhysAddrFilter = false;
	EthVersionInfoApi = false;

	dev_add_pack(&stbm_packet_type);
}

Std_ReturnType		Eth_ControllerInit(uint8_t CtrlIdx, 
					   uint8_t CfgIdx) {
  
  return E_OK;
}

Std_ReturnType		Eth_SetControllerMode(uint8_t CtrlIdx, 
					      Eth_ModeType CtrlMode) {

  return E_OK;
}

Std_ReturnType		Eth_GetControllerMode(uint8_t CtrlIdx, 
					      Eth_ModeType* CtrlModePtr) {

  return E_OK;
}

void			Eth_GetPhysAddr(uint8_t CtrlIdx, 
					uint8_t* PhysAddrPtr) {

}

void 			Eth_SetPhysAddr(uint8_t CtrlIdx,
					const uint8_t* PhysAddrPtr) {

}

Std_ReturnType		Eth_UpdatePhyAddrFilter(uint8_t CtrlIdx, 
						uint8_t* PhysAddrPtr, 
						Eth_FilterActionType Action) {
  return E_OK;
}

Std_ReturnType		Eth_WriteMii(uint8_t CtrlIdx, 				       
				     uint8_t TrcvIdx,
 				     uint8_t RegIdx, 
				     uint16_t RegVal) {
  return E_OK;
}

Std_ReturnType		Eth_ReadMii(uint8_t CtrlIdx, 				    
				    uint8_t TrcvIdx,
				    uint8_t RegIdx, 
				    uint16_t* RegValPtr) {
  return E_OK;
}

Std_ReturnType		Eth_GetDropCount(uint8_t CtrlIdx,
 					 uint8_t CountValues,
 					 uint32_t* DropCount) {
  return E_OK;
}

Std_ReturnType		Eth_GetEtherStats(uint8_t CtrlIdx, 
					  uint32_t* etherStats) {
  return E_OK;
}

/* Service ID 0x16 */
Std_ReturnType		Eth_GetCurrentTime(uint8_t CtrlIdx,
					   Eth_TimeStampQualType* timeQualPtr,
					   Eth_TimeStampType* timeStampPtr) {
  	//Linux Kernel Time Return
  	//Currently Eth Device Not Support time
  	getrawmonotonic(&EthCurrTime);
  	timeStampPtr->secondsHi = (uint16_t)((EthCurrTime.tv_sec & 0x0000FFFF00000000) >> 32);
	timeStampPtr->seconds = (uint32_t)(EthCurrTime.tv_sec & 0xFFFFFFFF);
	timeStampPtr->nanoseconds = EthCurrTime.tv_nsec;
	timeQualPtr = ETH_VALID;
  	return E_OK;
}

void			Eth_EnableEgressTimeStamp(uint8_t CtrlIdx,
						  uint8_t BufIdx) {

}

void 			Eth_GetEgressTimeStamp(uint8_t CtrlIdx,
					       uint8_t BufIdx,
					       Eth_TimeStampQualType* timeQualPtr,
					       Eth_TimeStampType* timeStampPtr) {

}

void			Eth_GetIngressTimeStamp(uint8_t CtrlIdx, 
						Eth_DataType* DataPtr, 
						Eth_TimeStampQualType* timeQualPtr, 
						Eth_TimeStampType* timeStampPtr) {

}

void			Eth_SetCorrectionTime(uint8_t CtrlIdx, 
					      Eth_TimeIntDiffType* timeOffsetPtr, 
					      Eth_RateRatioType* rateRatioPtr) {
  	//linux kernel time sync
  	//update
  	//slave 
}

Std_ReturnType		Eth_SetGlobalTime(uint8_t CtrlIdx, 
					  Eth_TimeStampType* timeStampPtr) {
	//linux kernel time setting
	//Os time only accessable
  	//grandmaster only 
	int ret;

	EthCurrTime.tv_sec = (long long)(timeStampPtr->secondsHi) << 32;
    	EthCurrTime.tv_sec += (timeStampPtr->seconds);
	EthCurrTime.tv_nsec = timeStampPtr->nanoseconds;
	ret = do_settimeofday(&EthCurrTime);
	if(ret) {
		return E_NOT_OK;
	} else {
		return E_OK;
	}
}

BufReq_ReturnType 	Eth_ProvideTxBuffer(uint8_t CtrlIdx, 
					    Eth_BufIdxType* BufIdxPtr, 
					    uint8_t** BufPtr, 
					    uint16_t* LenBytePtr) {
  return BUFREQ_OK;
}

Std_ReturnType		Eth_Transmit(uint8_t CtrlIdx, 
				     Eth_BufIdxType BufIdx, 
				     Eth_FrameType FrameType, 
				     bool TxConfirmation, 
				     uint16_t LenByte, 
				     uint8_t* PhysAddrPtr) {
  return E_OK;
}

void			Eth_Receive(uint8_t CtrlIdx, 
				    Eth_RxStatusType* RxStatusPtr) {
  
}

int			Eth_Receive_linux(struct sk_buff* skb, 
					  struct net_device* dev, 
					  struct packet_type* pt, 
					  struct net_device* orig_dev) {
	const struct ptphdr *ptp;
	
	skb = skb_share_check(skb, GFP_ATOMIC);
	if(!skb)
	  goto out_of_mem;
	
	
freeskb:
  	kfree_skb(skb);
out_of_mem:
  	return 0;
}

void			Eth_TxConfirmation(uint8_t CtrlIdx) {

}

void			Eth_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr) {

}

void			Eth_MainFunction(void) {

}


