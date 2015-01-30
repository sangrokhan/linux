
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/export.h>
#include <linux/std_types.h>
#include <net/stbm.h>
#include <net/ethtsyn.h>
#include <net/ethif.h>
#include <net/ptp.h>

bool EthTSynHardwareTimestampSupport;

Std_ReturnType hardwareRegisterTime;

Eth_TimeStampQualType* timeQualPtr;

Std_ReturnType globalTime;
Std_ReturnType currentTime;
Std_ReturnType currentTimeRaw;
Std_ReturnType timeDifferenceOfCurrentTimeRaw;

StbM_SynchronizedTimeBaseType timeBaseId;
StbM_TimeStampType*	timeStampPtr;
StbM_UserDataType* userDataPtr;
StbM_TimeStampRawType* timeStampRawPtr;
StbM_TimeStampRawType givenTimeStamp;
StbM_TimeStampRawType* timeStampDiffPtr;

EthTSyn_MessageType Type;

time_t temp, EthTSynTime1, EthTSynTime2, EthTSynTime3, EthTSynTime4;

static int ethtsyn_netdev_event(struct notifier_block *this, 
				unsgined long event, 
				void* ptr) {
  	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_change_info *change_info;

	switch(event) {
	default: 
	  break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block ethtsyn_netdev_notifier = {
  	.notifier_call = ethtsyn_netdev_notifier,
};

static struct packet_type ethtsyn_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_1588),
	.func = ,
};

static const struct file_operations ethtsyn_seq_fops = {
  	.owner = THIS_MODULE,
};

static int __net_init ethtsyn_net_init(struct net *net) {
  	if(!proc_create("ethtsyn", S_IRUGO, net->proc_net, &ethtsyn_seq_fops))
    		return -ENOMEM;
  	return 0;
}

static void __net_init ethtsyn_net_exit(struct net *net) {
  	remove_proc_entry("ethtsyn",net->proc_net);
}

static struct pernet_operations ethtsyn_net_ops = {
  	.init = ethtsyn_net_init,
  	.exit = ethtsyn_net_exit,
};

static int __init ethtsyn_proc_init(void) {
  	return register_pernet_subsys(&ethtsyn_net_ops);
}

static int ethtsyn_rcv(struct sk_buff* skb, 
		       struct net_device* dev, 
		       struct packet_type* pt, 
		       struct net_device* orig_dev) {
  	const struct ptphdr *ptp;
	
	skb = skb_share_check(skb, GFP_ATOMIC);
	if(!skb)
	  goto out_of_mem;
	
	//ptp = 
freeskb:
  	kfree_skb(skb);
out_of_mem:
  	return 0;
}

/* Initialize all internal variables and set the EthTSync module to init state */
void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr) {
  //When DET reporting is enabled EthTSyn module shall call DEt_ReportError() with the error code
  //ETHTSYN_E_NOT_INITIALIZED when any API is called in uninitialized state

  //After first initialized, when init function is called, reinitialize

  //rate correction -> 0
  //latency for ingress and egress to 0
  
   	switch(*configPtr) {
      		case 6 : // If configured as Time Master,
         // the StbM shall allow configuration of the initialization value of the Global Time Base.
         // The initialization value can be either a value from static configuration or a value from non-volatile memory.
         // StbM_SetGlobalTime();
         	break;
      		case 9 : // If configured as Time slave,
         // the StbM shall use the Local Time Base while no valid Global Time Base is available (e.g. at startup)
         //    - Startup with a defined Time Base.
         // the StbM shall initialize the Local Time Base with 0 at startup.
         //    - Startup with a network wide common Time Base value.
         // StbM_SetGlobalTime();
         	break;
	}

   	EthTSynHardwareTimestampSupport = false; //Hardware can't support timestamp on RaspberryPi

   	dev_add_pack(&ethtsyn_packet_type);
   	ethtsyn_proc_init();
	register_netdevice_notifier(ethtsyn_netdev_notifier);	   
}

/* Returns the version information of this module */
void 		EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo) {
   if(EthTSynVersionInfo == 0) {   // False : version information API deactivated
   } else {   // True : version information API activated
   }
}

/* Returns a time value according its definition out of the HW registers */
Std_ReturnType 	EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId,
				       StbM_TimeStampType* timeStampPtr,
				       EthTSyn_SyncStateType* syncState) {
   // hardwareRegisterTime = EthIf_GetCurrentTime(CtrlIdx, timeQualPtr, timeStampPtr);
   //if(timeQualPtr == ) {
   //} else {
   //}
  
   return E_OK;
}

/* Allows the Time Master to adjust the global ETH Reference clock in HW */
/* This method is used to set a Global Time Base on ETH in general or to synchronize the Global ETH Time Base with another time base, e.g. Ethernet */
Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				      StbM_TimeStampType* timeStampPtr) {
   uint8_t CtrlIdx;
   Eth_TimeStampType* ethTimeStampPtr = timeStampPtr;
   globalTime = EthIf_SetGlobalTime(CtrlIdx, ethTimeStampPtr);
   return globalTime;
}

/* This API is used to turn on and off the TX capabilities of the EthTSyn */
Std_ReturnType	EthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
					    EthTSyn_TransmissionModeType Mode) {
   if(Mode == ETHTSYN_TX_OFF) {
      /* All transmit request from EthTSyn shall be omitted on this Ethernet controller */
   }

   if(Mode == ETHTSYN_TX_ON) {
      /* All transmit request from EthTSyn on this Ethernet controller shall be able to be transmitted */
   }
   return E_OK;
}

/* By this API service the EthTSyn gets an indication and the data of a received frame */
void		EthTSyn_RxIndication(uint8_t CtrlIdx,
				     Eth_FrameType FrameType,
				     bool IsBroadcast,
				     uint8_t* PhyAddrPtr,
				     uint8_t* DataPtr,
				     uint16_t LenByte) {
   if(Type.Sync == 1 || Type.Pdelay_Req == 1 || Type.Pdelay_Resp == 1) {   // if(Type == Sync || Type == Pdelay_Req || Type == Pdelay_Resp) {
      if(EthTSynHardwareTimestampSupport == true) {
	     /* the time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
		 // EthIf_GetEgressTimeStamp(CtrlIdx, BufIdx, timeQualPtr, timeStampPtr);
      } else {
         if(Type.Pdelay_Req == 1) {   // if(Type == Pdelay_Req) {
	   currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr);
	 } else if(Type.Sync == 1 || Type.Pdelay_Req == 1) {   // else if(Type == Sync || Type == Pdelay_Req) {
	   currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr); // why??
	   
	   if(Type.Pdelay_Req == 1) {   // if(Type == Pdelay_Req) {
	     EthTSynTime2 = *timeStampRawPtr;
	   } else if(Type.Sync == 1) {// && Type == EthTimeGatewaySlavePort) {   // else if(Type == Sync || Type == EthTimeGatewaySlavePort) {
	     /* Start time stamp for correctionField(i) calculation of Time Aware Bridges */
	     // Tr,i = *timeStampRawPtr
	   } else if(Type.Pdelay_Resp == 1) {   // else if(Type == Pdelay_Resp) {
	     givenTimeStamp = EthTSynTime1;
	     
	     if((timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr)) == "E_OK") {
	       temp = EthTSynTime4 - EthTSynTime1;
	       timeStampDiffPtr = (StbM_TimeStampRawType*)&temp; /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
               }
		  	   }
		   }
	   }
   }
}

/* Confirms the transmission of an Ethernet frame */
void		EthTSyn_TxConfirmation(uint8_t CtrlIdx,
				       uint8_t BufIdx) {
   if(Type.Sync == 1 || Type.Pdelay_Req == 1 || Type.Pdelay_Resp == 1) {   // if(Type == Sync || Type == Pdelay_Req || Type == Pdelay_Resp) {
      if(EthTSynHardwareTimestampSupport == true) {
         /* the egress time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
		 /* the egress time stamp shall be retrieved for Sync from the EthIf */ // ??
         // EthIf_GetEgressTimeStamp(CtrlIdx, BufIdx, timeQualPtr, timeStampPtr);
      } else {    // In case EthTSynHardwareTimestamp is set to FALSE
         if(Type.Sync == 1 || Type.Pdelay_Resp == 1) {   // if(Type == Sync || Type == Pdelay_Resp) {
            currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr);
         } else if(Type.Pdelay_Req == 1) {   // else if(Type == Pdelay_Req) {
            if((currentTimeRaw = StbM_GetCurrentTimeRaw(timeStampRawPtr)) == "E_OK") {
               EthTSynTime1 = *timeStampRawPtr;
            }
         } else if(Type.Pdelay_Resp == 1) {   // else if(Type == Pdelay_Resp) {
            givenTimeStamp = EthTSynTime2;
            
            if((timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr)) == "E_OK") {
               temp = EthTSynTime3 - EthTSynTime2;
               timeStampDiffPtr = (StbM_TimeStampRawType*)&temp;    /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
            }
         } else if(Type.Sync == 1 ){ //&& Type == EthTimeGatewayMasterPort) {   // } else if(Type == Sync && Type == EthTimeGatewayMasterPort) {
            // givenTimeStamp = (Tr,i);   // Maybe 'Tr' means the time that received message, and 'i' means time-aware system indexed i
            if((timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr)) == "E_OK") {
               // timeStampDiffPtr = (Ts,i - Tr,i);   /* For correctionField(i) calculation of Time Aware Bridges */
               // 'Ts' means the synchronized time, maybe
               // 'Ts,i - Tr,i' means the residence time
            }
         }
      }
   }
}

/* Allow resetting state machine in case of unexpected Link loss to avoid inconsistent Sync and Follw_Up sequences */
Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState) {
  return E_OK;
}

/* Main function for cyclic call / resp. Sync, Follow_Up and Pdelay_Req transmissions */
void 		EthTSyn_MainFunction(void) {

}
                                                                                                                                                                                                                                                                                                                                                                        
