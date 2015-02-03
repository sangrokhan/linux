#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/export.h>
#include <linux/std_types.h>
#include <linux/audit.h>
#include <linux/socket.h>
#include <linux/byteorder/generic.h>
#include <uapi/linux/netfilter_arp.h>
#include <uapi/linux/in.h>
#include <uapi/linux/snmp.h>
#include <net/ip.h>
#include <net/stbm.h>
#include <net/ethtsyn.h>
#include <net/ethif.h>
#include <net/ptp.h>
#include <net/sock.h>
#include <net/route.h>

MODULE_LICENSE("GPL");

bool EthTSynHardwareTimestampSupport;

Std_ReturnType hardwareRegisterTime;

Eth_TimeStampQualType* timeQualPtr;

Std_ReturnType globalTime;
Std_ReturnType currentTime;
Std_ReturnType currentTimeRaw;
Std_ReturnType timeDifferenceOfCurrentTimeRaw;

StbM_SynchronizedTimeBaseType timeBaseId;
StbM_TimeStampType*timeStampPtr;
StbM_UserDataType* userDataPtr;
StbM_TimeStampRawType* timeStampRawPtr;
StbM_TimeStampRawType givenTimeStamp;
StbM_TimeStampRawType* timeStampDiffPtr;

EthTSyn_MessageType Type;

time_t temp, EthTSynTime1, EthTSynTime2, EthTSynTime3, EthTSynTime4;

// ktime_t RxTimeT2, RxTimeT3, TxTimeT1, TxTimeT4, SynTimeT1, SynTimeT2; // for saving time in _rcv() (dongwon0)
// timespec ts_LinkDelay, ts_ClockSlaveOffset;// dongwon0

struct sockaddr_in sockaddr;

const char* master_addr = "192.168.100.20";
const char* slave_addr = "192.168.100.21";

static struct timer_list ethTSynTimer;

struct inet_sock* thisinetsock;
struct socket* thissock;

void ethtsyn_timer_callback(unsigned long arg);

//char type ip address change to sockaddr_storage type
static void ethtsyn_ip_to_sockaddr_storage(const char* ch_addr, struct sockaddr_storage *address) {
  __be32 tempAddr;
  uint8_t arr[4];
  int a, b, c ,d;
  sscanf(ch_addr, "%d.%d.%d.%d", &a, &b, &c, &d);
  arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
  tempAddr = *(uint32_t *)arr;
  memcpy(address, &tempAddr, 4);
  audit_sockaddr(4, address);
}

//copied from udp source code 
static struct sk_buff* ethtsyn_route_check(struct msghdr *msg,
					   struct sock *sk) {
  struct inet_sock *inet = inet_sk(sk);
  struct sk_buff* skb;
  struct rtable *rt = NULL;
  struct flowi4 fl4_stack;
  struct flowi4 *fl4;
  struct ipcm_cookie ipc;
  int (*getfrag)(void *, char *, int, int, int, struct sk_buff*);
  int connected = 0;
  u8 tos;
  int err, ulen = 0;
  int corkreq = msg->msg_flags & MSG_MORE;
  __be32 daddr, faddr, saddr;
  __be16 dport;//port value is need? there is no user application

  ipc.opt = NULL;
  ipc.tx_flags = 0;
  getfrag = NULL;

  ulen += sizeof(struct ptphdr);

  if(msg->msg_name) {
    struct sockaddr_in *usin = (struct sockaddr_in *) msg->msg_name;
    if(msg->msg_namelen < sizeof(*usin))
      return -EINVAL;
    if(usin->sin_family != AF_INET) {
      if(usin->sin_family != AF_UNSPEC) {
	return -EAFNOSUPPORT;
      }
    }
    daddr = usin->sin_addr.s_addr;
    //dport = ?//if need fill the port value
  } else {//W/O IP Address
    return -EINVAL;
  }
  
  ipc.addr = inet->inet_saddr;
  ipc.oif = sk->sk_bound_dev_if;
  sock_tx_timestamp(sk, &ipc.tx_flags);

  tos = RT_TOS(inet->tos);//need to check what value need to be initialized to inet
  if(sock_flag(sk, SOCK_LOCALROUTE) ||
     (msg->msg_flags & MSG_DONTROUTE) ||
     (ipc.opt && ipc.opt->opt.is_strictroute)) {
    tos |= RTO_ONLINK;
    connected = 0;
  }
  
  /*
   * TCP always connected, so using sk_dst_check for routing 
   * UDP is not connected always, so flow check is need;
   */
  if(connected)
    rt = (struct rtable *) sk_dst_check(sk, 0);

  if(rt == NULL) {
    struct net *net = sock_net(sk);  
    
    fl4 = &fl4_stack;
    flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
		       RT_SCOPE_UNIVERSE, sk->sk_protocol,
		       inet_sk_flowi_flags(sk) | FLOWI_FLAG_CAN_SLEEP,
		       faddr, saddr, dport, inet->inet_sport);
    //security_sk_classify_flow(sk, flowi4_to_flow(fl4));//maybe nothing happend
    rt = ip_route_output_flow(net, fl4, sk);//flow check function
    if(IS_ERR(rt)) {
      err = PTR_ERR(rt);
      rt = NULL;
      if(err = -ENETUNREACH)
	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
      goto out;
    }

    err = -EACCES;
    if((rt->rt_flags & RTCF_BROADCAST) && 
       !sock_flag(sk, SOCK_BROADCAST))
      goto out;
    if(connected)
      sk_dst_set(sk, dst_clone(&rt->dst));
  } 

  if(msg->msg_flags & MSG_CONFIRM)
    goto do_confirm;
 back_from_confirm:
  
  saddr = fl4->saddr;
  if(!ipc.addr)
    daddr = ipc.addr = fl4->daddr;

  if(!corkreq) {
    skb = ip_make_skb(sk, fl4, getfrag, msg->msg_iov, ulen,
		      sizeof(sutrct udphdr), &ipc, &rt, 
		      msg->msg_flags);
    err = PTR_ERR(skb);
    if(!IS_ERROR_OR_NULL(skb))
      err = udp_send_skb(skb, fl4);
  }
 out:
  


 do_confirm:
  dst_confirm(&rt->dst);
  //if(!(msg->msg_flags & MSG_PROBE) || len)//CHECK ABOUT MSG_FLAGS 
  //goto back_from_confirm;
  //err = 0;
  //goto out;
  //after confirm, the route is exsit. 
  //return sk_buff
}

//Parameters need to check
//code copied from arp_create
//parameters may not be need
//need to compare arp & ptp 
struct sk_buff* ethtsyn_create(int type, 
			       timestamp* time,//might be null when Request, and sync type
			       struct net_device *dev,
			              
			       int ptype, 
			       __be32 dest_ip, 
			       __be32 src_ip,
			       const unsigned char* dest_hw, 
			       const unsigned char* src_hw, 
			       const unsigned char* target_hw) {
  struct ptphdr* ptp;
  unsigned char* ptp_ptr;
  int hlen = LL_RESERVED_SPACE(dev);
  int tlen = dev->needed_tailroom;

  /*
   *Allocate a buffer
   */

  skb = alloc_skb(ptp_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);
  if(skb == NULL) 
    return NULL;

  skb_reserve(skb, hlen);
  skb_reset_network_header(skb);
  ptp = (struct ptphdr *)skb_put(skb, ptp_hdr_len(dev));
  skb->dev = dev;
  skb->protocol = htons(ETH_P_1588);
  if(src_hw == NULL) 
    src_hw = dev->dev_addr;
  if(dest_hw == NULL)
    dest_hw = dev->broadcast;
  //should not be broadcast. routine needs copied from tcp or udp source code 
  //how tcp or udp is using arp protocol to get device address
  //or need to check how address is decided in AUTOSAR standard
  
  /*
   * Fill the device header for the ptp frame
   */

  if(dev_hard_header(skb, dev, ptype, dest_hw, src_hw, skb->len) < 0)
    goto out;

  switch(type) {
    ptp->messageType = type;
      
    /* Sync */
  case 0 :
    printk(KERN_INFO "This is type of Syn.\n");

    SynTimeT1 = ktime_get_real(); // ClockMaster's SYN T1 Time. later, this t1 might be contained FOLLOW_UP packet. (dongwon0)
      
    // SynMsg syn_msg;
    // syn_msg->header = ptp;
      
    break;
      
    /* Pdelay_Req */
  case 2 :
    printk(KERN_INFO "This is type of Pdelay_Req.\n");

    TxTimeT1 = ktime_get_real(); // Requester's T1 Time. later, this is calculated (dongwon0)
      
    // PdelayReqMsg pdelay_req_msg;
      
    //ptp->correctionField = 0;
    // ptp->domainNumber = 0;
    // pdelay_req_msg->header = ptp;
    // clock_gettime(CLOCK_REALTIME, &pdelay_req_msg->originTimestamp);
      
    break;
      
    /* Pdelay_Resp */
  case 3 :
    printk(KERN_INFO "This is type of Pdelay_Resp.\n");
      
    // PdelayRespMsg pdelay_resp_msg;
    //ptp->correctionField = 0; 
    // ptp->sequenceId = ;  // Copy the sequenceId field from the Pdelay_Req message
    // pdelay_resp_msg->header = ptp;
      
    break;
      
    /* Follow_Up */
  case 8 :
    printk(KERN_INFO "This is type of Follow_Up.\n");
      
    // FollowUpMsg follow_up_msg;
      
    // follow_up_msg->header = ptp;
      
    break;
      
    /* Pdelay_Resp_Follow_Up */
  case 10 :
    printk(KERN_INFO "This is type of Pdelay_Resp_Follow_Up.\n");
      
    // PdelayRespFollowUpMsg pdelay_resp_follow_up_msg;
      
    // ptp->correctionField = ;   // Copy the correctionField from the Pdelay_Req message to the correctionField of the Pdelay_Resp_Follow_Up message
    // ptp->sequenceId = ;  // Copy the sequenceId field from the Pdelay_Req message
      
    // pdelay_resp_follow_up_msg->header = ptp;
      
    break;
  }
  
  return skb;
 out :
  kfree_skb(skb);
  return NULL;
} 
EXPORT_SYMBOL(ethtsyn_create);

/*
 * ethtsyn_xmit function 
 * NF_HOOK part should be filled! currently using ARP NF_HOOK
 * will not working currectly
 * Do not send any packet yet!
 */
void ethtsyn_xmit(struct sk_buff *skb)
{
  /* Send it off, maybe filter it using firewalling first.  */
  //NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);
}
EXPORT_SYMBOL(ethtsyn_xmit);

/*
 * skb might have a dst pointer attached, refcounted or not.
 * _skb_refdst low order bit is set if refcount was _not_ taken
 */

/*
#define SKB_DST_NOREF   1UL
#define SKB_DST_PTRMASK ~(SKB_DST_NOREF)
void set_device_test(struct sk_buff *skb) {
   struct sock *sk = skb->sk;
   struct rtable *rt;
   struct net_device *dev;
   rt = (struct rtable *) (skb->_skb_refdst & SKB_DST_PTRMASK);
   rt = (struct rtable *) __sk_dst_get(sk);
   dev = &rt->dst.dev;
   if(!dev) {
      printk(KERN_INFO "dev is null\n");
   } else {
      printk(KERN_INFO "dev is set\n");
   }
}
*/

static int ethtsyn_netdev_event(struct notifier_block* this, 
				unsigned long event, 
				void* ptr) {
  struct net_device* dev = netdev_notifier_info_to_dev(ptr);
  struct netdev_notifier_change_info* change_info;

  switch(event) {
  default: 
    break;
  }
  return NOTIFY_DONE;
}

static struct notifier_block ethtsyn_netdev_notifier = {
  .notifier_call = ethtsyn_netdev_event,
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

static void ethtsyn_get_clockslaveoffset(const ktime_t TimeT1, const ktime_t TimeT2, struct timespec Link_Delay){

  struct timespec T1, T2, temp1, temp2, now;

  T1 = ktime_to_timespec(TimeT1);
  T2 = ktime_to_timespec(TimeT2);

  temp1 = timespec_sub(T2, T1);
  ts_ClockSlaveOffset = timespec_sub(temp1, Link_Delay);

  getnstimeofday(&temp2);
  now = timespec_sub(temp2, ts_ClockSlaveOffset);
  do_settimeofday(&now);
  // need to set slave's time by 'now' ...... i couldn't find proper fuction 
  
}

static struct timespec ethtsyn_get_linkdelay(const ktime_t TimeT1, 
					     const ktime_t TimeT2, 
					     const ktime_t TimeT3, 
					     const ktime_t TimeT4 ) {

  struct timespec T1, T2, T3, T4, temp1, temp2, temp3;
  s64 ns_LinkDelay;

  T1 = ktime_to_timespec(TimeT1);
  T2 = ktime_to_timespec(TimeT2);
  T3 = ktime_to_timespec(TimeT3);
  T4 = ktime_to_timespec(TimeT4);
  
  temp1 = timespec_sub(T4, T3);
  temp2 = timespec_sub(T2, T1);
  temp3 = timespec_add(temp1, temp2);

  ns_LinkDelay = timespec_to_ns(&temp3)/2;

  return ns_to_timespec(ns_LinkDelay);

}


//dongwon0
static int ethtsyn_rcv(struct sk_buff* skb, 
		       struct net_device* dev, 
		       struct packet_type* pt, 
		       struct net_device* orig_dev) {

  /*
    int rcv_type;
    int rcv_ptype;
    __be32 rcv_dest_ip = skb->;
    __be32 rcv_src_ip;
    const unsigned char* rcv_dest_hw;
    const unsigned char* rcv_src_hw;
    const unsigned char* rcv_target_hw;
  */

  printk(KERN_INFO "Receive Packet!!\n");

  const struct ptphdr *ptp;

  ptp = ptp_hdr(skb);
  
  skb = skb_share_check(skb, GFP_ATOMIC); // ???????
  if(!skb)
    goto out_of_mem;

  int m_type = ptp->messageType;

  switch(m_type){

  case SYN:
    printk(KERN_INFO "This is type of Syn.\n");

    SynTimeT2 = skb_get_ktime(skb);//save Syn Arrive Time, wait Follow_Up
      
    break;

  case PDELAY_REQ:
    printk(KERN_INFO "This is type of Pdelay_Req.\n");

    RxTimeT2 = skb_get_ktime(skb);
 
    RxTimeT3 = ktime_get_real();
    
    // call create (Pdelay_Resp)
    
    // call create (Pdelay_Resp_Follow_Up which might be contained RxTimeT2, RxTimeT3 )
             
    break;

  case PDELAY_RESP:
    printk(KERN_INFO "This is type of Pdelay_Resp.\n");

    TxTimeT4 = skb_get_ktime(skb);
             
    break;

  case FOLLOW_UP:
    printk(KERN_INFO "This is type of Follow_Up.\n");

    // originally, might get SynTimeT1 in packet and save it
    
    ethtsyn_get_clockslaveoffset(SynTimeT1, SynTimeT2, ts_LinkDelay);
             
    break;

  case PDELAY_RESP_FOLLOW_UP:
    printk(KERN_INFO "This is type of Pdelay_Resp_Follow_Up.\n");

    // originally, might get RxTimeT2, RxTimeT3 in packet and save it

    ts_LinkDelay = ethtsyn_get_linkdelay(TxTimeT1, RxTimeT2, RxTimeT3, TxTimeT4);
    
    break;
  }

 freeskb:
  kfree_skb(skb);
 out_of_mem:
  return 0;
}



/*
static int64_t calculate_offset(struct timespec *ts1,
      struct timespec *rt,
            struct timespec *ts2)
{
int64_t interval;
int64_t offset;
#define NSEC_PER_SEC 1000000000ULL
// calculate interval between clock realtime 
interval = (ts2->tv_sec - ts1->tv_sec) * NSEC_PER_SEC;
interval += ts2->tv_nsec - ts1->tv_nsec;
// assume PHC read occured half way between CLOCK_REALTIME reads 
offset = (rt->tv_sec - ts1->tv_sec) * NSEC_PER_SEC;
offset += (rt->tv_nsec - ts1->tv_nsec) - (interval / 2);
return offset;
}
*/

 //type parameter need to add
void ethtsyn_send(const char* addr, uint32_t addr_len) {
  struct sockaddr_storage address;
  struct msghdr msg;
  struct iovec iov;//why?
  struct sk_buff *skb;

  ethtsyn_ip_to_sockaddr_storage(addr, &address);

  msg.msg_name = (struct sockaddr *) &address;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_namelen = addr_len;
 
  //ethtsyn_route_check(msg, sk);
  //skb = ethtsyn_create(sk);
  if(skb == NULL)
    return;
  ethtsyn_xmit(skb);
}

/* Start of Timer */
void ethtsyn_timer_callback(unsigned long arg) {
  struct sk_buff *skb;

  unsigned long now = jiffies;
  int ret;

  printk(KERN_INFO "Hello world, this is ethtsyn_timer_callback()\n");

  /*
    //dong
    ktime_t tx_time;
    tx_time = ktime_get_real();
    s64 delta;
    delta = ktime_to_ns(tx_time);
    printk(KERN_INFO "ktime : %lld  (NOW) \n ", (long long)delta);
  */

  ret = mod_timer(&ethTSynTimer, now + msecs_to_jiffies(200));

  if(ret) {
    printk(KERN_INFO "Error in mod_timer\n");
  }

  //ethtsyn_send(type);

  // skb = ethtsyn_create(SYN, ETH_P_ARP, NULL, NULL, NULL, NULL, NULL, NULL);
  // ethtsyn_xmit(skb);
  //set_device_test(skb);
}

int ethtsyn_timer_init_module(void) {
  int ret;

  printk(KERN_INFO "Timer module installing\n");

  setup_timer(&ethTSynTimer, ethtsyn_timer_callback, 0);

  ret = mod_timer(&ethTSynTimer, jiffies + msecs_to_jiffies(200));

  if(ret) {
    printk(KERN_INFO "Error in mod_timer\n");
  }

  return 0;
}

void ethtsyn_timer_cleanup_module(void) {
  int ret;

  ret = del_timer(&ethTSynTimer);

  if(ret) {
    printk(KERN_INFO "The timer is still in use...\n");
  }

  printk(KERN_INFO "Timer module uninstalling\n");

  return;
}

/* End of Timer */

static struct packet_type ethtsyn_packet_type __read_mostly = {
  .type = cpu_to_be16(ETH_P_1588),
  .func = ethtsyn_rcv
};

/* Initialize all internal variables and set the EthTSync module to init state */
void EthTSyn_Init(const EthTSyn_ConfigType* configPtr) {
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

  printk(KERN_INFO "EthTsyn init function called\n");

  //copied from arp style
  dev_add_pack(&ethtsyn_packet_type);
  ethtsyn_proc_init();
  register_netdevice_notifier(&ethtsyn_netdev_notifier);   
  ethtsyn_timer_init_module();
}

/* Returns the version information of this module */
void EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo) {
  if(EthTSynVersionInfo == 0) {   // False : version information API deactivated
  } else {   // True : version information API activated
  }
}

/* Returns a time value according its definition out of the HW registers */
Std_ReturnType EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId,
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
Std_ReturnType EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				     StbM_TimeStampType* timeStampPtr) {
  uint8_t CtrlIdx;
  Eth_TimeStampType* ethTimeStampPtr = timeStampPtr;
  globalTime = EthIf_SetGlobalTime(CtrlIdx, ethTimeStampPtr);
  return globalTime;
}

/* This API is used to turn on and off the TX capabilities of the EthTSyn */
Std_ReturnTypeEthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
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
voidEthTSyn_RxIndication(uint8_t CtrlIdx,
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
voidEthTSyn_TxConfirmation(uint8_t CtrlIdx,
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
Std_ReturnTypeEthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
				       EthTrcv_LinkStateType TrcvLinkState) {
  return E_OK;
}

/* Main function for cyclic call / resp. Sync, Follow_Up and Pdelay_Req transmissions */
void EthTSyn_MainFunction(void) {

}
