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
#include <net/avtp.h>


MODULE_LICENSE("GPL");

// #define CONFIG_STBM_MASTER

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

time_t temp, EthTSynTime1, EthTSynTime2, EthTSynTime3, EthTSynTime4; // for saving time in RXIndication() & TXConfirmation()
struct  timespec ts_LinkDelay, ts_ClockSlaveOffset;// dongwon0
ktime_t EthTSynT1_s, EthTSynT2_s, EthTSynT1_p, EthTSynT2_p, EthTSynT3_p, EthTSynT4_p, EthTSynLinkDelay; // for saving time in _create()
struct timespec tsEthTSynT1, tsEthTSynT2, tsEthTSynT3, tsEthTSynT4; // value type of timespec for saving time in _rcv()
ktime_t RxTimeT2, RxTimeT3, TxTimeT1, TxTimeT4; // for saving time in _rcv() (dongwon0)
ktime_t ethTSynTxTimestamp;
s64 delta2, delta4, delta_result = 0;

struct sockaddr_in sockaddr;

const char* master_addr = "192.168.100.20";
const char* slave_addr = "192.168.100.21";

static struct timer_list ethTSynTimer;

struct inet_sock* thisinetsock;
struct socket* thissock;

struct net_device *dev;

int state;
unsigned char dest_addr[6];

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
	
	fl4 = &inet->cork.fl.u.ip4;
	
	/* 
	 * No pending on ethtsyn (gPTP) remove pending check
	 */

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
		dport = usin->sin_port;		//dport = ?//if need fill the port value
	} else {
	  	/*
		 * No Connection Established Always Need IP Address or multicast source code need
		 */
	  	return -EINVAL;
	}
	
  	ipc.addr = inet->inet_saddr;

	ipc.oif = sk->sk_bound_dev_if;

	sock_tx_timestamp(sk, &ipc.tx_flags);

	if(msg->msg_controllen) {
	  	/*
		 * Will be 0 value in msg_controllen
		 */
	}
	
	if(!ipc.opt) {
	  	/*
		 * ipc opt is set when if statement above need to be check
		 */
	  	struct ip_options_rcu *inet_opt;
		
		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
/*		  memcpy(&opt_copy, inet_opt,
			 sizeof(*inet_opt) + inet_opt->opt.optlen);
		  ipc.opt = &opt_copy.opt;
*/	// error
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;
	
	if (ipc.opt && ipc.opt->opt.srr) {
	  	if (!daddr)
	    		return -EINVAL;
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}

	tos = RT_TOS(inet->tos);//need to check what value need to be initialized to inet

	if(sock_flag(sk, SOCK_LOCALROUTE) ||
	   (msg->msg_flags & MSG_DONTROUTE) ||
	   (ipc.opt && ipc.opt->opt.is_strictroute)) {
	  	tos |= RTO_ONLINK;
	  	connected = 0;
	}

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
		  	ipc.oif = inet->mc_index;
	  	if (!saddr)
		  	saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif)
	  	ipc.oif = inet->uc_index;
  
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
				  sizeof(struct udphdr), &ipc, &rt, 
				  msg->msg_flags);
		err = PTR_ERR(skb);
//		if(!IS_ERR_OR_NULL(skb))	// error
//			err = udp_send_skb(skb, fl4);	// error
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

/*
 * ethtsyn_xmit function 
 * NF_HOOK part should be filled! currently using ARP NF_HOOK
 * will not working currectly
 * Do not send any packet yet!
 */
void ethtsyn_xmit(struct sk_buff *skb)
{
  /* Send it off, maybe filter it using firewalling first.  */
  NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);
//  printk(KERN_INFO "ethtsyn_xmit finish\n");
}
EXPORT_SYMBOL(ethtsyn_xmit);

//Parameters need to check
//code copied from arp_create
//parameters may not be need
//need to compare arp & ptp 
struct sk_buff* ethtsyn_create(int type, 
			       ktime_t* time,	//might be null when Request, and sync type
			       struct net_device *dev,
			       int ptype, 
			       __be32 dest_ip, 
			       __be32 src_ip,
			       const unsigned char* dest_hw, 
			       const unsigned char* src_hw, 
			       const unsigned char* target_hw) {
  	struct sk_buff *skb;
	struct ptphdr* ptp;
	unsigned char* ptp_ptr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	u64 nsec;
	uint8_t *pCorrectionField;
	int ret;
	struct timespec tmp;
	ktime_t ktime_tmp;
	s64 delta;
	
	/*
	 *Allocate a buffer
	 */
	
	skb = alloc_skb(ptp_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);

	if(skb == NULL) 
	  return NULL;
	
	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	ptp = (struct ptphdr *)skb_put(skb, ptp_hdr_len(dev));

//	unsigned char dest_addr[6];

//#ifdef CONFIG_STBM_MASTER
		/* This address is address of raspberry pi(36) */
//		dest_addr[0] = 0xb8;
//		dest_addr[1] = 0x27;
//		dest_addr[2] = 0xeb;
//		dest_addr[3] = 0x38;
//		dest_addr[4] = 0x9c;
//		dest_addr[5] = 0x50;
//#else
		/* This address is address of raspberry pi(37) */
//		dest_addr[0] = 0xb8;
//		dest_addr[1] = 0x27;
//		dest_addr[2] = 0xeb;
//		dest_addr[3] = 0x38;
//		dest_addr[4] = 0x1f;
//		dest_addr[5] = 0x3f;
//#endif

//	dest_hw = dest_addr;

	/* For Debugging */
// 	printk(KERN_INFO "func: %s(1),     ptp_hdr_len(dev): %d\n", __func__, ptp_hdr_len(dev));

	skb->dev = dev;
	skb->protocol = htons(ETH_P_1588);
	if(src_hw == NULL) 
	  	src_hw = dev->dev_addr;
	if(dest_hw == NULL)
	  	dest_hw = dev->broadcast;

	/* For Debugging */
//  	printk(KERN_INFO "func: %s(2),     dest_hw: %02x:%02x:%02x:%02x:%02x:%02x\n", __func__,
//	       dest_hw[0], dest_hw[1], dest_hw[2],
//	       dest_hw[3], dest_hw[4], dest_hw[5]);


	//should not be broadcast. routine needs copied from tcp or udp source code 
	//how tcp or udp is using arp protocol to get device address
	//or need to check how address is decided in AUTOSAR standard
	
	/*
	 * Fill the device header for the ptp frame
	 */
	
	if(dev_hard_header(skb, dev, ptype, dest_hw, src_hw, skb->len) < 0)
	  	goto out;
	
	/* For Debug */
//	printk(KERN_INFO "Fill PTP Header\n");

#ifdef CONFIG_STBM_MASTER
	EthTSyn_ConfigType config = MASTER;
	ptp->sourcePortIdentity.portNumber = 1;  
#else
	EthTSyn_ConfigType config = SLAVE;
	// The portNumber values for a port on a time-aware end station (i.e., a time-aware system supporting a single port) shall be 1
	// The portNumber values for the ports on a time-aware Bridge supporting N ports shall be 1, 2, ..., N, respectively
	ptp->sourcePortIdentity.portNumber = 1;
#endif
	
	/*
	 * ptphdr initialization
	 */

	ptp->transportSpecific = 1;
	ptp->messageType = type;
	ptp->reserved = 0;
	ptp->versionPTP = 2;
	ptp->messageLength = 0x2C;   // 0x2C = 44 (byte)	// sizeof(struct ptphdr)
	ptp->domainNumber = 0;
	ptp->domainNumberrsv = 0;
	// struct flagField flags = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};   // initialized in ptp.h
	ptp->flags;
	pCorrectionField = &ptp->correctionField;
	*pCorrectionField = 0;
//	ptp->Fieldrsv = 0;	// error
	// ptp->sequenceId;
	ptp->control = 5;
	ptp->logMessageInterval = 0x7F;

	/* ClockIdentity initialization from Hw Addr */
	ptp->sourcePortIdentity.clockIdentity.B0 = dev->dev_addr[0];
	ptp->sourcePortIdentity.clockIdentity.B1 = dev->dev_addr[1];
	ptp->sourcePortIdentity.clockIdentity.B2 = dev->dev_addr[2];
	ptp->sourcePortIdentity.clockIdentity.B3 = 0xFF;
	ptp->sourcePortIdentity.clockIdentity.B4 = 0xFE;
	ptp->sourcePortIdentity.clockIdentity.B5 = dev->dev_addr[3];
	ptp->sourcePortIdentity.clockIdentity.B6 = dev->dev_addr[4];
	ptp->sourcePortIdentity.clockIdentity.B7 = dev->dev_addr[5];

	switch(type) {
	  
	case SYN :
//	  	printk(KERN_INFO "This is type of Syn.\n");
		// uint8_t currentLogSyncInterval;
		
		ptp->control = 0;
		//ptp->logMessageInterval = currentLogSyncInterval;    // currentLogSyncInterval specifies the current value of the sync interval, and is a per-port attributea

		// Need to set multicast
		// Need to set sequenceId
		// Need to set logMessageInterval

//		printk(KERN_INFO "func: %s(tx: SYN)\n", __func__);

		break;
	  
	case PDELAY_REQ :
 //		printk(KERN_INFO "This is type of Pdelay_Req.\n");
	  
		// EthTSynT1 = ktime_get_real();	// dongwon0	// PDELAY_REQ's time is TxTimeT1. might be modi (dong's opinion)
		// nsec = ktime_to_ns(EthTSynT1);	// dongwon0
		
		*pCorrectionField = (uint8_t)(nsec * 65536);   // is it corrected?? need to check
		
		// Need to set sequenceId
		// Need to set logMessageInterval
		
//		printk(KERN_INFO "func: %s(tx: PDELAY_REQ)\n", __func__);

		break;
	  
	case PDELAY_RESP :
//	  	printk(KERN_INFO "This is type of Pdelay_Resp.\n");
		
		// EthTSynT2 = skb_get_ktime(skb);	// dongwon0	//EthTSynT2 is ClockSlave's receive time.might be delete (dong's opinion)
		// EthTSynT3 = ktime_get_real();	// dongwon0
		// nsec = ktime_to_ns(EthTSynT2);	// dongwon0
		
		*pCorrectionField = (uint8_t)(nsec * 65536);
		
		tmp = ktime_to_timespec(EthTSynT2_p);
		ptp->timestamp.seconds = tmp.tv_sec;
		ptp->timestamp.nanoseconds = tmp.tv_nsec;

		ktime_tmp = timespec_to_ktime(tmp);

		delta = ktime_to_ns(ktime_tmp);
//		printk(KERN_INFO "func: %s(tx: RDELAY_RESP), time: %lld ns\n", __func__, (long long)delta);

		break;
	case FOLLOW_UP :
//	  	printk(KERN_INFO "This is type of Follow_Up.\n");
		
		EthTSynT1_s = ethTSynTxTimestamp;
	        tmp = ktime_to_timespec(EthTSynT1_s);
		ptp->timestamp.seconds = tmp.tv_sec;
		ptp->timestamp.nanoseconds = tmp.tv_nsec;

		ktime_tmp = timespec_to_ktime(tmp);

		delta = ktime_to_ns(ktime_tmp);
//		printk(KERN_INFO "func: %s(tx: FOLLOW_UP), time: %lld ns\n", __func__, (long long)delta);
	
		// Need to set logMessageInterval

		break;
		
	case PDELAY_RESP_FOLLOW_UP :
//	  	printk(KERN_INFO "This is type of Pdelay_Resp_Follow_Up.\n");
		
		// nsec = ktime_to_ns(EthTSynT3);		// dongwon0
		
		ptp->control = 2;
		*pCorrectionField = (uint8_t)(nsec * 65536);
		
		EthTSynT3_p = ethTSynTxTimestamp;
	        tmp = ktime_to_timespec(EthTSynT3_p);
		ptp->timestamp.seconds = tmp.tv_sec;
		ptp->timestamp.nanoseconds = tmp.tv_nsec;

		ktime_tmp = timespec_to_ktime(tmp);

		delta = ktime_to_ns(ktime_tmp);
//		printk(KERN_INFO "func: %s(tx: PDELAY_RESP_FOLLOW_UP), time: %lld ns\n", __func__, (long long)delta); 
		
		break;
	}

	ethtsyn_xmit(skb);

	return skb;
out :
	kfree_skb(skb);
	return NULL;
} 
EXPORT_SYMBOL(ethtsyn_create);

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

static void ethtsyn_get_clockslaveoffset(const ktime_t TimeT1, 
					 const ktime_t TimeT2, 
					 struct timespec Link_Delay) {

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

static int ethtsyn_rcv(struct sk_buff* skb, 
		       struct net_device* dev, 
		       struct packet_type* pt, 
		       struct net_device* orig_dev) {

//   	printk(KERN_INFO "Receive Packet!!\n");

	const struct ptphdr *ptp;

	int ret;
	s64 delta, delta3;
	ktime_t temp_diff, temp_diff_t1_t4, temp_diff_t2_t3,temp_offset;
	s64 delta_diff, delta_diff_t1_t4 = 0, delta_diff_t2_t3 = 0, delta_offset;

	/* For Debugging */
	//	EthTSynT4_p = ktime_get_real();
	//	delta4 = ktime_to_ns(EthTSynT4_p);
	//	printk(KERN_INFO "rx: -----------------t4: %lld\n", delta4);

	ptp = ptp_hdr(skb);
	
	skb = skb_share_check(skb, GFP_ATOMIC);

	if(!skb)
	  goto out_of_mem;
	
	int m_type = ptp->messageType;
	// printk(KERN_INFO "mtype: %d \n", m_type);

	switch(m_type){
	  
	case SYN:
//        	printk(KERN_INFO "Syn Received.\n");
	  
	  	EthTSynT2_s = skb_get_ktime(skb);	//save Syn Arrive Time, wait Follow_Up

		delta2 = ktime_to_ns(EthTSynT2_s);

		if(delta2 < 0 || delta2 == 0)
		  	goto freeskb;

//		printk(KERN_INFO "func: %s(rx: SYN),	time: %lld ms\n", __func__, (long long)delta2);

  	  	break;
#ifdef CONFIG_STBM_MASTER	  
	case PDELAY_REQ:
		if(state == PDELAY_REQ || state == PDELAY_RESP)
		  	goto freeskb;

//	  	printk(KERN_INFO "Pdelay_Req Received.\n");
	  
	  	// RxTimeT2 = skb_get_ktime(skb);	// dongwon0

	  	/*
	    	ethtsyn_create(PDELAY_RESP, null, null, dev, null, dev->dev_addr, null, null);
	    	// originally, Pdelay_Resp_Follow_Up which might be contained RxTimeT2
	    
	    	ethtsyn_create(PDELAY_RESP_FOLLOW_UP, null, null, dev, null, dev->dev_addr, null, null);
	    	// make at case:PDelayResp in ethtsyn_create ???
	    	// originally, Pdelay_Resp_Follow_Up which might be contained RxTimeT3
	    	*/
		state = PDELAY_REQ;

		dest_addr[0] = ptp->sourcePortIdentity.clockIdentity.B0;
		dest_addr[1] = ptp->sourcePortIdentity.clockIdentity.B1;
		dest_addr[2] = ptp->sourcePortIdentity.clockIdentity.B2;
		dest_addr[3] = ptp->sourcePortIdentity.clockIdentity.B5;
		dest_addr[4] = ptp->sourcePortIdentity.clockIdentity.B6;
		dest_addr[5] = ptp->sourcePortIdentity.clockIdentity.B7;

		EthTSynT2_p = skb_get_ktime(skb);
		delta2 = ktime_to_ns(EthTSynT2_p);

//		printk(KERN_INFO "func: %s(rx: PDELAY_REQ), time: %lld ns\n", __func__, (long long)delta2);

		/* Send Pdelay_resp message to Master */
		ethtsyn_create(PDELAY_RESP, NULL, dev, ETH_P_1588, NULL, NULL, dest_addr, NULL, NULL);

		state = PDELAY_RESP;
		
		ret = mod_timer(&ethTSynTimer, jiffies + msecs_to_jiffies(100));
		if(ret) {
//	  		printk(KERN_INFO "Error in mod_timer\n");
			break;	
		}
	  
	  	break;
#endif	  
	case PDELAY_RESP:
//	  	printk(KERN_INFO "Pdelay_Resp Received.\n");
	  
	  	// TxTimeT4 = skb_get_ktime(skb);	// dongwon0

		/* For Debugging */
		//		EthTSynT4_p = ktime_get_real();
		//		delta4 = ktime_to_ns(EthTSynT4_p);
		//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP), t4(1): %lld ns\n", __func__, (long long)delta4);

		EthTSynT4_p = skb_get_ktime(skb);		
		delta4 = ktime_to_ns(EthTSynT4_p);

		if(delta4 < 0 || delta4 == 0)
		  	goto freeskb;

		EthTSynT1_p = ethTSynTxTimestamp;		// There is the reason why this code is here.
		delta = ktime_to_ns(EthTSynT1_p);

//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP), t4(2): %lld ns\n", __func__, (long long)delta4);

		temp_diff = ktime_sub(EthTSynT4_p, EthTSynT1_p);
       		delta_diff = ktime_to_ns(temp_diff);

//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP), t1: %lld ns\n", __func__, (long long)delta);
//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP), t4(3): %lld ns\n", __func__, (long long)delta4);
//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP), diff_t1_t4: %lld ns\n", __func__, (long long)delta_diff);

		tsEthTSynT2.tv_sec = ptp->timestamp.seconds;
		tsEthTSynT2.tv_nsec = ptp->timestamp.nanoseconds;
		EthTSynT2_p = timespec_to_ktime(tsEthTSynT2);

		delta2 = ktime_to_ns(EthTSynT2_p);
//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP)\n", __func__);
//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP), t2: %lld ns\n", __func__, (long long)delta2);


	  	break;
	  
	case FOLLOW_UP:
#ifdef CONFIG_STBM_MASTER

#else
		if(delta_result == 0) {
			ethtsyn_create(PDELAY_REQ, NULL, dev, ETH_P_1588, NULL, NULL, NULL, NULL, NULL);
		  	goto out_of_mem;
		}
#endif

//	  	printk(KERN_INFO "Follow_Up Received.\n");
	  
	  	// originally, might get SynTimeT1 in packet and save it
	  	// ethtsyn_get_clockslaveoffset(EthTSynT1, EthTSynT2, ts_LinkDelay);	// dongwon0	// correct error

		delta2 = ktime_to_ns(EthTSynT2_s);
		
		tsEthTSynT1.tv_sec = ptp->timestamp.seconds;
		tsEthTSynT1.tv_nsec = ptp->timestamp.nanoseconds;
		EthTSynT1_s = timespec_to_ktime(tsEthTSynT1);

		delta = ktime_to_ns(EthTSynT1_s);
		temp_diff = ktime_sub(EthTSynT1_s, EthTSynT2_s);
       		delta_diff = ktime_to_ns(temp_diff);

//		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), time1: %lld ns\n", __func__, (long long)delta);
//		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), time2: %lld ns\n", __func__, (long long)delta2);
		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), diff: %lld ns\n", __func__, (long long)delta_diff);

		// Subtract network delay
		temp_offset = ktime_add(temp_diff, EthTSynLinkDelay);
		delta_offset = ktime_to_ns(temp_offset);

		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), diff_offset: %lld ns\n", __func__, (long long)delta_offset);

		ktime_t kt_now = ktime_get_real();
		s64 delta_now = ktime_to_ns(kt_now);
//		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), before_offset: %lld ns\n", __func__, (long long)delta_now);
		
		struct timespec ts = ktime_to_timespec(temp_offset);
		timekeeping_inject_offset(&ts);

		kt_now = ktime_get_real();
		delta_now = ktime_to_ns(kt_now);
//		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), after_offset: %lld ns\n", __func__, (long long)delta_now);
//		printk(KERN_INFO "func: %s(rx: FOLLOW_UP), delta_result: %lld ns\n", __func__, (long long)delta_result);
	  
	  	break;
	  
	case PDELAY_RESP_FOLLOW_UP:
//	  	printk(KERN_INFO "Pdelay_Resp_Follow_Up Received.\n");

		if(delta < 0 || delta4 == 0)
		  	goto freeskb;
	  
	  	// originally, might get RxTimeT2, RxTimeT3 in packet and save it	  
	  	// ts_LinkDelay = ethtsyn_get_linkdelay(TxTimeT1, RxTimeT2, RxTimeT3, TxTimeT4);	// dongwon0	// error

		tsEthTSynT3.tv_sec = ptp->timestamp.seconds;
		tsEthTSynT3.tv_nsec = ptp->timestamp.nanoseconds;
		EthTSynT3_p = timespec_to_ktime(tsEthTSynT3);

		delta3 = ktime_to_ns(EthTSynT3_p);
//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP_FOLLOW_UP), t3: %lld ns\n", __func__, (long long)delta3);


	        /* T4 - T1 */
		temp_diff_t1_t4 = ktime_sub(EthTSynT4_p, EthTSynT1_p);
       		delta_diff_t1_t4 = ktime_to_ns(temp_diff_t1_t4);

//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP_FOLLOW_UP), diff_t1_t4: %lld ns\n", __func__, (long long)delta_diff_t1_t4);


		/* T3 - T2 */
		temp_diff_t2_t3 = ktime_sub(EthTSynT3_p, EthTSynT2_p);
       		delta_diff_t2_t3 = ktime_to_ns(temp_diff_t2_t3);

//		printk(KERN_INFO "func: %s(rx: PDELAY_RESP_FOLLOW_UP), diff_t2_t3: %lld ns\n", __func__, (long long)delta_diff_t2_t3);


		/* [(T4-T1)-(T3-T2)] / 2 */
		EthTSynLinkDelay = ktime_sub(temp_diff_t1_t4, temp_diff_t2_t3);
		delta_result = ktime_to_ns(EthTSynLinkDelay); 
       		delta_result = delta_result / 2;

		printk(KERN_INFO "func: %s(rx: PDELAY_RESP_FOLLOW_UP, link_delay: %lld ns\n", __func__, (long long)delta_result);

	  	break;
	default:
		break;
	}
	
 freeskb:
	kfree_skb(skb);
 out_of_mem:
	return 0;
}

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
	
//	skb = ethtsyn_route_check(msg, thissock);	// error
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
	char strEth[5] = "eth0";

//	printk(KERN_INFO "Hello world, this is ethtsyn_timer_callback()\n");
	
	if(dev == NULL) {
		dev = first_net_device(&init_net);

		while(dev) {
		  	if(!strcmp(dev->name, strEth)) {
	    			/* Print Device Information */
//			  	printk(KERN_INFO "1. dev->name [%s]\n", dev->name);
//				printk(KERN_INFO "2. dev->base_addr [%lu]\n", dev->base_addr);
//				printk(KERN_INFO "3. dev->ifindex [%d]\n", dev->ifindex);
//				printk(KERN_INFO "4. dev->mtu [%d]\n", dev->mtu);
//				printk(KERN_INFO "5. dev->type [%hu]\n", dev->type);
//				printk(KERN_INFO "6. dev->perm_addr [%s]\n", dev->perm_addr);
//				printk(KERN_INFO "7. dev->addr_len [%02x]\n", dev->addr_len);
//				printk(KERN_INFO "8. dev->dev_id [%hu]\n", dev->dev_id);
//				printk(KERN_INFO "9. dev->last_rx [%lu]\n", dev->last_rx);
//				printk(KERN_INFO "10. dev->dev_addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
//				       dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2],
//				       dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5]);
//				printk(KERN_INFO "11. dev->broadcast [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
//				       dev->broadcast[0], dev->broadcast[1], dev->broadcast[2],
//				       dev->broadcast[3], dev->broadcast[4], dev->broadcast[5]);
				
				break;
			}
			dev = next_net_device(dev);
		}
	}
	// For AVTP debug (dongwon0)
	avtp_create(0x7E, NULL, dev, NULL, NULL, NULL, NULL, NULL, dev->broadcast);

	switch(state) {
	case SYN:
	 	skb = ethtsyn_create(FOLLOW_UP, NULL, dev, ETH_P_1588, NULL, NULL, dev->broadcast, NULL, NULL);

		state = FOLLOW_UP;

		ret = mod_timer(&ethTSynTimer, now + msecs_to_jiffies(5000));
	
		if(ret) {
//	 		printk(KERN_INFO "Error in mod_timer\n");
		  	break;
		}
 
		break;
	case PDELAY_RESP:
		skb = ethtsyn_create(PDELAY_RESP_FOLLOW_UP, NULL, dev, ETH_P_1588, NULL, NULL, dest_addr, NULL, NULL);

		state = FOLLOW_UP;

		ret = mod_timer(&ethTSynTimer, now + msecs_to_jiffies(5000));
	
		if(ret) {
//	 		printk(KERN_INFO "Error in mod_timer\n");
		  	break;
		}
 
		break;
	case FOLLOW_UP:
		skb = ethtsyn_create(SYN, NULL, dev, ETH_P_1588, NULL, NULL, dev->broadcast, NULL, NULL);

		state = SYN;

 		ret = mod_timer(&ethTSynTimer, now + msecs_to_jiffies(100));
	
		if(ret) {
//	 		printk(KERN_INFO "Error in mod_timer\n");
		  	break;
		}
 
		break;
	default:
	  	break;
	}

	// skb = ethtsyn_create(SYN, NULL, dev, NULL, NULL, NULL, NULL, NULL, NULL);		// Send to broadcaat

}

int ethtsyn_timer_init_module(void) {
#ifdef CONFIG_STBM_MASTER
  	state = FOLLOW_UP;
#else
	state = -1;
#endif

  	int ret;

	dev = NULL;

//	printk(KERN_INFO "Timer module installing\n");
	
	setup_timer(&ethTSynTimer, ethtsyn_timer_callback, 0);
	
	ret = mod_timer(&ethTSynTimer, jiffies + msecs_to_jiffies(60000));
	
	if(ret) {
//	  	printk(KERN_INFO "Error in mod_timer\n");
	  	return 0;
	}

	return 0;
}

void ethtsyn_timer_cleanup_module(void) {
  	int ret;

	ret = del_timer(&ethTSynTimer);
	
	if(ret) {
//	  	printk(KERN_INFO "The timer is still in use...\n");
	  	return;
	}
	
//	printk(KERN_INFO "Timer module uninstalling\n");
	
	return;
}
/* End of Timer  */

static int ethtsyn_sock_check() {
  	struct sockaddr_storage address;
	int retval;
#ifdef CONFIG_ETHTSYN_MASTER
	ethtsyn_ip_to_sockaddr_storage(slave_addr, address);
#elif CONFIG_ETHTSYN_SLAVE
	ethtsyn_ip_to_sockaddr_storage(master_addr, address);
#endif
	//sock create parameters need to be update
	retval = sock_create(AF_INET, SOCK_RAW, IPPROTO_RAW, &thissock);
	if(retval < 0)
	  	goto out;	//when error is occured retval will be under 0
	//assume sock setting is finished
out:
	return retval;
}

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
  	ethtsyn_sock_check();
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
