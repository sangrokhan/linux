#include <linux/types.h>
#include <linux/string.h>
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
#include <net/ethif.h>
#include <net/ptp.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/avtp.h>
#include <net/maap.h>

struct net_device *avtp_dev;

static struct timer_list avtp_timer;

void avtp_timer_callback(unsigned long arg);

void avtp_xmit(struct sk_buff* skb){

  	printk(KERN_INFO "[avtp]avtp_xmit function called\n");

  	//	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);

  	dev_queue_xmit(skb);
}

struct sk_buff* avtp_create(struct avtp_common_hdr *temp_hdr,
			    uint8_t type,
			    unsigned message_type,
			    struct net_device *dev,
			    const uint8_t* req_start_addr,
			    uint16_t req_count,
			    const uint8_t* conflict_start_addr,
			    uint16_t conflict_count,
			    const unsigned char* src_hw,
			    const unsigned char* dest_hw){
  	printk(KERN_INFO "[avtp]avtp_create function called\n");
	struct sk_buff* skb;
	
	struct avtp_ctr_hdr* avtp_ctr;
	struct avtp_str_hdr* avtp_str;
	struct avtp_maap_hdr* avtp_maap;
	unsigned char* avtp_ptr;	

	//	uint8_t* tmp = (uint8_t*)temp_hdr;
	//printk(KERN_INFO "func: %s,tmp[0] :  %x\n", __func__, tmp[0]);

	if(dev == NULL) {
	  	dev = avtp_dev;
	}

	int hlen = LL_RESERVED_SPACE(dev);	// ???????
	int tlen = dev->needed_tailroom;	// ???????


	if(is_ctr_avtp_packet(temp_hdr)){	//contol data

		struct maaphdr *avtp_maap;
	
	    	avtp_maap = temp_hdr;

		skb = alloc_skb(avtp_maap_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);	// what is hlen, tlen, GFP_ATOMIC ???

  		if(skb == NULL) 
    			return NULL;
  
  		skb_reserve(skb, hlen);
  		skb_reset_network_header(skb);
  		avtp_maap = (struct avtp_maap_hdr *)skb_put(skb, avtp_maap_hdr_len(dev));

		skb->dev = dev;
		skb->protocol = htons(ETH_P_AVTP);

		if(src_hw == NULL) 
		  src_hw = dev->dev_addr;
		if(dest_hw == NULL)
		  dest_hw = dev->broadcast;
		/*
		// For Debugging sources - send to 28th raspberry pi  (dongwon0)	
		unsigned char mc_addr[6];	// raspberry 28's mac addr
		mc_addr[0]=0x91;
		mc_addr[1]=0xE0;
		mc_addr[2]=0xF0;
		mc_addr[3]=0x00;
		mc_addr[4]=0xFF;
		mc_addr[5]=0x00;
		dest_hw = mc_addr;

		avtp_maap->cd = 1;
		avtp_maap->subtype = 0x7E;
		*/

		printk(KERN_INFO "[avtp]func:%s(2), src_hw: %02x:%02x:%02x:%02x:%02x:%02x\n", __func__,
		       src_hw[0], src_hw[1], src_hw[2],
		       src_hw[3], src_hw[4], src_hw[5]);
		printk(KERN_INFO "[avtp]func:%s(2), dest_hw(raspberry 28: %02x:%02x:%02x:%02x:%02x:%02x\n", __func__,
		       dest_hw[0], dest_hw[1], dest_hw[2],
		       dest_hw[3], dest_hw[4], dest_hw[5]);	// For debuging source end!

		if(dev_hard_header(skb, dev, ETH_P_AVTP, dest_hw, src_hw, skb->len) < 0)
		  goto out;

		printk(KERN_INFO "=============MAAP heaader==========\n");
		printk(KERN_INFO "[avtp]1. cd [%u]\n", 		avtp_maap->cd);
		printk(KERN_INFO "[avtp]2. subtype [%u]\n", 		avtp_maap->subtype);
		printk(KERN_INFO "[avtp]3. sv [%u]\n", 		avtp_maap->sv);
		printk(KERN_INFO "[avtp]4. version [%u]\n", 		avtp_maap->version);
		printk(KERN_INFO "[avtp]5. message_type [%u]\n", 	avtp_maap->message_type);
		printk(KERN_INFO "[avtp]6. maap_version [%u]\n", 	avtp_maap->maap_version);
		printk(KERN_INFO "[avtp]7. maap_data_length [%lu]\n",avtp_maap->maap_data_length);
		printk(KERN_INFO "[avtp]9. req_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
			avtp_maap->requested_start_address[0], avtp_maap->requested_start_address[1], 
			avtp_maap->requested_start_address[2], avtp_maap->requested_start_address[3],
			avtp_maap->requested_start_address[4], avtp_maap->requested_start_address[5]);
		printk(KERN_INFO "[avtp]10. requested_count [%lu]\n", avtp_maap->requested_count);
		printk(KERN_INFO "[avtp]11. conflict_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
			avtp_maap->conflict_start_address[0], avtp_maap->conflict_start_address[1], 
			avtp_maap->conflict_start_address[2], avtp_maap->conflict_start_address[3],
			avtp_maap->conflict_start_address[4], avtp_maap->conflict_start_address[5]);
		printk(KERN_INFO "[avtp]13. conflict_count [%lu]\n", avtp_maap->conflict_count);
		printk(KERN_INFO "=============MAAP heaader==========\n");

	}
	else{	// stream data


	}

	/*
	uint8_t ftype;
	ftype = tmp[0];
	printk(KERN_INFO "func: %s,ftype :  %x\n", __func__, ftype);


	//struct maaphdr *avtp_maap;
	
	

	if (temp_hdr != NULL)
	  {
	    ftype = ((uint8_t *)temp_hdr)[0];
	    avtp_maap = temp_hdr;
	  }
	else
	  {
	    printk(KERN_INFO "temp_hdr is null !\n");
	  }

	// For Debugging 
	printk(KERN_INFO "func: %s,	avtp_dev->name: %s\n", __func__, avtp_dev->name);

	if(dev == NULL) {
	  	dev = avtp_dev;
	}

	int hlen = LL_RESERVED_SPACE(dev);	// ???????
	int tlen = dev->needed_tailroom;	// ???????

	// For Debugging
	printk(KERN_INFO "func: %s,	dev->name: %s\n", __func__, dev->name);

	if(ftype == MAAP){

		skb = alloc_skb(avtp_maap_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);	// what is hlen, tlen, GFP_ATOMIC ???

  		if(skb == NULL) 
    			return NULL;
  
  		skb_reserve(skb, hlen);
  		skb_reset_network_header(skb);
  		avtp_maap = (struct maaphdr *)skb_put(skb, avtp_maap_hdr_len(dev));

		skb->dev = dev;
		skb->protocol = htons(ETH_P_AVTP);

		if(src_hw == NULL) 
		  src_hw = dev->dev_addr;
		if(dest_hw == NULL)
		  dest_hw = dev->broadcast;

		// For Debugging sources - send to 28th raspberry pi  (dongwon0)	
		unsigned char mc_addr[6];	// raspberry 28's mac addr
		mc_addr[0]=0x91;
		mc_addr[1]=0xE0;
		mc_addr[2]=0xF0;
		mc_addr[3]=0x00;
		mc_addr[4]=0xFF;
		mc_addr[5]=0x00;
		dest_hw = mc_addr;

		avtp_maap->cd = 1;
		avtp_maap->subtype = 0x7E;
	     
		printk(KERN_INFO "[avtp]func:%s(2), src_hw: %02x:%02x:%02x:%02x:%02x:%02x\n", __func__,
		       src_hw[0], src_hw[1], src_hw[2],
		       src_hw[3], src_hw[4], src_hw[5]);
		printk(KERN_INFO "[avtp]func:%s(2), dest_hw(raspberry 28: %02x:%02x:%02x:%02x:%02x:%02x\n", __func__,
		       dest_hw[0], dest_hw[1], dest_hw[2],
		       dest_hw[3], dest_hw[4], dest_hw[5]);	// For debuging source end!



		if(dev_hard_header(skb, dev, ETH_P_AVTP, dest_hw, src_hw, skb->len) < 0)
		  goto out;

		printk(KERN_INFO "=============MAAP heaader==========\n");
		printk(KERN_INFO "[avtp]1. cd [%u]\n", 		avtp_maap->cd);
		printk(KERN_INFO "[avtp]2. subtype [%u]\n", 		avtp_maap->subtype);
		printk(KERN_INFO "[avtp]3. sv [%u]\n", 		avtp_maap->sv);
		printk(KERN_INFO "[avtp]4. version [%u]\n", 		avtp_maap->version);
		printk(KERN_INFO "[avtp]5. message_type [%u]\n", 	avtp_maap->message_type);
		printk(KERN_INFO "[avtp]6. maap_version [%u]\n", 	avtp_maap->maap_version);
		printk(KERN_INFO "[avtp]7. maap_data_length [%lu]\n",avtp_maap->maap_data_length);
		printk(KERN_INFO "[avtp]9. req_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
			avtp_maap->requested_start_address[0], avtp_maap->requested_start_address[1], 
			avtp_maap->requested_start_address[2], avtp_maap->requested_start_address[3],
			avtp_maap->requested_start_address[4], avtp_maap->requested_start_address[5]);
		printk(KERN_INFO "[avtp]10. requested_count [%lu]\n", avtp_maap->requested_count);
		printk(KERN_INFO "[avtp]11. conflict_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
			avtp_maap->conflict_start_address[0], avtp_maap->conflict_start_address[1], 
			avtp_maap->conflict_start_address[2], avtp_maap->conflict_start_address[3],
			avtp_maap->conflict_start_address[4], avtp_maap->conflict_start_address[5]);
		printk(KERN_INFO "[avtp]13. conflict_count [%lu]\n", avtp_maap->conflict_count);
		printk(KERN_INFO "=============MAAP heaader==========\n");
	}

	avtp_xmit(skb);
	*/
	return skb;
 	
out :
	kfree_skb(skb);

	return NULL;
  
}
EXPORT_SYMBOL(avtp_create);

static int avtp_rcv(struct sk_buff* skb, 
		       struct net_device* dev, 
		       struct packet_type* pt, 
		       struct net_device* orig_dev){
  	printk(KERN_INFO "[avtp]avtp_rcv function called\n");
	printk(KERN_INFO "Receive AVTP!!\n");
	//	const struct avtp_ctr_hdr* avtp_ctr;
	//	const struct avtp_str_hdr* avtp_str;
	const struct avtp_common_hdr* avtp_common;
	const struct avtp_maap_hdr* avtp_maap;

	avtp_common = avtp_common_hdr(skb);

	skb = skb_share_check(skb, GFP_ATOMIC);	// ?????

	if(!skb)
	  goto out_of_mem;

	unsigned cd = avtp_common->cd;
	uint8_t m_type = 0;
	m_type = avtp_common->subtype;	

       	if(cd == 0){	  // stream data AVTPDU
		
	}
	else if(cd == 1){	  // control AVTPDU (include MAAP) 
	  		
		switch(m_type){
	    		
		case IIDC_66883_SUBTYPE :

		  break;

		case MMA_SUBTYPE :

		  break;

		case MAAP :
		        avtp_maap = avtp_maap_hdr(skb);	// need to check which get header data correctly because avtp header is changeable

			printk(KERN_INFO "=============Received MAAP heaader==========\n");
			printk(KERN_INFO "[avtp]1. cd [%u]\n", 		avtp_maap->cd);
			printk(KERN_INFO "[avtp]2. subtype [%u]\n", 		avtp_maap->subtype);
			printk(KERN_INFO "[avtp]3. sv [%u]\n", 		avtp_maap->sv);
			printk(KERN_INFO "[avtp]4. version [%u]\n", 		avtp_maap->version);
			printk(KERN_INFO "[avtp]5. message_type [%u]\n", 	avtp_maap->message_type);
			printk(KERN_INFO "[avtp]6. maap_version [%u]\n", 	avtp_maap->maap_version);
			printk(KERN_INFO "[avtp]7. maap_data_length [%lu]\n",avtp_maap->maap_data_length);
			printk(KERN_INFO "[avtp]9. req_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
				avtp_maap->requested_start_address[0], avtp_maap->requested_start_address[1], 
				avtp_maap->requested_start_address[2], avtp_maap->requested_start_address[3],
				avtp_maap->requested_start_address[4], avtp_maap->requested_start_address[5]);
			printk(KERN_INFO "[avtp]10. requested_count [%lu]\n", avtp_maap->requested_count);
			printk(KERN_INFO "[avtp]11. conflict_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
				avtp_maap->conflict_start_address[0], avtp_maap->conflict_start_address[1], 
				avtp_maap->conflict_start_address[2], avtp_maap->conflict_start_address[3],
				avtp_maap->conflict_start_address[4], avtp_maap->conflict_start_address[5]);
			printk(KERN_INFO "[avtp]13. conflict_count [%lu]\n", avtp_maap->conflict_count);
			printk(KERN_INFO "=============Received MAAP heaader==========\n");

			maap_rcv(avtp_maap);
		  
		  break;

		case EXPERIMENTAL_SUBTYPE :

		  break;
	  	}
	  
	}

	freeskb:
		kfree_skb(skb);
 	out_of_mem:
		return 0;

}

static int avtp_netdev_event(struct notifier_block* this, 
				unsigned long event, 
				void* ptr) {
  printk(KERN_INFO "[avtp]avtp_netdev_event function called\n");
  struct net_device* dev = netdev_notifier_info_to_dev(ptr);
  struct netdev_notifier_change_info* change_info;

  		/*
	      //For debuging - Print Device Information
	      printk(KERN_INFO "[avtp]1. dev->name [%s]\n", dev->name);
	      printk(KERN_INFO "[avtp]2. dev->base_addr [%lu]\n", dev->base_addr);
	      printk(KERN_INFO "[avtp]3. dev->ifindex [%d]\n", dev->ifindex);
	      printk(KERN_INFO "[avtp]4. dev->mtu [%d]\n", dev->mtu);
	      printk(KERN_INFO "[avtp]5. dev->type [%hu]\n", dev->type);
	      printk(KERN_INFO "[avtp]6. dev->perm_addr [%s]\n", dev->perm_addr);
	      printk(KERN_INFO "[avtp]7. dev->addr_len [%02x]\n", dev->addr_len);
	      printk(KERN_INFO "[avtp]8. dev->dev_id [%hu]\n", dev->dev_id);
	      printk(KERN_INFO "[avtp]9. dev->last_rx [%lu]\n", dev->last_rx);
	      printk(KERN_INFO "[avtp]10. dev->dev_addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
	             dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2],
	             dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5]);
	      printk(KERN_INFO "[avtp]11. dev->broadcast [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
	             dev->broadcast[0], dev->broadcast[1], dev->broadcast[2],
	             dev->broadcast[3], dev->broadcast[4], dev->broadcast[5]);	      
		*/
  
  switch(event) {
  default: 
    break;
  }
  return NOTIFY_DONE;
}

static struct notifier_block avtp_netdev_notifier = {
  .notifier_call = avtp_netdev_event,
};

static const struct file_operations avtp_seq_fops = {
  .owner = THIS_MODULE,
};

static int __net_init avtp_net_init(struct net *net) {
  if(!proc_create("avtp", S_IRUGO, net->proc_net, &avtp_seq_fops))
    return -ENOMEM;
  return 0;
}

static void __net_init avtp_net_exit(struct net *net) {
  remove_proc_entry("avtp",net->proc_net);
}

static struct pernet_operations avtp_net_ops = {
  .init = avtp_net_init,
  .exit = avtp_net_exit,
};

static int __init avtp_proc_init(void) {
  return register_pernet_subsys(&avtp_net_ops);
}

static struct packet_type avtp_packet_type __read_mostly = {
  .type = cpu_to_be16(ETH_P_AVTP),
  .func = avtp_rcv
};

void avtp_timer_callback(unsigned long arg) {
  	int ret;
	char strEth[5] = "eth0";

	if(avtp_dev == NULL) {
	  	avtp_dev = first_net_device(&init_net);

	  	while(avtp_dev) {
	    		if(!strcmp(avtp_dev->name, strEth)) break;
		        avtp_dev = next_net_device(avtp_dev);
	  	}

		/* For Debugging */
		printk(KERN_INFO "func: %s,	avtp_dev->name: %s\n", __func__, avtp_dev->name);
	}	
}

int avtp_timer_init_module(void) {
  	int ret;

	avtp_dev = NULL;

	setup_timer(&avtp_timer, avtp_timer_callback, 0);

	ret = mod_timer(&avtp_timer, jiffies + msecs_to_jiffies(60000));

	if(ret) return 0;

	return 0;
}

void avtp_timer_cleanup_module(void) {
  	int ret;

	ret = del_timer(&avtp_timer);

	if(ret) return;

	return;
}


void avtp_init(void){
	printk(KERN_INFO "======================================\n");
	printk(KERN_INFO "[avtp]avtp init function called\n");
	printk(KERN_INFO "======================================\n");
	struct sk_buff *skb;
//	char strEth[5] = "eth0";

	//	avtp_sock_check();	// need to check which function necessary or not
	dev_add_pack(&avtp_packet_type);
       	avtp_proc_init();
	register_netdevice_notifier(&avtp_netdev_notifier);

	avtp_timer_init_module();

//	if(avtp_dev == NULL) {
//	  	avtp_dev = first_net_device(&init_net);

//	  	while(avtp_dev) {
//	    		if(!strcmp(avtp_dev->name, strEth)) break;
//		        avtp_dev = next_net_device(avtp_dev);
//	  	}

		/* For Debugging */
//		printk(KERN_INFO "func: %s, avtp_dev->name: %s\n", __func__, avtp_dev->name);
//	}

}

