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

//struct net_device *avtp_dev;

/*
void maap_send(unsigned cd,
	       unsigned subtype,
	       unsigned sv,
	       unsigned message_type,
	       unsigned maap_version,
	       unsigned maap_data_len,
	       const unsigned char* req_start_addr,
	       __be16 req_count,
	       const unsisgned char* conflict_start_addr,
	       __be16 conflict_count){

	struct sk_buff* skb;

	skb = avtp_create(cd, subtype, sv, NULL, message_type, maap_version, maap_data_len, 
			  NULL, req_start_addr, req_count, conflict_start_addr, conflict_count);

	if(skb == NULL)
	  return;

	avtp_xmit(skb);
}
*/

void avtp_xmit(struct sk_buff* skb){

  	printk(KERN_INFO "[avtp]avtp_xmit function called\n");

  	//	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);

  	dev_queue_xmit(skb);
}

struct sk_buff* avtp_create(uint8_t type,
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
	//struct avtp_common_hdr* avtp_common;
	//struct avtp_ctr_hdr* avtp_ctr;
	//struct avtp_str_hdr* avtp_str;
	struct avtp_maap_hdr* avtp_maap;
	unsigned char* avtp_ptr;

	int hlen = LL_RESERVED_SPACE(dev);	// ???????
	int tlen = dev->needed_tailroom;	// ???????

	if(type == MAAP){

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

		if(dev_hard_header(skb, dev, ETH_P_AVTP, dest_hw, src_hw, skb->len) < 0)
		  goto out;
		/*
		avtp_maap->cd = 1;
		avtp_maap->subtype = 0x7E;
		avtp_maap->sv = 0;
		avtp_maap->version = 0;
		avtp_maap->message_type = message_type;
		avtp_maap->maap_version = 1;
		avtp_maap->maap_data_length = 16;
		memset(avtp_maap->stream_id, 0, 8);
		memcpy(avtp_maap->requested_start_address, req_start_addr, 6);
		avtp_maap->requested_count = req_count;
		memcpy(avtp_maap->conflict_start_address, conflict_start_addr, 6);
		avtp_maap->conflict_count = conflict_count;
		*/


		printk(KERN_INFO "=============MAAP heaader==========\n");
		printk(KERN_INFO "[avtp]1. cd [%u]\n", 		avtp_maap->cd);
		printk(KERN_INFO "[avtp]2. subtype [%u]\n", 		avtp_maap->subtype);
		printk(KERN_INFO "[avtp]3. sv [%u]\n", 		avtp_maap->sv);
		printk(KERN_INFO "[avtp]4. version [%u]\n", 		avtp_maap->version);
		printk(KERN_INFO "[avtp]5. message_type [%u]\n", 	avtp_maap->message_type);
		printk(KERN_INFO "[avtp]6. maap_version [%u]\n", 	avtp_maap->maap_version);
		printk(KERN_INFO "[avtp]7. maap_data_length [%lu]\n",avtp_maap->maap_data_length);
		printk(KERN_INFO "[avtp]8. stream_id[0] [%d]\n", 	avtp_maap->stream_id[0]);
		printk(KERN_INFO "=============MAAP heaader==========\n");
		//printk(KERN_INFO "9. dev->last_rx [%lu]\n", dev->last_rx);
		//printk(KERN_INFO "10.  [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
		//	dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2],
		//       dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5]);
		//printk(KERN_INFO "11. dev->broadcast [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
		//       dev->broadcast[0], dev->broadcast[1], dev->broadcast[2],
		//       dev->broadcast[3], dev->broadcast[4], dev->broadcast[5]);
	}

	avtp_xmit(skb);

	return skb;
 	
out :
	kfree_skb(skb);

	return NULL;
  
	/*
       	if(cd == 0){	  // stream data AVTPDU

		skb = alloc_skb(avtp_str_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);	// what is hlen, tlen, GFP_ATOMIC ???

  		if(skb == NULL) 
    			return NULL;
  
  		skb_reserve(skb, hlen);
  		skb_reset_network_header(skb);
  		avtp = (struct aptp_str_hdr *)skb_put(skb, avtp_str_hdr_len(dev));


	}
	else if(cd == 1){	  // control AVTPDU (include MAAP) 

		skb = alloc_skb(avtp_ctr_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);	// what is hlen, tlen, GFP_ATOMIC ???

  		if(skb == NULL) 
    			return NULL;
  
  		skb_reserve(skb, hlen);
  		skb_reset_network_header(skb);
  		avtp = (struct aptp_ctr_hdr *)skb_put(skb, avtp_ctr_hdr_len(dev));
	}
	*/

}
EXPORT_SYMBOL(avtp_create);

static int avtp_rcv(struct sk_buff* skb, 
		       struct net_device* dev, 
		       struct packet_type* pt, 
		       struct net_device* orig_dev){
  	printk(KERN_INFO "[avtp]avtp_rcv function called\n");
	const struct avtp_ctr_hdr* avtp_ctr;
	const struct avtp_str_hdr* avtp_str;
	const struct avtp_common_hdr* avtp_common;

	avtp_common = avtp_common_hdr(skb);

	skb = skb_share_check(skb, GFP_ATOMIC);	// ?????

	if(!skb)
	  goto out_of_mem;

	int cd = avtp_common->cd;
	// need to declare m_type ? for switch

       	if(cd == 0){	  // stream data AVTPDU

		
	}
	else if(cd == 1){	  // control AVTPDU (include MAAP) 
	  /*	
		switch(m_type){
	    		
		case IIDC_66883_SUBTYPE :

		  break;

		case MMA_SUBTYPE :

		  break;

		case MAAP :

		  

		  break;

		case EXPERIMENTAL_SUBTYPE :

		  break;
	  	}
	  */
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

	      //Print Device Information
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


void avtp_init(void){
	printk(KERN_INFO "======================================\n");
	printk(KERN_INFO "[avtp]avtp init function called\n");
	printk(KERN_INFO "======================================\n");
	struct sk_buff *skb;

	//	avtp_sock_check();	// ?????
	dev_add_pack(&avtp_packet_type);
	printk(KERN_INFO "[avtp]dev_add_pack() complete\n");
       	avtp_proc_init();
	printk(KERN_INFO "[avtp]avtp_proc_init() complete\n");
	register_netdevice_notifier(&avtp_netdev_notifier);
	printk(KERN_INFO "[avtp]register_netdevice_notifier() complete\n");

}

