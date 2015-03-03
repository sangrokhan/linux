#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <net/maap.h>
#include <net/avtp.h>

// MODULE_LICENSE("GPL");

/* MAAP Probe Constant Values */
const int MAAP_PROBE_RETRANSMITS = 3;
const int MAAP_PROBE_INTERVAL_BASE = 500;		// 500 ms
const int MAAP_PROBE_INTERVAL_VARIATION = 100;		// 100 ms
const int MAAP_ANNOUNCE_INTERVAL_BASE = 30;		// 30 s
const int MAAP_ANNOUNCE_INTERVAL_VARIATION = 2;		// 2 s

int maap_state;
int maap_probe_count;

int announce_mode;
int probe_mode;

unsigned char generated_address[6];
unsigned char multicast_address[6];

static struct timer_list announce_timer;
static struct timer_list probe_timer;

void announce_timer_callback(void);
void probe_timer_callback(void);

struct maaphdr *tx_maap;

void generate_address(unsigned char* requestor_address) {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

  	unsigned int rand;

	generated_address[0] = 0x91;
	generated_address[1] = 0xE0;
	generated_address[2] = 0xF0;
	generated_address[3] = 0x00;

  	// srand((unsigned)time(NULL) + (unsigned)requestor_address);	// srand() is not available
        get_random_bytes(&rand, sizeof(rand));
	rand = rand % 254;

	generated_address[4] = 0x28; //rand;	// Need to debug

	/* For Debugging */
	printk("func: [MAAP]%s,	rand1: %02x\n", __func__, rand);

	get_random_bytes(&rand, sizeof(rand));
	rand = rand % 256;

	generated_address[5] = 0x28; //rand;	// Need to debug

	/* For Debugging */
	printk("func: [MAAP]%s,	rand2: %02x\n", __func__, rand);

	if(maap_state == INITIAL) {
	  	init_maap_probe_count();
		memcpy(tx_maap->requested_start_address, generated_address, MAC_ADDR_LEN);		// tx_maap = maap;

		probe_mode = 1;
	  	maap_init_timer(&probe_timer, probe_timer_callback, 0, MAAP_PROBE_INTERVAL_BASE);
	}
}

/* Set the value of maap_probe_count to MAAP_PROBE_RETRANSMITS */
void init_maap_probe_count() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

  	maap_probe_count = MAAP_PROBE_RETRANSMITS;
}

/* Decrement the value of maap_probe_count by one(1) */
void dec_maap_probe_count() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

  	maap_probe_count --;	// maap_probe_count -= 1;	// Which is better??
     
	/* Send a probeCount! event if the resulting value of maap_probe_count is less than of equal to zero(0) */
	if(maap_probe_count < 0 || maap_probe_count == 0) {
	  	if(maap_state == PROBE) {
		  	probe_mode = 0;
		  	maap_cleanup_timer(&probe_timer);

			announce_mode = 1;
			maap_init_timer(&announce_timer, announce_timer_callback, MAAP_ANNOUNCE_INTERVAL_BASE, 0);
	  	}
	}
}

int compare_MAC(unsigned char* current_mac_address, unsigned char* received_mac_address) {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

	int result;

	result = memcmp(current_mac_address, received_mac_address, strlen(current_mac_address));

	if(result == 0) {
	  	return 1;
	}

	return 0;
}

/* Send a MAAP_PROBE PDU */
void sProbe() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

	tx_maap->message_type = MAAP_PROBE;
	
        printk(KERN_INFO "::::::sizeof(maaphdr):[%d] in func:[%s]::::::\n", sizeof(struct maaphdr), __func__);     	
	//unsigned char *frm = (unsigned char *)tx_maap;
	//frm[0] |= htons(0xFE);
	//tx_maap->m_type = htons(0xFE);
	
	//for debug
	printk(KERN_INFO "====MAAP heaader====[ %s ]in maap.c======\n", __func__);
	//printk(KERN_INFO "[avtp]1. cd [%u]\n",          tx_maap->cd);
	//printk(KERN_INFO "[avtp]2. subtype [%02x]\n",             tx_maap->subtype);
	printk(KERN_INFO "[avtp]2. subtype [%02x]\n",             tx_maap->d_type);
	printk(KERN_INFO "[avtp]3. sv [%u]\n",          tx_maap->sv);
	printk(KERN_INFO "[avtp]4. version [%u]\n",             tx_maap->version);
	printk(KERN_INFO "[avtp]5. message_type [%u]\n",        tx_maap->message_type);
	printk(KERN_INFO "[avtp]6. maap_version [%u]\n",        tx_maap->maap_version);
	printk(KERN_INFO "[avtp]7. maap_data_length [%lu]\n",tx_maap->maap_data_length);
	printk(KERN_INFO "[avtp]8. stream_id [%u]\n",tx_maap->stream_id);
	printk(KERN_INFO "[avtp]9. req_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
	       tx_maap->requested_start_address[0], tx_maap->requested_start_address[1],
	       tx_maap->requested_start_address[2], tx_maap->requested_start_address[3],
	       tx_maap->requested_start_address[4], tx_maap->requested_start_address[5]);
	printk(KERN_INFO "[avtp]10. req count [%u]\n",tx_maap->requested_count);
	printk(KERN_INFO "[avtp]11. conflict_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
	       tx_maap->conflict_start_address[0], tx_maap->conflict_start_address[1],
	       tx_maap->conflict_start_address[2], tx_maap->conflict_start_address[3],
	       tx_maap->conflict_start_address[4], tx_maap->conflict_start_address[5]);
	printk(KERN_INFO "[avtp]12. conflict_count [%u]\n", tx_maap->conflict_count);
	printk(KERN_INFO "======before send=======MAAP heaader====in maap.c======\n");
	
	avtp_create(tx_maap, NULL, NULL, multicast_address);
}

/* Send a MAAP_DEFEND PDU */
void sDefend(struct maaphdr *rx_maap) {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);
        printk(KERN_INFO "::::::sizeof(maaphdr):[%d] in func:[%s]::::::\n", sizeof(struct maaphdr), __func__);     	
	tx_maap->message_type = MAAP_DEFEND;
	memcpy(tx_maap->requested_start_address, rx_maap->requested_start_address, MAC_ADDR_LEN);
	tx_maap->requested_count = rx_maap->requested_count;
	memcpy(tx_maap->conflict_start_address, rx_maap->requested_start_address, MAC_ADDR_LEN);
	tx_maap->conflict_count = rx_maap->requested_count;

	//unsigned char *frm = (unsigned char *)tx_maap;
	//frm[0] |= htons(0xFE);
	//tx_maap->m_type = htons(0xFE);

	//for debug
	printk(KERN_INFO "====MAAP heaader====[ %s ]in maap.c======\n", __func__);
	//printk(KERN_INFO "[avtp]1. cd [%u]\n",          tx_maap->cd);
	//printk(KERN_INFO "[avtp]2. subtype [%02x]\n",             tx_maap->subtype);
	printk(KERN_INFO "[avtp]2. subtype [%02x]\n",             tx_maap->d_type);
	printk(KERN_INFO "[avtp]3. sv [%u]\n",          tx_maap->sv);
	printk(KERN_INFO "[avtp]4. version [%u]\n",             tx_maap->version);
	printk(KERN_INFO "[avtp]5. message_type [%u]\n",        tx_maap->message_type);
	printk(KERN_INFO "[avtp]6. maap_version [%u]\n",        tx_maap->maap_version);
	printk(KERN_INFO "[avtp]7. maap_data_length [%u]\n",tx_maap->maap_data_length);
	printk(KERN_INFO "[avtp]8. stream_id [%u]\n",tx_maap->stream_id);
	printk(KERN_INFO "[avtp]9. req_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
	       tx_maap->requested_start_address[0], tx_maap->requested_start_address[1],
	       tx_maap->requested_start_address[2], tx_maap->requested_start_address[3],
	       tx_maap->requested_start_address[4], tx_maap->requested_start_address[5]);
	printk(KERN_INFO "[avtp]10. req count [%u]\n",tx_maap->requested_count);
	printk(KERN_INFO "[avtp]11. conflict_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
	       tx_maap->conflict_start_address[0], tx_maap->conflict_start_address[1],
	       tx_maap->conflict_start_address[2], tx_maap->conflict_start_address[3],
	       tx_maap->conflict_start_address[4], tx_maap->conflict_start_address[5]);
	printk(KERN_INFO "[avtp]12. conflict_count [%u]\n", tx_maap->conflict_count);
	printk(KERN_INFO "======before send=======MAAP heaader====in maap.c======\n");

	avtp_create(tx_maap, NULL, NULL, multicast_address);	
}

/* Send a MAAP_ANNOUNCE PDU */
void sAnnounce() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);
        printk(KERN_INFO "::::::sizeof(maaphdr):[%d] in func:[%s]::::::\n", sizeof(struct maaphdr), __func__);     	
 	tx_maap->message_type = MAAP_ANNOUNCE;
	memcpy(tx_maap->requested_start_address, generated_address, MAC_ADDR_LEN);
    	tx_maap->requested_count = 0xcc;
	tx_maap->conflict_start_address[0] = 0x00;
	tx_maap->conflict_start_address[1] = 0x00;
	tx_maap->conflict_start_address[2] = 0x00;
	tx_maap->conflict_start_address[3] = 0x00;
	tx_maap->conflict_start_address[4] = 0x00;
	tx_maap->conflict_start_address[5] = 0x00;
	tx_maap->conflict_count = 0xdd;

	//	unsigned char *frm = (unsigned char *)tx_maap;
	//frm[0] |= htons(0xFE);


	// for debug
	printk(KERN_INFO "====MAAP heaader====[ %s ]in maap.c======\n", __func__);
	//printk(KERN_INFO "[avtp]1. cd [%u]\n",          tx_maap->cd);
	//printk(KERN_INFO "[avtp]2. subtype [%02x]\n",             tx_maap->subtype);
	printk(KERN_INFO "[avtp]2. subtype [%02x]\n",             tx_maap->d_type);
	printk(KERN_INFO "[avtp]3. sv [%u]\n",          tx_maap->sv);
	printk(KERN_INFO "[avtp]4. version [%u]\n",             tx_maap->version);
	printk(KERN_INFO "[avtp]5. message_type [%u]\n",        tx_maap->message_type);
	printk(KERN_INFO "[avtp]6. maap_version [%u]\n",        tx_maap->maap_version);
	printk(KERN_INFO "[avtp]7. maap_data_length [%u]\n",tx_maap->maap_data_length);
	printk(KERN_INFO "[avtp]8. stream_id [%u]\n",tx_maap->stream_id);
	printk(KERN_INFO "[avtp]9. req_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
	       tx_maap->requested_start_address[0], tx_maap->requested_start_address[1],
	       tx_maap->requested_start_address[2], tx_maap->requested_start_address[3],
	       tx_maap->requested_start_address[4], tx_maap->requested_start_address[5]);
	printk(KERN_INFO "[avtp]10. req count [%lu]\n",tx_maap->requested_count);
	printk(KERN_INFO "[avtp]11. conflict_start_addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
	       tx_maap->conflict_start_address[0], tx_maap->conflict_start_address[1],
	       tx_maap->conflict_start_address[2], tx_maap->conflict_start_address[3],
	       tx_maap->conflict_start_address[4], tx_maap->conflict_start_address[5]);
	printk(KERN_INFO "[avtp]12. conflict_count [%u]\n", tx_maap->conflict_count);
	printk(KERN_INFO "======before send=======MAAP heaader====in maap.c======\n");

	avtp_create(tx_maap, NULL, NULL, multicast_address);
}

int maap_rcv(struct maaphdr *rx_maap) {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

  	int ret;

	switch(rx_maap->message_type) {
	case MAAP_PROBE:
  		if(maap_state == PROBE) {
		  	if(!(ret = compare_MAC(generated_address, rx_maap->requested_start_address))) break;
	  		
			probe_mode = 0;
			maap_cleanup_timer(&probe_timer);
			maap_state = INITIAL;
			generate_address(rx_maap->requested_start_address);
  		}

		if(maap_state == DEFEND) {
		  	sDefend(rx_maap);
		}

		break;

	case MAAP_DEFEND:
	  	if(maap_state == PROBE) {
		  	probe_mode = 0;
		  	maap_cleanup_timer(&probe_timer);
	  	}

		if(maap_state == DEFEND) {
		  	if(!(ret = compare_MAC(generated_address, rx_maap->requested_start_address))) break;

			announce_mode = 0;
		        maap_cleanup_timer(&announce_timer);
		}

		maap_state = INITIAL;
		generate_address(rx_maap->requested_start_address);

		break;

 	case MAAP_ANNOUNCE:
	  	if(maap_state == PROBE) {
		  	probe_mode = 0;
		  	maap_cleanup_timer(&probe_timer);
		}

		if(maap_state == DEFEND) {
		  	if(!(ret = compare_MAC(generated_address, rx_maap->requested_start_address))) break;

			announce_mode = 0;
		  	maap_cleanup_timer(&announce_timer);
		}

		maap_state = INITIAL;
		generate_address(rx_maap->requested_start_address);

		break;
	}
	return 0;
}


void announce_timer_callback() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

	int ret;

  	sAnnounce();

	if(maap_state == PROBE) {
	  	maap_state = DEFEND;
	}

	if(announce_mode == 1) {
		ret = mod_timer(&announce_timer, jiffies + msecs_to_jiffies(MAAP_ANNOUNCE_INTERVAL_BASE * 1000));
		if(ret) printk("Error in mod_timer(announce_timer)\n");
	}
}

// void probe_timer_callback(unsigned long arg) {
void probe_timer_callback() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

        int ret;

  	sProbe();

	if(maap_state == INITIAL) {
	  	maap_state = PROBE;
	}

	if(maap_state == PROBE) {
	  	dec_maap_probe_count();
	}

	if(probe_mode == 1) {
		ret = mod_timer(&probe_timer, jiffies + msecs_to_jiffies(MAAP_PROBE_INTERVAL_BASE * 10));	// 5s	// For Debugging(the original is 500 ms)
		if(ret) printk("Error in mod_timer(announce_timer)\n");
	}
}

int maap_init_timer(struct timer_list *timer, void (*function)(void), int second, int millisecond) {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

  	int ret;

	setup_timer(timer, function, 0);

	ret = mod_timer(timer, jiffies + msecs_to_jiffies((second * 1000) + millisecond));
	if(ret) printk("Error in mod_timer(announce_timer)\n");

	return 0;
}

void maap_cleanup_timer(struct timer_list *timer) {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

  	int ret;

	ret = del_timer(timer);
	if(ret) printk("The announce timer is still in use...\n");

	return;
}

void maap_init() {
  	/* For Debugging */
  	printk(KERN_INFO "func: [MAAP]%s\n", __func__);

	announce_mode = 0;
	probe_mode = 0;

	multicast_address[0] = 0x91;
	multicast_address[1] = 0xE0;
	multicast_address[2] = 0xF0;
	multicast_address[3] = 0x00;
	multicast_address[4] = 0xFF;
	multicast_address[5] = 0x00;

  	maap_state = INITIAL;
	tx_maap = kmalloc(sizeof(struct maaphdr), GFP_KERNEL);

	if(!tx_maap)  {
	  	printk(KERN_INFO "[Error] maap_init(): Couldn't initialize.\n");

		return;
	}

	tx_maap->d_type = 0xFE;
 	//tx_maap->subtype = 0x7E;
	tx_maap->sv = 0;
	tx_maap->version = 0x0;
  	tx_maap->message_type = 0;
  	tx_maap->maap_version = 1;
  	tx_maap->maap_data_length = 0x10;
  	tx_maap->stream_id = 0x0000000000000000;
  	tx_maap->requested_start_address[0] = 0x00;
	tx_maap->requested_start_address[1] = 0x00;
	tx_maap->requested_start_address[2] = 0x00;
	tx_maap->requested_start_address[3] = 0x00;
	tx_maap->requested_start_address[4] = 0x00;
	tx_maap->requested_start_address[5] = 0x00;
	tx_maap->requested_count = 0xaa;
	tx_maap->conflict_start_address[0] = 0x00;
	tx_maap->conflict_start_address[1] = 0x00;
	tx_maap->conflict_start_address[2] = 0x00;
	tx_maap->conflict_start_address[3] = 0x00;
	tx_maap->conflict_start_address[4] = 0x00;
	tx_maap->conflict_start_address[5] = 0x00;
	tx_maap->conflict_count = 0xbb;
}
