#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <net/maap.h>

// MODULE_LICENSE("GPL");

/* MAAP Probe Constant Values */
const int MAAP_PROBE_RETRANSMITS = 3;
const int MAAP_PROBE_INTERVAL_BASE = 500;		// 500 ms
const int MAAP_PROBE_INTERVAL_VARIATION = 100;		// 100 ms
const int MAAP_ANNOUNCE_INTERVAL_BASE = 30;		// 30 s
const int MAAP_ANNOUNCE_INTERVAL_VARIATION = 2;		// 2 s

int maap_state;
int maap_probe_count;

unsigned char generated_address[6];

static struct timer_list announce_timer;
static struct timer_list probe_timer;

void announce_timer_callback(void);
void probe_timer_callback(void);

void generate_address(unsigned char* requestor_address) {
  	unsigned int rand;

	generated_address[0] = 0x91;
	generated_address[1] = 0xE0;
	generated_address[2] = 0xF0;
	generated_address[3] = 0x00;

  	// srand((unsigned)time(NULL) + (unsigned)requestor_address);	// srand() is not available
        get_random_bytes(&rand, sizeof(rand));
	rand = rand % 254;

	generated_address[4] = rand;	// Need to debug

	/* For Debugging */
	printk("func: %s,	rand1: %02x\n", __func__, rand);

	get_random_bytes(&rand, sizeof(rand));
	rand = rand % 256;

	generated_address[5] = rand;	// Need to debug

	/* For Debugging */
	printk("func: %s,	rand2: %02x\n", __func__, rand);

	if(maap_state == INITIAL) {
	  	init_maap_probe_count();
	  	maap_init_timer(&probe_timer, probe_timer_callback, MAAP_PROBE_INTERVAL_BASE, 0);
	}
}

/* Set the value of maap_probe_count to MAAP_PROBE_RETRANSMITS */
void init_maap_probe_count() {
  	maap_probe_count = MAAP_PROBE_RETRANSMITS;
}

/* Decrement the value of maap_probe_count by one(1) */
void dec_maap_probe_count() {
  	maap_probe_count --;	// maap_probe_count -= 1;	// Which is better??
     
	/* Send a probeCount! event if the resulting value of maap_probe_count is less than of equal to zero(0) */
	if(maap_probe_count < 0 || maap_probe_count == 0) {
	  	if(maap_state == PROBE) {
		  	maap_cleanup_timer(&probe_timer);
			maap_init_timer(&announce_timer, announce_timer_callback, 0, MAAP_ANNOUNCE_INTERVAL_BASE);
	  	}
	}
}

int compare_MAC(unsigned char* current_mac_address, unsigned char* received_mac_address) {
	int result;

	result = memcmp(current_mac_address, received_mac_address, strlen(current_mac_address));

	if(result < 0) {
	  	return 1;
	}

	return 0;
}

/* Send a MAAP_PROBE PDU */
void sProbe() {
    	struct maaphdr* maap;

	maap->message_type = MAAP_PROBE;
	memcpy(maap->requested_start_address, generated_address, MAC_ADDR_LEN);
    	maap->requested_count = 0x00;
	maap->conflict_start_address[0] = 0x00;
	maap->conflict_start_address[1] = 0x00;
	maap->conflict_start_address[2] = 0x00;
	maap->conflict_start_address[3] = 0x00;
	maap->conflict_start_address[4] = 0x00;
	maap->conflict_start_address[5] = 0x00;
	maap->conflict_count = 0;
}

/* Send a MAAP_DEFEND PDU */
void sDefend(struct maaphdr *rcv_maap) {
    	struct maaphdr* maap;

	maap->message_type = MAAP_DEFEND;
//	maap->requested_start_address = ;
//    	maap->requested_count = ;
	memcpy(maap->conflict_start_address, rcv_maap->requested_start_address, MAC_ADDR_LEN);
	maap->conflict_count = rcv_maap->requested_count;
}

/* Send a MAAP_ANNOUNCE PDU */
void sAnnounce() {
    	struct maaphdr* maap;

	maap->message_type = MAAP_ANNOUNCE;
	memcpy(maap->requested_start_address, generated_address, MAC_ADDR_LEN);
    	maap->requested_count = 0x00;
	maap->conflict_start_address[0] = 0x00;
	maap->conflict_start_address[1] = 0x00;
	maap->conflict_start_address[2] = 0x00;
	maap->conflict_start_address[3] = 0x00;
	maap->conflict_start_address[4] = 0x00;
	maap->conflict_start_address[5] = 0x00;
	maap->conflict_count = 0;
}

// Need to determine parameter
static int maap_rcv(struct maaphdr *rcv_maap) {
  	int ret;

	switch(rcv_maap->message_type) {
	case MAAP_PROBE:
  		if(maap_state == PROBE) {
		  	if(!(ret = compare_MAC(generated_address, rcv_maap->requested_start_address))) break;
	  		
			maap_cleanup_timer(&probe_timer);
			maap_state = INITIAL;
			generate_address(rcv_maap->requested_start_address);
  		}

		if(maap_state == DEFEND) {
		  	sDefend(rcv_maap);
		}

		break;

	case MAAP_DEFEND:
	  	if(maap_state == PROBE) {
		  	maap_cleanup_timer(&probe_timer);
	  	}

		if(maap_state == DEFEND) {
		  	if(!(ret = compare_MAC(generated_address, rcv_maap->requested_start_address))) break;

		        maap_cleanup_timer(&announce_timer);
		}

		maap_state = INITIAL;
		generate_address(rcv_maap->requested_start_address);

		break;

 	case MAAP_ANNOUNCE:
	  	if(maap_state == PROBE) {
		  	maap_cleanup_timer(&probe_timer);
		}

		if(maap_state == DEFEND) {
		  	if(!(ret = compare_MAC(generated_address, rcv_maap->requested_start_address))) break;

		  	maap_cleanup_timer(&announce_timer);

		}

		maap_state = INITIAL;
		generate_address(rcv_maap->requested_start_address);

		break;
	}
	return 0;
}


// void announce_timer_callback(unsigned long arg) {
void announce_timer_callback() {
  	sAnnounce();

	if(maap_state == PROBE) {
	  	maap_state = DEFEND;
	}
}

// void probe_timer_callback(unsigned long arg) {
void probe_timer_callback() {
  	sProbe();

	if(maap_state == INITIAL) {
	  	maap_state = PROBE;
	}

	if(maap_state == PROBE) {
	  	dec_maap_probe_count();
	}
}

int maap_init_timer(struct timer_list *timer, void (*function)(void), int second, int millisecond) {
  	int ret;

	setup_timer(timer, function, 0);

	ret = mod_timer(&timer, jiffies + msecs_to_jiffies(second * 1000 + millisecond));
	if(ret) printk("Error in mod_timer(announce_timer)\n");

	return 0;
}

void maap_cleanup_timer(struct timer_list *timer) {
  	int ret;

	ret = del_timer(&timer);
	if(ret) printk("The announce timer is still in use...\n");

	return;
}
