#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <net/maap.h>

MODULE_LICENSE("GPL");

/* MAAP Probe Constant Values */
const int MAAP_PROBE_RETRANSMITS = 3;
const int MAAP_PROBE_INTERVAL_BASE = 500;		// 500 ms
const int MAAP_PROBE_INTERVAL_VARIATION = 100;		// 100 ms
const int MAAP_ANNOUNCE_INTERVAL_BASE = 30;		// 30 s
const int MAAP_ANNOUNCE_INTERVAL_VARIATION = 2;		// 2 s

int state;
int maap_probe_count;

static struct timer_list announce_timer;
static struct timer_list probe_timer;

void announce_timer_callback(unsigned long arg);

void generate_address() {
	
}

/* Set the value of maap_probe_count to MAAP_PROBE_RETRANSMITS */
void init_maap_probe_count() {
  	maap_probe_count = MAAP_PROBE_RETRANSMITS;
}

/* Decrement the value of maap_probe_count by one(1) */
void dec_maap_probe_count() {
  	maap_probe_count --;
     
	/* Send a probeCount! event if the resulting value of maap_probe_count is less than of equal to zero(0) */
	if(maap_probe_count < 0 || maap_probe_count == 0) {
	  	if(state == PROBE) {
		  	cleanup_timer(&probe_timer);
			init_timer(&announce_timer, announce_timer_callback());

			// TO-DO: Send a MAAP_ANNOUNCE PDU
	  	}
	}
}

void compare_MAC() {
}

void sProbe() {
    	struct maaphdr* maap;
}

void sDefend() {
}

void sAnnounce() {
}

void announce_timer_callback(unsigned long arg) {
}

void probe_timer_callback(unsigned long arg) {
}

int init_timer(struct timer_list *timer, void *function) {
  	int ret;

	setup_timer(&timer, function, 0);

	ret = mod_timer(&timer, jiffies + msecs_to_jiffies(200));
	if(ret) printk("Error in mod_timer(announce_timer)\n");

	return 0;
}

void cleanup_timer(struct timer_list *timer) {
  	int ret;

	ret = del_timer(&timer);
	if(ret) printk("The announce timer is still in use...\n");

	return;
}
