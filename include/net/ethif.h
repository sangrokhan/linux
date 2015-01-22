#ifndef _ETHIF_H
#define _ETHIF_H

#include <linux/types.h>
#include <linux/std_types.h>
#include <net/eth.h>

typedef struct {

} EthIf_ConfigType;

typedef enum {
  ETHCTRL_STATE_UNINIT = 0x00,
  ETHCTRL_STATE_INIT
} EthIf_StateType;

#endif
