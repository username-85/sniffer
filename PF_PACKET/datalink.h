#ifndef DATALINK_H
#define DATALINK_H

#include <net/ethernet.h>

int get_ethhdr_len(void);
int check_ethhdr(unsigned char const *buf, int bufsize);

#endif
