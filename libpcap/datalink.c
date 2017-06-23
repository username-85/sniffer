#include "datalink.h"
#include <string.h>

int get_ethhdr_len(void)
{
	return sizeof(struct ethhdr);
}

int check_ethhdr(unsigned char const *buf, int bufsize)
{
	(void)buf; //unused
	if (buf && bufsize > 0 && get_ethhdr_len() <= bufsize)
		return 0;
	return -1;
}
