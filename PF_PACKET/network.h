#ifndef NETWORK_H
#define NETWORK_H

int get_iphdr_len(unsigned char const *buf);
void *get_iphdr_ptr(unsigned char const *buf);
int check_iphdr(unsigned char const *buf, int bufsize);

int get_icmphdr_len(void);
void *get_icmp_ptr(unsigned char const *buf);
int check_icmphdr(unsigned char const *buf, int bufsize);

#endif
