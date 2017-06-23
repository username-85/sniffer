#ifndef TRANSPORT_H
#define TRANSPORT_H

void *get_transport_hdr_ptr(unsigned char const *buf);

int get_tcphdr_len(unsigned char const *buf);
int check_tcphdr(unsigned char const *buf, int bufsize);

int get_udphdr_len(void);
int check_udphdr(unsigned char const *buf, int bufsize);

#endif
