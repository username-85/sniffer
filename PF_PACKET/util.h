#ifndef UTIL_H
#define UTIL_H

#include <ncurses.h>

void print_data_hex(WINDOW *win, unsigned char *buf, int size);
void print_data_ascii(WINDOW *win, unsigned char *buf, int size);
void print_unknown_packet(WINDOW *win, unsigned char *buf, int bufsize);

#endif
