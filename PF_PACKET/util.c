#include "util.h"

void print_data_hex(WINDOW *win, unsigned char *buf, int size)
{
	wprintw(win, "DATA HEX\t");
	for(int i=0; i < size; i++)
		wprintw(win," %.2X ", buf[i]);
}

void print_data_ascii(WINDOW *win, unsigned char *buf, int size)
{
	wprintw(win, "DATA ASCII\t");
	for(int i=0; i < size; i++)
		wprintw(win,"%c", buf[i]);
}

void print_unknown_packet(WINDOW *win, unsigned char *buf, int bufsize)
{
	wprintw(win, "UNKNOWN\t");
	wprintw(win, "\n");
	print_data_ascii(win, buf, bufsize);
	wprintw(win, "\n");
	print_data_hex(win, buf, bufsize);
}

