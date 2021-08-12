// Copyright (c) 2020 Technica Engineering GmbH
// Copyright (c) 2016 Radu Velea

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "light_pcapng_ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int PACKETS_PER_FILE = 100000;
int NUMBER_OF_FILES = 12;

char * get_file_name(const char* prefix, int counter){
	char *extension = ".pcapng";
	char suffix[7];
	sprintf(suffix, "%05d", counter);
	char *c = malloc(strlen(prefix)+strlen(suffix)+strlen(extension)+1);
	strcpy(c,prefix);
	strcat(c,suffix);
	strcat(c,extension);
	printf("%s\n",c);
	return c;
}

int main(int argc, const char** args) {
	if (argc < 2) {
		fprintf(stderr, "Usage %s <outfile-prefix>", args[0]);
		return 1;
	}


	for (int f =0; f< NUMBER_OF_FILES; f++){

		char* outfile = get_file_name(args[1], f);

		light_pcapng writer = light_pcapng_open(outfile, "wb");

		for (int p =0; p < PACKETS_PER_FILE; p++) {
			light_packet_interface pkt_interface;
			light_packet_header pkt_header;
			uint8_t* pkt_data = NULL;


			// Set interface properties
			pkt_interface.link_type = 1; // link_type: ETHERNET
			pkt_interface.name = "Test interface";
			pkt_interface.description = "Interface description";
			pkt_interface.timestamp_resolution = 1000000000;

			// Set packet header
			struct timespec ts;
			clockid_t clk_id = CLOCK_REALTIME;
			clock_gettime(clk_id, &ts);
			pkt_header.timestamp = ts;
			pkt_header.captured_length = 256;
			pkt_header.original_length = 1024;
			pkt_header.flags = 0x1; // direction indicator
			pkt_header.dropcount = 0;
			pkt_header.comment = "Packet comment";

			// Pkt content
			pkt_data = (uint8_t *) malloc(pkt_header.captured_length * sizeof(uint8_t));
			memset(pkt_data, '-', pkt_header.captured_length);

			light_write_packet(writer, &pkt_interface, &pkt_header, pkt_data);
		}
		light_pcapng_close(writer);
		free(outfile);

	}	

	return 0;
}
