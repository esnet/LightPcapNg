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
#include "light_io_zstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libconfig.h>

int NUMBER_OF_FILES = 12;

char * get_file_name(const char* prefix, int counter, int use_zstd){
	char *extension;
	if (use_zstd) {
		extension = ".pcapng.zst";
	} else {
		extension = ".pcapng";
	}
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
		fprintf(stderr, "Usage %s <configfile>", args[0]);
		return 1;
	}
	
	const char* configfile = args[1];

	config_t cfg;
	config_setting_t *setting;
	const char *str;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, configfile))
	{
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
	        	config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(EXIT_FAILURE);
	}

	const char* filename_prefix;
	if(!config_lookup_string(&cfg, "pcapng.filename_prefix", &filename_prefix)) {
		fprintf(stderr, "No 'pcapng.filename_prefix' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	int packets_per_file;
	if(!config_lookup_int(&cfg, "pcapng.packets_per_file", &packets_per_file)) {
		fprintf(stderr, "No 'pcapng.packets_per_file' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	int use_zstd;
	if(!config_lookup_bool(&cfg, "pcapng.use_zstd", &use_zstd)) {
		fprintf(stderr, "No 'pcapng.use_zstd' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	// Interface config
	const char * interface_name;
	if(!config_lookup_string(&cfg, "interface.name", &interface_name)) {
		fprintf(stderr, "No 'interface_name' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	const char * interface_description;
	if(!config_lookup_string(&cfg, "interface.description", &interface_description)) {
		fprintf(stderr, "No 'interface_description' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	int interface_speed;
	if(!config_lookup_int(&cfg, "interface.speed", &interface_speed)) {
		fprintf(stderr, "No 'interface_speed' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	// FPGA filter expression
	const char * interface_filter;
	if(!config_lookup_string(&cfg, "interface.filter", &interface_filter)) {
		fprintf(stderr, "No 'interface_filter' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	//Packet config
	int packet_flags;
	if(!config_lookup_int(&cfg, "packet.flags", &packet_flags)) {
		fprintf(stderr, "No 'packet.flags' setting in configuration file.\n");
		return(EXIT_FAILURE);
	}

	for (int f =0; f< NUMBER_OF_FILES; f++){

		char * outfile = get_file_name(filename_prefix, f, use_zstd); 

		light_pcapng writer;
		if (use_zstd) {	
			light_file zstd_file = light_io_zstd_open(outfile, "wb");
        		light_pcapng_file_info* file_info =  light_create_default_file_info();
			writer = light_pcapng_create(zstd_file, "wb", file_info);
		} else {
			writer = light_pcapng_open(outfile, "wb");	
		}

		for (int p =0; p< packets_per_file; p++) {
			light_packet_interface pkt_interface;
			light_packet_header pkt_header;
			uint8_t* pkt_data = NULL;

			// Set interface properties
			pkt_interface.link_type = 1; // link_type: ETHERNET
			pkt_interface.name = interface_name;
			pkt_interface.description = interface_description; 
			pkt_interface.timestamp_resolution = 1000000000;

			// Set packet header
			struct timespec ts;
			clockid_t clk_id = CLOCK_REALTIME;
			clock_gettime(clk_id, &ts);
			pkt_header.timestamp = ts;
			//TODO: parse these from telemetry format
			pkt_header.captured_length = 256;
			pkt_header.original_length = 1024;
			pkt_header.flags = packet_flags;
			pkt_header.dropcount = 0;
			pkt_header.comment = "Packet comment";

			// Pkt content
			pkt_data = (uint8_t *) malloc(pkt_header.captured_length * sizeof(uint8_t));
			memset(pkt_data, '-', pkt_header.captured_length);

			light_write_packet(writer, &pkt_interface, &pkt_header, pkt_data);
		}
		light_pcapng_close(writer);
	}
	return 0;
}
