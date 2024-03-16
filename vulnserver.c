/*
 * This is a Linux porting of the original VulnServer created by Stephen
 * Bradshaw - a deliberately vulnerable threaded TCP server application.
 *
 * As declared in the original version, this is vulnerable software, don't run
 * it on an important system!  The authors assume no responsibility if you run
 * this software and your system gets compromised, because this software was
 * designed to be exploited!
 *
 * For more details, visit Stephen's blog at http://www.thegreycorner.com
 *
 * Copyright (c) 2010, Stephen Bradshaw
 * All rights reserved.
 *
 * Redistribution conditions are the same as in the original version and are
 * declared below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.  Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.  Neither the name of the
 * organization nor the names of its contributors may be used to endorse or
 * promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BACKLOG			5
#define DEFAULT_BUFLEN		4096
#define DEFAULT_PORT_NUMBER	"9999"
#define VERSION			"1.00"

#define NOT_IMPLEMENTED		\
	"Command specific help has not been implemented\n"

#define VALID_COMMANDS		\
	"Valid Commands:\n"	\
	"HELP\n"		\
	"STATS [stat_value]\n"	\
	"RTIME [rtime_value]\n"	\
	"LTIME [ltime_value]\n"	\
	"SRUN [srun_value]\n"	\
	"TRUN [trun_value]\n"	\
	"GMON [gmon_value]\n"	\
	"GDOG [gdog_value]\n"	\
	"KSTET [kstet_value]\n"	\
	"GTER [gter_value]\n"	\
	"HTER [hter_value]\n"	\
	"LTER [lter_value]\n"	\
	"KSTAN [lstan_value]\n"	\
	"EXIT\n"

void *connection_handler(void *arg);
int handle_command(int client_fd, char *cmdbuf, char *gdogbuf);
int handle_not_implemented(int client_fd);
int handle_help(int client_fd);
int handle_stats(int client_fd, char *cmdbuf);
int handle_rtime(int client_fd, char *cmdbuf);
int handle_ltime(int client_fd, char *cmdbuf);
int handle_srun(int client_fd, char *cmdbuf);
int handle_trun(int client_fd, char *cmdbuf);
int handle_gmon(int client_fd, char *cmdbuf);
int handle_gdog(int client_fd, char *cmdbuf, char *gdogbuf);
int handle_kstet(int client_fd, char *cmdbuf);
int handle_gter(int client_fd, char *cmdbuf, char *gdogbuf);
int handle_hter(int client_fd, char *cmdbuf);
int handle_lter(int client_fd, char *cmdbuf);
int handle_kstan(int client_fd);
int handle_exit(int client_fd);
int handle_unknown(int client_fd);
void function1(char *input);
void function2(char *input);
void function3(char *input);
void function4(char *input);

void usage(char *argv[])
{
	fprintf(stderr, "Usage: %s [port_number]\n\n"
		"If no port number is provided, "
		"the default port of %s will be used.\n",
		argv[0], DEFAULT_PORT_NUMBER);
}

bool is_valid_port_number(char *argv)
{
	int port_number = atoi(argv);

	return port_number > 0 && port_number < 65536;
}

int main(int argc, char *argv[])
{
	char port_number[6];
	struct addrinfo hints;
	struct addrinfo *addrinfo, *ai;
	int server_fd;
	int err;

	if (argc == 1) {
		strncpy(port_number, DEFAULT_PORT_NUMBER, 6);
	} else if (argc == 2) {
		if (is_valid_port_number(argv[1])) {
			strncpy(port_number, argv[1], 6);
		} else {
			fprintf(stderr, "Invalid port number %s\n", argv[1]);
			return 1;
		}
	} else {
		usage(argv);
		return 1;
	}

	printf("Starting vulnserver version %s\n"
		"This is vulnerable software!\n"
		"Do not allow access from untrusted systems or networks!\n\n",
		VERSION);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;		/* Allows IPv4 or IPv6 */
	hints.ai_flags = AI_PASSIVE		/* Wildcard IP address */
			 | AI_NUMERICSERV;	/* Service name is numeric */

	err = getaddrinfo(NULL, port_number, &hints, &addrinfo);
	if (err != 0) {
		fprintf(stderr, "Could not get address info\n");
		return 1;
	}

	for (ai = addrinfo; ai != NULL; ai = ai->ai_next) {
		const int optval = 1;

		server_fd = socket(ai->ai_family, ai->ai_socktype,
				   ai->ai_protocol);
		if (server_fd == -1) {
			fprintf(stderr, "Could not create socket\n");
			continue;
		}

		err = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval,
				 sizeof(optval));
		if (err != 0) {
			fprintf(stderr, "Could not set socket options\n");
			close(server_fd);
			server_fd = -1;
			continue;
		}

		err = bind(server_fd, ai->ai_addr, ai->ai_addrlen);
		if (err != 0) {
			fprintf(stderr, "Could not bind to port number %s\n",
				port_number);
		} else {
			printf("Successfully bound to port number %s\n",
				port_number);
			break;
		}

		close(server_fd);
		server_fd = -1;
	}

	freeaddrinfo(addrinfo);

	if (server_fd == -1) {
		fprintf(stderr, "Could not bind socket to any address\n");
		return 1;
	}

	err = listen(server_fd, BACKLOG);
	if (err != 0) {
		fprintf(stderr, "Could not start listen to socket\n");
		return 1;
	}

	for (;;) {
		struct sockaddr_storage client_addr;
		socklen_t addrlen = sizeof(client_addr);
		char host[NI_MAXHOST];
		pthread_t thread;
		int client_fd;

		printf("Waiting for client connections...\n");

		client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
				   &addrlen);

		if (client_fd == -1) {
			fprintf(stderr, "Could not accept connection\n");
			continue;
		}

		err = getnameinfo((struct sockaddr *)&client_addr, addrlen,
				   host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (err != 0)
			fprintf(stderr, "Could not get client host address\n");
		else
			printf("Received a client connection from host %s\n",
				host);

		err = pthread_create(&thread, NULL, connection_handler,
				     (void *)&client_fd);
		if (err != 0) {
			fprintf(stderr, "Could not create thread\n");
			continue;
		}

		err = pthread_detach(thread);
		if (err != 0) {
			fprintf(stderr, "Could not detach thread\n");
			continue;
		}
	}

	return 0;
}

void *connection_handler(void *arg)
{
	int client_fd = *(int *)arg;
	char *cmdbuf = malloc(DEFAULT_BUFLEN);
	char bigempty[1000];
	char *gdogbuf = malloc(1024);
	int count;

	memset(bigempty, 0, 1000);
	memset(cmdbuf, 0, DEFAULT_BUFLEN);

	count = send(client_fd, "Welcome to Vulnerable Server!\n"
				"Enter HELP for help.\n", 52, 0);
	if (count == -1) {
		fprintf(stderr, "Send failed with error (%d): %s\n", errno,
			strerror(errno));
		goto out_close;
	}

	for (;;) {
		count = recv(client_fd, cmdbuf, DEFAULT_BUFLEN, 0);
		if (count > 0) {
			int ret = handle_command(client_fd, cmdbuf, gdogbuf);
			if (ret == -1) {
				if (errno != 0) {
					fprintf(stderr, "Command %s failed with error (%d): %s\n",
						cmdbuf, errno, strerror(errno));
				}
				goto out_close;
			}
		} else if (count == 0) {
			printf("Connection closing...\n");
			goto out_close;
		} else  {
			fprintf(stderr, "Recv failed with error (%d): %s\n",
				errno, strerror(errno));
			goto out_close;
		}
	}

out_close:
	close(client_fd);
	pthread_exit(NULL);
}

int handle_command(int client_fd, char *cmdbuf, char *gdogbuf)
{
	if (strncmp(cmdbuf, "HELP ", 5) == 0)
		return handle_not_implemented(client_fd);
	else if (strncmp(cmdbuf, "HELP", 4) == 0)
		return handle_help(client_fd);
	else if (strncmp(cmdbuf, "STATS ", 6) == 0)
		return handle_stats(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "RTIME ", 6) == 0)
		return handle_rtime(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "LTIME ", 6) == 0)
		return handle_ltime(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "SRUN ", 5) == 0)
		return handle_srun(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "TRUN ", 5) == 0)
		return handle_trun(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "GMON ", 5) == 0)
		return handle_gmon(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "GDOG ", 5) == 0)
		return handle_gdog(client_fd, cmdbuf, gdogbuf);
	else if (strncmp(cmdbuf, "KSTET ", 6) == 0)
		return handle_kstet(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "GTER ", 5) == 0)
		return handle_gter(client_fd, cmdbuf, gdogbuf);
	else if (strncmp(cmdbuf, "HTER ", 5) == 0)
		return handle_hter(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "LTER ", 5) == 0)
		return handle_lter(client_fd, cmdbuf);
	else if (strncmp(cmdbuf, "KSTAN ", 6) == 0)
		return handle_kstan(client_fd);
	else if (strncmp(cmdbuf, "EXIT", 4) == 0)
		return handle_exit(client_fd);
	else
		return handle_unknown(client_fd);
}

int handle_not_implemented(int client_fd)
{
	return send(client_fd, NOT_IMPLEMENTED, sizeof(NOT_IMPLEMENTED), 0);
}

int handle_help(int client_fd)
{
	return send(client_fd, VALID_COMMANDS, sizeof(VALID_COMMANDS), 0);
}

int handle_stats(int client_fd, char *cmdbuf)
{
	char *statbuf = malloc(120);

	memset(statbuf, 0, 120);
	strncpy(statbuf, cmdbuf, 120);

	return send(client_fd, "STATS VALUE NORMAL\n", 19, 0);
}

int handle_rtime(int client_fd, char *cmdbuf)
{
	char *rtimebuf = malloc(120);

	memset(rtimebuf, 0, 120);
	strncpy(rtimebuf, cmdbuf, 120);

	return send(client_fd, "RTIME VALUE WITHIN LIMITS\n", 26, 0);
}

int handle_ltime(int client_fd, char *cmdbuf)
{
	char *ltimebuf = malloc(120);

	memset(ltimebuf, 0, 120);
	strncpy(ltimebuf, cmdbuf, 120);

	return send(client_fd, "LTIME VALUE HIGH, BUT OK\n", 25, 0);
}

int handle_srun(int client_fd, char *cmdbuf)
{
	char *srunbuf = malloc(120);

	memset(srunbuf, 0, 120);
	strncpy(srunbuf, cmdbuf, 120);

	return send(client_fd, "SRUN COMPLETE\n", 14, 0);
}

int handle_trun(int client_fd, char *cmdbuf)
{
	int i;
	char *trunbuf = malloc(3000);

	memset(trunbuf, 0, 3000);

	for (i = 5; i < DEFAULT_BUFLEN; i++) {
		if ((char)cmdbuf[i] == '.') {
			strncpy(trunbuf, cmdbuf, 3000);
			function3(trunbuf);
			break;
		}
	}

	memset(trunbuf, 0, 3000);

	return send(client_fd, "TRUN COMPLETE\n", 14, 0);
}

int handle_gmon(int client_fd, char *cmdbuf)
{
	int i;
	char gmon_status[13] = "GMON STARTED\n";

	for (i = 5; i < DEFAULT_BUFLEN; i++) {
		if ((char)cmdbuf[i] == '/') {
			if (strlen(cmdbuf) > 3950)
				function3(cmdbuf);
			break;
		}
	}

	return send(client_fd, gmon_status, sizeof(gmon_status), 0);
}

int handle_gdog(int client_fd, char *cmdbuf, char *gdogbuf)
{
	strncpy(gdogbuf, cmdbuf, 1024);

	return send(client_fd, "GDOG RUNNING\n", 13, 0);
}

int handle_kstet(int client_fd, char *cmdbuf)
{
	char *kstetbuf = malloc(100);

	strncpy(kstetbuf, cmdbuf, 100);
	memset(cmdbuf, 0, DEFAULT_BUFLEN);
	function2(kstetbuf);

	return send(client_fd, "KSTET SUCCESSFUL\n", 17, 0);
}

int handle_gter(int client_fd, char *cmdbuf, char *gdogbuf)
{
	char *gterbuf = malloc(180);

	memset(gdogbuf, 0, 1024);
	strncpy(gterbuf, cmdbuf, 180);
	memset(cmdbuf, 0, DEFAULT_BUFLEN);
	function1(gterbuf);

	return send(client_fd, "GTER ON TRACK\n", 14, 0);
}

int handle_hter(int client_fd, char *cmdbuf)
{
	char thbuf[3];

	memset(thbuf, 0, 3);
	char *hterbuf = malloc((DEFAULT_BUFLEN + 1) / 2);

	memset(hterbuf, 0, (DEFAULT_BUFLEN + 1) / 2);
	int i = 6;
	int k = 0;

	// TODO: Check byte replacement. Look original version.

	while ((cmdbuf[i]) && (cmdbuf[i+1])) {
		memcpy(thbuf, (char *)cmdbuf+i, 2);
		unsigned long j = strtoul((char *)thbuf, NULL, 16);

		memset((char *)hterbuf + k, j, 1);
		i = i + 2;
		k++;
	}

	function4(hterbuf);
	memset(hterbuf, 0, (DEFAULT_BUFLEN + 1) / 2);

	return send(client_fd, "HTER RUNNING FINE\n", 18, 0);
}

int handle_lter(int client_fd, char *cmdbuf)
{
	int i = 0;
	char *lterbuf = malloc(DEFAULT_BUFLEN);

	memset(lterbuf, 0, DEFAULT_BUFLEN);

	// TODO: byte has been replaced with unsigned char
	// Need to check if this is right

	while (cmdbuf[i]) {
		if ((unsigned char)cmdbuf[i] > 0x7f)
			lterbuf[i] = (unsigned char)cmdbuf[i] - 0x7f;
		else
			lterbuf[i] = cmdbuf[i];
		i++;
	}

	for (i = 5; i < DEFAULT_BUFLEN; i++) {
		if ((char)lterbuf[i] == '.') {
			function3(lterbuf);
			break;
		}
	}

	memset(lterbuf, 0, DEFAULT_BUFLEN);

	return send(client_fd, "LTER COMPLETE\n", 14, 0);
}

int handle_kstan(int client_fd)
{
	return send(client_fd, "KSTAN UNDERWAY\n", 15, 0);
}

int handle_exit(int client_fd)
{
	printf("Connection closing...\n");
	send(client_fd, "GOODBYE\n", 8, 0);

	return -1;
}

int handle_unknown(int client_fd)
{
	return send(client_fd, "UNKNOWN COMMAND\n", 16, 0);
}

void function1(char *input)
{
	char buffer[140];

	strcpy(buffer, input);
}

void function2(char *input)
{
	char buffer[60];

	strcpy(buffer, input);
}

void function3(char *input)
{
	char buffer[2000];

	strcpy(buffer, input);
}

void function4(char *input)
{
	char buffer[1000];

	strcpy(buffer, input);
}
