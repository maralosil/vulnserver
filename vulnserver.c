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

#define BACKLOG		5
#define BUFFER_LENGTH	4096
#define PORT_NUMBER	"9999"
#define VERSION		"1.00"

static void function1(char *input);
static void function2(char *input);
static void function3(char *input);
static void function4(char *input);
static void *connection_handler(void *arg);

static void usage(char *argv[])
{
	fprintf(stderr, "Usage: %s [port_number]\n\n"
		"If no port number is provided, "
		"the default port of %s will be used.\n",
		argv[0], PORT_NUMBER);
}
static bool is_valid_port_number(char *argv)
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
		strncpy(port_number, PORT_NUMBER, 6);
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

		if (getnameinfo((struct sockaddr *)&client_addr, addrlen,
			host, NI_MAXHOST, NULL, 0, 0) == 0) {
			printf("Received a client connection from %s\n", host);
		}
	
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

static void function1(char *input)
{
	char buffer[140];
	strcpy(buffer, input);
}

static void function2(char *input)
{
	char buffer[60];
	strcpy(buffer, input);
}

static void function3(char *input)
{
	char buffer[2000];
	strcpy(buffer, input);
}

static void function4(char *input)
{
	char buffer[1000];
	strcpy(buffer, input);
}

static void *connection_handler(void *arg)
{
	int client_fd = *(int *)arg;
	// char *recvbuf = malloc(DEFAULT_BUFFER_LENGTH);
	// char bigempty[1000];
	// char *gdogbuf = malloc(1024);
	// int Result, SendResult, i, k;
	//memset(bigempty, 0, 1000);
	// memset(recvbuf, 0, DEFAULT_BUFFER_LENGTH);
	char buffer[BUFFER_LENGTH];
	int err;
	int count;

	count = send(client_fd, "Welcome to Vulnerable Server!\n"
				"Enter HELP for help.\n", 52, 0 );
	if (count == -1) {
		printf("Send failed with error (%d): %s\n", errno,
			strerror(errno));
		close(client_fd);
		pthread_exit(NULL);
	}

#if 0
	for (;;) {
		count = recv(client_fd, buffer, BUFFER_LENGTH, 0);
		if (count > 0) {
			if (strncmp(buffer, "HELP ", 5) == 0) {
				const char NotImplemented[47] = "Command specific help has not been implemented\n";
				SendResult = send( Client, NotImplemented, sizeof(NotImplemented), 0 );
			} else if (strncmp(RecvBuf, "HELP", 4) == 0) {
				const char ValidCommands[251] = "Valid Commands:\nHELP\nSTATS [stat_value]\nRTIME [rtime_value]\nLTIME [ltime_value]\nSRUN [srun_value]\nTRUN [trun_value]\nGMON [gmon_value]\nGDOG [gdog_value]\nKSTET [kstet_value]\nGTER [gter_value]\nHTER [hter_value]\nLTER [lter_value]\nKSTAN [lstan_value]\nEXIT\n";
				SendResult = send( Client, ValidCommands, sizeof(ValidCommands), 0 );
			} else if (strncmp(RecvBuf, "STATS ", 6) == 0) {
				char *StatBuf = malloc(120);
				memset(StatBuf, 0, 120);
				strncpy(StatBuf, RecvBuf, 120);
				SendResult = send( Client, "STATS VALUE NORMAL\n", 19, 0 );
			} else if (strncmp(RecvBuf, "RTIME ", 6) == 0) {
				char *RtimeBuf = malloc(120);
				memset(RtimeBuf, 0, 120);
				strncpy(RtimeBuf, RecvBuf, 120);
				SendResult = send( Client, "RTIME VALUE WITHIN LIMITS\n", 26, 0 );
			} else if (strncmp(RecvBuf, "LTIME ", 6) == 0) {
				char *LtimeBuf = malloc(120);
				memset(LtimeBuf, 0, 120);
				strncpy(LtimeBuf, RecvBuf, 120);
				SendResult = send( Client, "LTIME VALUE HIGH, BUT OK\n", 25, 0 );
			} else if (strncmp(RecvBuf, "SRUN ", 5) == 0) {
				char *SrunBuf = malloc(120);
				memset(SrunBuf, 0, 120);
				strncpy(SrunBuf, RecvBuf, 120);
				SendResult = send( Client, "SRUN COMPLETE\n", 14, 0 );
			} else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);				
						Function3(TrunBuf);
						break;
					}
				}
				memset(TrunBuf, 0, 3000);				
				SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
			} else if (strncmp(RecvBuf, "GMON ", 5) == 0) {
				char GmonStatus[13] = "GMON STARTED\n";
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '/') {
						if (strlen(RecvBuf) > 3950) {
							Function3(RecvBuf);
						}
						break;
					}
				}				
				SendResult = send( Client, GmonStatus, sizeof(GmonStatus), 0 );
			} else if (strncmp(RecvBuf, "GDOG ", 5) == 0) {				
				strncpy(GdogBuf, RecvBuf, 1024);
				SendResult = send( Client, "GDOG RUNNING\n", 13, 0 );
			} else if (strncmp(RecvBuf, "KSTET ", 6) == 0) {
				char *KstetBuf = malloc(100);
				strncpy(KstetBuf, RecvBuf, 100);
				memset(RecvBuf, 0, DEFAULT_BUFLEN);
				Function2(KstetBuf);
				SendResult = send( Client, "KSTET SUCCESSFUL\n", 17, 0 );
			} else if (strncmp(RecvBuf, "GTER ", 5) == 0) {
				char *GterBuf = malloc(180);
				memset(GdogBuf, 0, 1024);
				strncpy(GterBuf, RecvBuf, 180);				
				memset(RecvBuf, 0, DEFAULT_BUFLEN);
				Function1(GterBuf);
				SendResult = send( Client, "GTER ON TRACK\n", 14, 0 );
			} else if (strncmp(RecvBuf, "HTER ", 5) == 0) {
				char THBuf[3];
				memset(THBuf, 0, 3);
				char *HterBuf = malloc((DEFAULT_BUFLEN+1)/2);
				memset(HterBuf, 0, (DEFAULT_BUFLEN+1)/2);
				i = 6;
				k = 0;
				while ( (RecvBuf[i]) && (RecvBuf[i+1])) {
					memcpy(THBuf, (char *)RecvBuf+i, 2);
					unsigned long j = strtoul((char *)THBuf, NULL, 16);
					memset((char *)HterBuf + k, (byte)j, 1);
					i = i + 2;
					k++;
				} 
				Function4(HterBuf);
				memset(HterBuf, 0, (DEFAULT_BUFLEN+1)/2);
				SendResult = send( Client, "HTER RUNNING FINE\n", 18, 0 );
			} else if (strncmp(RecvBuf, "LTER ", 5) == 0) {
				char *LterBuf = malloc(DEFAULT_BUFLEN);
				memset(LterBuf, 0, DEFAULT_BUFLEN);
				i = 0;
				while(RecvBuf[i]) {
					if ((byte)RecvBuf[i] > 0x7f) {
						LterBuf[i] = (byte)RecvBuf[i] - 0x7f;
					} else {
						LterBuf[i] = RecvBuf[i];
					}
					i++;
				}
				for (i = 5; i < DEFAULT_BUFLEN; i++) {
					if ((char)LterBuf[i] == '.') {					
						Function3(LterBuf);
						break;
					}
				}
				memset(LterBuf, 0, DEFAULT_BUFLEN);
				SendResult = send( Client, "LTER COMPLETE\n", 14, 0 );
			} else if (strncmp(RecvBuf, "KSTAN ", 6) == 0) {
				SendResult = send( Client, "KSTAN UNDERWAY\n", 15, 0 );
			} else if (strncmp(RecvBuf, "EXIT", 4) == 0) {
				SendResult = send( Client, "GOODBYE\n", 8, 0 );
				printf("Connection closing...\n");
				closesocket(Client);
				return 0;
			} else {
				SendResult = send( Client, "UNKNOWN COMMAND\n", 16, 0 );
			}
			if (SendResult == SOCKET_ERROR) {
				printf("Send failed with error: %d\n", WSAGetLastError());
				closesocket(Client);
				return 1;
			}
		} else if (Result == 0) {
			printf("Connection closing...\n");
			closesocket(Client);
			return 0;			
		} else  {
			printf("Recv failed with error: %d\n", WSAGetLastError());
			closesocket(Client);
			return 1;
		}

	}	
#endif
out_close:
	close(client_fd);
out:
	pthread_exit(NULL);
}

