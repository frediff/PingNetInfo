/*
#######################################################################
#####################                             #####################
#####################        NETWORKS  LAB        #####################
#####################        ASSIGNMENT  5        #####################
#####################  GROUP MEMBERS (GROUP - 5)  #####################
#####################  SUBHAM GHOSH  (20CS10065)  #####################
#####################  ANUBHAV DHAR  (20CS30004)  #####################
#####################                             #####################
#######################################################################
*/








/*
 +--------+
 | README |
 +--------+

FOR INITIAL TESTING (not printing the exact packets), please do the following.
This will allow you to see just the next hops and the latencies without the packets
because printing the packets take up a lot of space in the terminal, it is easier
to read from in this way

- Compile using
-	$ gcc -Wall -Wextra -DQUIET pingnetinfo.c -lpthread -o pingnetinfo.out
- run using
-	$ sudo ./pingnetinfo.out <url> <n> <T>
- for example:
-	$ sudo ./pingnetinfo.out iitkgp.ac.in 2 3


Now, to see the exact packets, please do the following


- Compile using
-	$ gcc -Wall -Wextra pingnetinfo.c -lpthread -o pingnetinfo.out
- run using
-	$ sudo ./pingnetinfo.out <url> <n> <T>
- for example:
-	$ sudo ./pingnetinfo.out iitkgp.ac.in 2 3

*/





/*
Note on calculations done:

Assume, that Li and Bi denote the latency and bandwidth, respectively, of the
i-th link that is joining the (i − 1)-the node and the i-th node. Also assume
that the 0-th node is our source machine from where the program is running.

Now, we send two different types of ICMP echo request packets: one of size D1
and the other of size D2.  Call  the round-trip time up to the i-th node of a
data packet of type t where t ∈ { 1, 2 } as R(i,t). So we have the following
equations:

 R(i,1) − R(i−1,1)          D1
─────────────────── = Li + ────
        2                   Bi

 R(i,2) − R(i−1,2)          D2
─────────────────── = Li + ────
        2                   Bi

 R(i,2) − R(i−1,2)     R(i,1) − R(i−1,1)     D2 − D1
─────────────────── - ─────────────────── = ─────────
        2                     2                 Bi

Thus,
+-------------------------------------------------+
|                   2 · (D2 − D1)                 |
|  Bi = ──────────────────────────────────────    |
|         R(i,2) − R(i−1,2) − R(i,1) + R(i−1,1)   |
+-------------------------------------------------+


+-------------------------------------------------------------------+
|        1    D2 · (R(i,1) − R(i−1,1)) − D1 · (R(i,2) − R(i−1,2))   |
|  Li = ─── · ────────────────────────────────────────────────────  |
|        2                        D2 − D1                           |
+-------------------------------------------------------------------+

In our case D1 = 0 and D2 = MSG_BW

*/


// Send is concurrent in ping_next_hop() with recv_thread()

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
// #include <math.h>
#include <poll.h>
#include <pthread.h>

#define MSG_SZ 2048
#define BUFFERSIZE 2048
#define MSG_BW 400
#define TTL_MAX 64
// #define MY_IP "10.124.36.182"
#define PACKET_SIZE 64
#define TIME_OUT_MILISEC 1000
#define NOTFOUND -123456
// for text colors
#define BLACK "\033[30m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define PURPLE "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"
#define DEFAULT "\033[0m"
#define BOLD "\033[1m"
#define NONBOLD "\033[m"

// for text styles
#define ITALIC "\033[3m"
#define UNDERLINE "\033[4m"


pthread_mutex_t stdlock;

int N_PING = 5;
int recv_sz = 0;
int T;

// get additional info about host
void describe_hostent_host(const struct hostent* host) {
	printf("\nDetails about Host\n");
	printf("------------------\n");
	printf("- name      : %s\n", host -> h_name);
	for (size_t i = 0; host -> h_aliases[i] != NULL; ++i)
		printf("- aliases   : %s\n", host -> h_aliases[i]);
	printf("- addrtype  : %s\n", (host -> h_addrtype == AF_INET) ? "IPv4" : "IPv6");
	printf("- addrlen   : %d bytes\n", host -> h_length);
	char dest [INET6_ADDRSTRLEN];
	printf("- address   : %s\n", inet_ntop(host -> h_addrtype, host -> h_addr, dest, INET6_ADDRSTRLEN));
	printf("\n");
}

// // helper for min, max, avg, sd
// void running_max_min_avg_mdev(long long sample, int n, long long* max, long long* min, long double* avg, long double* mdev) {
// 	*max = (*max < sample) ? sample : *max;
// 	*min = (*min > sample) ? sample : *min;
// 	*avg = ((n - 1) * (*avg) + sample) / n;
// 	*mdev = sqrtl(((*mdev) * (*mdev) * (n - 1)) / n + ((n == 1) ? 0 : ((sample - *avg) * (sample - *avg) / (n - 1))));
// }

// converts url to ip and fills it in optional_str and serv_addr
unsigned url_to_ip(const char * site_name, char ** optional_str, struct sockaddr_in * serv_addr) {

	struct hostent *host = gethostbyname(site_name);
	if (host == NULL) {
		// gives error message
		herror("error in gethostname");
		exit(1);
	}

	// for debugging
	describe_hostent_host(host);

	struct in_addr ** r = (struct in_addr **) host -> h_addr_list;

	if (optional_str != NULL) {
		*optional_str = inet_ntoa(*r[0]);
	}

	if (serv_addr != NULL) {
		serv_addr -> sin_addr = *((struct in_addr *)host -> h_addr);
	}

	return r[0] -> s_addr;
}

// calculates the icmp checksum
unsigned short calculate_checksum(unsigned short *paddress, int len) {
	unsigned int sum = 0;
	unsigned short checksum = 0;
	while (len > 1) {
		sum += *paddress++;
		len -= 2;
	}
	if (len == 1) {
		sum += *((unsigned char *)paddress);
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	checksum = ~sum;
	return checksum;
}


void print_ip_header(struct iphdr* ip_header) {

	// struct hostent *host = gethostbyaddr(&(ip_header -> saddr), sizeof(ip_header -> saddr), AF_INET);
	// if (host == NULL) herror("error in gethostname");
	// else describe_hostent_host(host);

	char dest [INET6_ADDRSTRLEN];

	printf("\n    IP header:\n");
	printf("    +---------+---------+-----------------+------------------------------------+\n");
	printf("    | VER: %2u | IHL: %2u | TOS: %10hhu | TOT LEN: %25hu |\n", ip_header -> version, ip_header -> ihl, ip_header -> tos, ntohs(ip_header -> tot_len));
	printf("    +---------+---------+-----------------+----------+-------------------------+\n");
	printf("    | ID: %31hu | FLG: 000 | FRAG OFF: %13hu |\n", ip_header -> id, ntohs(ip_header -> frag_off));
	printf("    +-------------------+-----------------+----------+-------------------------+\n");
	printf("    | TTL: %12hhu | PROTOCOL: %5hhu | HDR CHECKSUM: %20hu |\n", ip_header -> ttl, ip_header -> protocol, ip_header -> check);
	printf("    +-------------------+-----------------+------------------------------------+\n");
	printf("    | SADDR: %65s |\n", inet_ntop(AF_INET, &(ip_header -> saddr), dest, INET6_ADDRSTRLEN));
	printf("    +--------------------------------------------------------------------------+\n");
	printf("    | DADDR: %65s |\n", inet_ntop(AF_INET, &(ip_header -> daddr), dest, INET6_ADDRSTRLEN));
	printf("    +--------------------------------------------------------------------------+\n");
	printf("\n");

	// checksum_verify(ip_header);
}

void printf_wrapped_data(char* buffer, size_t n) {
	printf("\n");
	printf("    Echo Data (%lu bytes):\n", n);
	printf("    +--------------------------------------------------------------------------+\n");
	printf("    | ");
	int linewrap = 0;
	for (size_t i = 0; i < n; ++i) {
		if (buffer[i] != '\n') {
			printf("%c", buffer[i]);
			++linewrap;
			if (linewrap == 72) {
				printf(" |\n    | ");
				linewrap = 0;
			}
		}
		else {
			while (linewrap++ < 72) printf(" ");
			printf(" |\n    | ");
			linewrap = 0;
		}

	}

	while (linewrap++ < 72) printf(" ");
	printf(" |\n");
	printf("    +--------------------------------------------------------------------------+\n");
	printf("\n");
	fflush(stdout);
}

  void print_tcp_header(struct tcphdr* tcpheader) {
    printf("\n" ITALIC);
  printf("    TCP header:\n");
  printf("    +-------------------------------------+------------------------------------+\n");
  printf("    | SRC PORT: %25hu | DST PORT: %24hu |\n", ntohs(tcpheader->source), ntohs(tcpheader->dest));
  printf("    +-------------------------------------+------------------------------------+\n");
  printf("    | SEQ: %67u |\n", ntohl(tcpheader->seq));
  printf("    +--------------------------------------------------------------------------+\n");
  printf("    | ACK: %67u |\n", ntohl(tcpheader->ack_seq));
  printf("    +--------------+--------+-------------+------------------------------------+\n");
  printf("    | DOFF: %6hu |  RSVD  | FLG: %1hu%1hu%1hu%1hu%1hu%1hu | WINDOW: %26hu |\n", (tcpheader->doff), tcpheader->urg, tcpheader->ack, tcpheader->psh, tcpheader->rst, tcpheader->syn, tcpheader->fin, ntohs(tcpheader->window));
  printf("    +--------------+--------+-------------+------------------------------------+\n");
  printf("    | CHECK: %28hu | URG: %29hu |\n", ntohs(tcpheader->check), ntohs(tcpheader->urg_ptr));
  printf("    +-------------------------------------+------------------------------------+\n");
  printf("\n" NONBOLD);
}

void print_udp_header(struct udphdr* udpheader) {
  printf("\n" ITALIC);
  printf("    UDP header:\n");
  printf("    +-------------------------------------+------------------------------------+\n");
  printf("    | SRC PORT: %25hu | DST PORT: %24hu |\n", ntohs(udpheader->source), ntohs(udpheader->dest));
  printf("    +-------------------------------------+------------------------------------+\n");
  printf("    | LEN: %30hu | CHECK: %27hu |\n", ntohs(udpheader->len), ntohs(udpheader->check));
  printf("    +-------------------------------------+------------------------------------+\n");
  printf("\n" NONBOLD);
}

void print_icmp_packet(struct icmphdr* icmpheader, size_t n) {
	printf("\n");
	if ((icmpheader -> type == 8 || icmpheader -> type == 0) && icmpheader -> code == 0) {
		printf("    Echo reply/request:\n");
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | TYPE: %11hhu | CODE: %10hhu | CHECKSUM: %23hu |\n", icmpheader -> type, icmpheader -> code, icmpheader -> checksum);
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | ID: %32hu | SEQ: %28hu |\n", icmpheader -> un.echo.id, icmpheader -> un.echo.sequence);
		printf("    +--------------------------------------+-----------------------------------+\n");
		printf_wrapped_data((char*) icmpheader + sizeof(struct icmphdr), n);
	}
	else if (icmpheader -> type == 11) {
		printf("    Time exceeded:\n");
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | TYPE: %11hhu | CODE: %10hhu | CHECKSUM: %23hu |\n", icmpheader -> type, icmpheader -> code, icmpheader -> checksum);
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("\n    Original Datagram\n");
		printf("    -----------------\n");
		print_ip_header((struct iphdr*)((char*) icmpheader + sizeof(struct icmphdr)));
		icmpheader = (struct icmphdr*) ((char*) icmpheader + sizeof(struct icmphdr) + sizeof(struct iphdr));
		printf("    ICMP header:\n");
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | TYPE: %11hhu | CODE: %10hhu | CHECKSUM: %23hu │\n", icmpheader -> type, icmpheader -> code, icmpheader -> checksum);
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | ID: %32hu | SEQ: %28hu |\n", icmpheader -> un.echo.id, icmpheader -> un.echo.sequence);
		printf("    +--------------------------------------+-----------------------------------+\n");
	}
	else if (icmpheader -> type == 4 || icmpheader -> type == 5 || icmpheader -> type == 4) {
		printf("    Time exceeded:\n");
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | TYPE: %11hhu | CODE: %10hhu | CHECKSUM: %23hu |\n", icmpheader -> type, icmpheader -> code, icmpheader -> checksum);
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("\n    Original Datagram\n");
		printf("    -----------------\n");
		struct iphdr* ip_header = (struct iphdr*)((char*) icmpheader + sizeof(struct icmphdr));
		print_ip_header(ip_header);
		if(ip_header -> protocol == IPPROTO_TCP) print_tcp_header((struct tcphdr*)((char*) ip_header + (ip_header -> ihl << 2)));
		else if(ip_header -> protocol == IPPROTO_UDP) print_udp_header((struct udphdr*)((char*) ip_header + (ip_header -> ihl << 2)));
	}
	else {
		printf("    +-------------------+------------------+-----------------------------------+\n");
		printf("    | TYPE: %11hhu | CODE: %10hhu | CHECKSUM: %23hu |\n", icmpheader -> type, icmpheader -> code, icmpheader -> checksum);
		printf("    +-------------------+------------------+-----------------------------------+\n");
	}
	printf("\n");
}

// discover the next router
// returns 0 on ok, non-zero on unknown
int discover_ith_router(int sockfd, int ttl_inc, struct sockaddr_in serv_addr, struct sockaddr_in * next_hop_dest) {

	struct iphdr * ip_header;
	struct icmphdr * icmp_header;
	char buff[MSG_SZ];
	int my_id = htons(getpid() & 0xffff);
	// ssize_t n;

	// ip header
	ip_header = (struct iphdr *) buff;
	ip_header -> version = 4;
	ip_header -> ihl = 20 >> 2;
	ip_header -> tos = 0;
	ip_header -> tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr));
	ip_header -> id = my_id;
	ip_header -> frag_off = 0;
	ip_header -> ttl = ttl_inc;
	ip_header -> protocol = IPPROTO_ICMP;
	ip_header -> check = 0;
	ip_header -> saddr = 0;
	ip_header -> daddr = serv_addr.sin_addr.s_addr;

	// icmp header
	icmp_header = (struct icmphdr *)(buff + sizeof(struct iphdr));
	icmp_header -> type = 8;
	icmp_header -> code = 0;
	icmp_header -> checksum = 0;
	icmp_header -> un.echo.id = my_id;  // identifier field
	icmp_header -> un.echo.sequence = 0;      // sequence number

	// compute ICMP checksum struct timeval tv;
	icmp_header -> checksum = calculate_checksum((unsigned short *) icmp_header, sizeof(struct icmphdr));

	ssize_t send_ret = sendto(sockfd, buff, sizeof(struct icmphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (send_ret < 0) {
		perror("sendto() failed");
		return 1;
	}



	#ifndef QUIET
	pthread_mutex_lock(&stdlock);
	printf("  Sent Packet >>>>>>\n");
	printf(GREEN);
	print_ip_header(ip_header);
	print_icmp_packet(icmp_header, send_ret - sizeof(struct iphdr) - sizeof(struct icmphdr));
	printf("\n\n\n");
	printf(DEFAULT);
	fflush(stdout);
	pthread_mutex_unlock(&stdlock);
	#endif

	while (1) {
		int serv_len = sizeof(*next_hop_dest);
		struct pollfd poller;
		poller.fd = sockfd;
		poller.events = POLLIN;
		int poll_ret = poll(&poller, 1, TIME_OUT_MILISEC);
		if (poll_ret <= 0) {
			return 2;
			// printf(" %15s | ", (temp_addr.s_addr == 0xFFFF) ? "Unknown" : inet_ntoa(temp_addr));
			// temp_addr.s_addr = 0xFFFF;
			// printf("%15s | %6s\n", (temp_addr.s_addr == 0xFFFF) ? "Unknown" : inet_ntoa(temp_addr), "NA");
			// fflush(stderr);
		}
		else {
			ssize_t ret_recv;
			if ((ret_recv = recvfrom(sockfd, buff, MSG_SZ, 0, (struct sockaddr *) next_hop_dest, (socklen_t *__restrict) &serv_len)) <= 0) {
				return 4;
			}

			ip_header = (struct iphdr *) buff;
			icmp_header = (struct icmphdr *) (buff + ((ip_header -> ihl) << 2));

			// ip_header = (struct iphdr *)  buff + sizeof(struct icmphdr) + sizeof(struct iphdr);
			#ifndef QUIET
			pthread_mutex_lock(&stdlock);
			printf("  Received Packet <<<<<<\n");
			printf(CYAN);
			print_ip_header(ip_header);
			print_icmp_packet(icmp_header, ret_recv - ((ip_header -> ihl) << 2) - sizeof(struct icmphdr));
			printf(DEFAULT);
			printf("\n\n\n");
			fflush(stdout);
			pthread_mutex_unlock(&stdlock);
			#endif

			if (icmp_header -> type != 11 && icmp_header -> type != 0) { // something else is received

				// ip header of the packet which was dropped that cause this packet to arrive
				;

			} else {
				fprintf(stderr, "Next hop is %u (%s) \n", next_hop_dest -> sin_addr.s_addr, inet_ntoa(next_hop_dest -> sin_addr));
				return 0;
			}
		}
	}
}


// recv_thread();
long long * send_time;
long long * recv_time;

void * recv_thread(void * arg) {

	int sockfd = *((int*) arg);
	struct iphdr * ip_header;
	struct icmphdr * icmp_header;
	char buff[MSG_SZ];
	// int my_id = htons(getpid() & 0xffff);
	struct timeval tv2;
	recv_sz = 0;

	for (int i = 0; i < N_PING; ++i) {
		recv_time[i] = 3e17;
	}
	for (int r = 0; r < N_PING; ++r) {
		while (1) {
			struct sockaddr_in temp_sockaddr;
			int serv_len = sizeof(temp_sockaddr);
			struct pollfd poller;
			poller.fd = sockfd;
			poller.events = POLLIN;
			int poll_ret = poll(&poller, 1, TIME_OUT_MILISEC + T * 1000);
			if (poll_ret <= 0) {
				fprintf(stderr, "poll time limit exceeded\n");
				break;
			}
			else {
				ssize_t ret_recv;
				if ((ret_recv = recvfrom(sockfd, buff, MSG_SZ, 0, (struct sockaddr *) &temp_sockaddr, (socklen_t *__restrict) &serv_len)) <= 0) {
					perror("error in recvfrom()");
					exit(16);
				}

				gettimeofday(&tv2, NULL);
				ip_header = (struct iphdr *) buff;
				icmp_header = (struct icmphdr *) (buff + ((ip_header -> ihl) << 2));

				#ifndef QUIET
				pthread_mutex_lock(&stdlock);
				printf("  Received Packet <<<<<<\n");
				printf(CYAN);
				print_ip_header(ip_header);
				print_icmp_packet(icmp_header, ret_recv - ((ip_header -> ihl) << 2) - sizeof(struct icmphdr));
				printf(DEFAULT);
				printf("\n\n\n");
				fflush(stdout);
				pthread_mutex_unlock(&stdlock);
				#endif

				if (icmp_header -> type != 11 && icmp_header -> type != 0 && ((unsigned short)icmp_header -> un.echo.sequence < N_PING)) { // something else is received
					;		
				} else {
					// long long rtt_sample = tv2.tv_sec * (uint64_t)1000000 + tv2.tv_usec - tv1.tv_sec * (uint64_t)1000000 - tv1.tv_usec;
					// printf("Time taken = %lld\n", rtt_sample);
					// if(rtt_sample < min_rtt){
					// 	min_rtt = rtt_sample;
					// }
					// avg_rtt += rtt_sample;


					pthread_mutex_lock(&stdlock);
					printf("Ping number %d received [%ld bytes]\n", icmp_header -> un.echo.sequence, ret_recv);
					fflush(stdout);
					pthread_mutex_unlock(&stdlock);
					recv_sz += ret_recv - ((ip_header -> ihl) << 2) - sizeof(struct icmphdr);
					recv_time[icmp_header -> un.echo.sequence] = tv2.tv_sec * (uint64_t)1000000 + tv2.tv_usec;
					break;
				}
			}
		}
	}
	// rounded avg
	recv_sz = (int)(1.0 * recv_sz / N_PING + 0.5);
	return NULL;
}


// ping. try 5 times and return min rtt
long double ping_next_hop(int sockfd, struct sockaddr_in * next_hop_dest, int sz) {

	struct iphdr * ip_header;
	struct icmphdr * icmp_header;
	char buff[MSG_SZ];
	int my_id = htons(getpid() & 0xffff);

	send_time = (long long *)malloc(sizeof(long long) * N_PING);
	recv_time = (long long *)malloc(sizeof(long long) * N_PING);

	pthread_t recv_t;
	pthread_create(&recv_t, NULL, recv_thread, &sockfd);

	// try out 5 times concurrently
	for (int ping_it = 0; ping_it < N_PING; ++ping_it, sleep(T)) {
		char * data = buff + sizeof(struct icmphdr) + sizeof(struct iphdr);
		for (int i = 0; i < sz; ++i) { // not needed, but still doing it for completeness and easier debugging
			data[i] = 'A';
		}
		// struct sockaddr_in client_addr;
		struct timeval tv1;


		// ip header
		ip_header = (struct iphdr *) buff;
		ip_header -> version = 4;
		ip_header -> ihl = 20 >> 2;
		ip_header -> tos = 0;
		ip_header -> tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr) + sz);
		ip_header -> id = my_id;
		ip_header -> frag_off = 0;
		ip_header -> ttl = TTL_MAX;
		ip_header -> protocol = IPPROTO_ICMP;
		ip_header -> check = 0;
		ip_header -> saddr = 0;
		ip_header -> daddr = next_hop_dest -> sin_addr.s_addr;

		// icmp header
		icmp_header = (struct icmphdr *)(buff + sizeof(struct iphdr));
		icmp_header -> type = 8;
		icmp_header -> code = 0;
		icmp_header -> checksum = 0;
		icmp_header -> un.echo.id = my_id;  // identifier field
		icmp_header -> un.echo.sequence = ping_it;      // sequence number

		// compute ICMP checksum struct timeval tv;
		icmp_header -> checksum = calculate_checksum((unsigned short *) icmp_header, sizeof(struct icmphdr) + sz);

		gettimeofday(&tv1, NULL);
		send_time[icmp_header -> un.echo.sequence] = tv1.tv_sec * (uint64_t)1000000 + tv1.tv_usec;
		if (sendto(sockfd, buff, sizeof(struct icmphdr) + sizeof(struct iphdr) + sz, 0, (struct sockaddr *)next_hop_dest, sizeof(*next_hop_dest)) < 0) {
			perror("sendto() failed");
			exit(8);
		}

		pthread_mutex_lock(&stdlock);
		printf("Ping number %d sent     [%ld (header) + %d (data) bytes]\n", icmp_header -> un.echo.sequence, sizeof(struct icmphdr) + sizeof(struct iphdr), sz);
		fflush(stdout);
		pthread_mutex_unlock(&stdlock);

		#ifndef QUIET
		pthread_mutex_lock(&stdlock);
		printf("  Sent Packet >>>>>>\n");
		printf(GREEN);
		print_ip_header(ip_header);
		print_icmp_packet(icmp_header, sz);
		printf("\n\n\n");
		printf(DEFAULT);
		fflush(stdout);
		pthread_mutex_unlock(&stdlock);
		#endif

	}

	pthread_join(recv_t, NULL);

	long long min_rtt = 3e17;
	for (int i = 0; i < N_PING; ++i) {
		if (min_rtt > recv_time[i] - send_time[i]) {
			min_rtt = recv_time[i] - send_time[i];
		}
	}

	// avg_rtt /= N_PING;

	// return avg_rtt;
	free(send_time);
	free(recv_time);
	return (min_rtt > 2e17) ? NOTFOUND : min_rtt;

}




// formatted printing of latency and bandwidth
void print_latency_bandwidth(struct sockaddr_in next_hop_source, struct sockaddr_in next_hop_dest, long double l, long double b, int hop_n, int prev_time_not_found) {
	printf(BOLD);
	printf("\n\t\t\t +---------------------------------------------+\n");
	printf("\t\t\t |    # In The Link (Hop %2d)                   |\n", hop_n);
	printf("\t\t\t |    # From      : %15s            |\n", inet_ntoa(next_hop_source.sin_addr));
	printf("\t\t\t |    # To        : %15s            |\n", inet_ntoa(next_hop_dest.sin_addr));
	if (prev_time_not_found) {
		printf("\t\t\t |    # Latency   : <NA>                       |\n");
	    printf("\t\t\t |    # Bandwidth : <NA>                       |\n");
		printf("\t\t\t +---------------------------------------------+\n\n");
		printf(NONBOLD);
		fflush(stdout);
		return;
	}

	printf("\t\t\t |    # Latency   : %13.6Lf microseconds |\n", l);
	printf("\t\t\t |    # Bandwidth : %13.6Lf MBps         |\n", b);
	printf("\t\t\t +---------------------------------------------+\n\n");
	printf(NONBOLD);
	fflush(stdout);
}

int main(int argc, char ** argv) {

	fprintf(stderr, ITALIC "\nKindly read \'README\' from line 20 of pingnetinfo.c before compiling and running code!\n" NONBOLD); 
	fflush(stderr); 
	usleep(1500000);

	pthread_mutex_init(&stdlock, NULL);
	if (argc < 4) {
		fprintf(stderr, "Invalid command! run as \n\t $ sudo ./pingnetinfo.out <url> <n> <T>\n");
		exit(1);
	}

	// get arguments
	int n;
	N_PING = n = atoi(argv[2]);
	T = atoi(argv[3]);

	// the info about the final destination
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	char * IP_addr;
	unsigned IP_val = url_to_ip(argv[1], &IP_addr, & serv_addr);

	// open raw socket
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		perror("Error in opening raw socket");
		exit(2);
	}

	// set sockopt so as to include the IP headers
	int one = 1;
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));


	struct sockaddr_in next_hop_dest;
	struct sockaddr_in next_hop_source;
	next_hop_dest.sin_family = AF_INET;
	next_hop_source.sin_family = AF_INET;
	next_hop_source.sin_addr.s_addr = INADDR_ANY;


	int ttl_inc = 1;
	// printf(" %15s | %15s | %20s\n", "FROM", "TO", "RTT TIME");
	// printf("-----------------+-----------------+---------------------\n");
	int ITERATION_LIMIT = 32;
	long double prev_time[2] = {0, 0}; // prev_time[0] is 0 sized packet, prev_time[1] is MSG_BW sized packet
	while (ITERATION_LIMIT--) {

		// discover the IP of the next router
			
		// if (discover_ith_router(sockfd, ttl_inc++, serv_addr, &next_hop_dest)) {
		// 	print_latency_bandwidth(next_hop_source, next_hop_dest, 0, 0, 1);
		// 	prev_time[0] = prev_time[1] = NOTFOUND;
		// 	continue;
		// }
		int link_not_responding = 0;
		unsigned int last_ip = 0;
		int last_ip_stays_constant = 0;
		int discover_while_lim = 20;
		while(last_ip_stays_constant < 5 && discover_while_lim--){
			sleep(1);
			if (discover_ith_router(sockfd, ttl_inc, serv_addr, &next_hop_dest)) { 
				// link did not respond
				prev_time[0] = prev_time[1] = NOTFOUND;
				link_not_responding = 1;
				break;
			}
			if(next_hop_dest.sin_addr.s_addr == last_ip){
				last_ip_stays_constant++;
			}else{
				last_ip = next_hop_dest.sin_addr.s_addr;
				last_ip_stays_constant = 1;

			}
		}
		ttl_inc++;
		if(link_not_responding || discover_while_lim < 0){
			fprintf(stderr, YELLOW "Failed to finalize next hop\n" DEFAULT);
			continue;
		}
		fprintf(stderr, YELLOW "Finalized next hop as %u (%s) \n" DEFAULT, next_hop_dest.sin_addr.s_addr, inet_ntoa(next_hop_dest.sin_addr));



		// long double min_curr_time[2] = {3e15, 3e15};
		// long double avg_curr_time[2] = {0, 0};
		
		// ping it n times;
		long double curr_time[2];
		printf("\n"); fflush(stdout);
		curr_time[0] = ping_next_hop(sockfd, &next_hop_dest, 0); // empty packet
		printf("\n"); fflush(stdout);
		curr_time[1] = ping_next_hop(sockfd, &next_hop_dest, MSG_BW); // not empty packet
		printf("\n"); fflush(stdout);
		if(curr_time[1] != NOTFOUND && curr_time[2] != NOTFOUND){
			printf(ITALIC "      RTT's are %Lf microseconds(%d bytes of data), %Lf microseconds(%d bytes of data)\n" NONBOLD, curr_time[0], 0, curr_time[1], MSG_BW);
		}
		long double latency   = (curr_time[0] - prev_time[0]) / 2.0;
		long double bandwidth = (recv_sz + MSG_BW) / (1.0 * curr_time[1] - prev_time[1] - curr_time[0] + prev_time[0]);

		// formatted printing
		// min_curr_time[0] = (min_curr_time[0] > curr_time[0]) ? curr_time[0] : min_curr_time[0];
		// min_curr_time[1] = (min_curr_time[1] > curr_time[1]) ? curr_time[1] : min_curr_time[1];
		// avg_curr_time[0] += curr_time[0];
		// avg_curr_time[1] += curr_time[1];
		print_latency_bandwidth(next_hop_source, next_hop_dest, latency, bandwidth, ttl_inc - 1, (prev_time[0] == NOTFOUND) || (curr_time[0] == NOTFOUND));

		// avg_curr_time[0] /= n;
		// avg_curr_time[1] /= n;

		// prev_time[0] = avg_curr_time[0];
		prev_time[0] = curr_time[0];
		// prev_time[1] = avg_curr_time[1];
		prev_time[1] = curr_time[1];

		// this is the last hop
		if (next_hop_dest.sin_addr.s_addr == IP_val) break;

		// set current next hop destination to the next hop source for the upcoming iteration
		next_hop_source = next_hop_dest;
	}

	if (ITERATION_LIMIT < 0) {
		printf("\nMaximum hop limit exceeded! Stopping\n");
	} else {
		printf(" -----------------+-----------------------------+---------------------\n");
		printf(" -----------------|   Terminating Succesfully   |---------------------\n");
		printf(" -----------------+-----------------------------+---------------------\n");

	}
	close(sockfd);
	pthread_mutex_destroy(&stdlock);
	return 0;
}