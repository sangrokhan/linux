#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

int in_cksum(u_short *p, int n);

int main(int argc, char **argv)
{
   int icmp_socket;
   int ret;
   struct icmp *p, *rp;
   struct sockaddr_in addr, from;
   struct ip *ip;
   char buffer[1024];
   int sl;
   int hlen;
   int ping_pkt_size;

   if((icmp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
   {
      perror("Socket error : ");
      exit(0);
   }

   memset(buffer, 0x00, 1024);

   p = (struct icmp*)buffer;
   p->icmp_type = ICMP_ECHO;
   p->icmp_code = 0;
   p->icmp_cksum = 0;
   p->icmp_seq = 15;
   p->icmp_id = getpid();

   p->icmp_cksum = in_cksum((u_short*)p, 1000);
   
   memset(&addr, 0, sizeof(0));
   
   addr.sin_addr.s_addr = inet_addr(argv[1]);
   addr.sin_family = AF_INET;

   if((ret = sendto(icmp_socket, p, sizeof(*p), MSG_DONTWAIT, (struct sockaddr*)&addr, sizeof(addr))) < 0)
   {
      perror("Sendto error : ");
   }

   sl = sizeof(from);
   if((ret = recvfrom(icmp_socket, buffer, 1024, 0, (struct sockaddr*)&from, &sl)) < 0)
   {
      printf("%d %d %d\n", ret, errno, EAGAIN);
      perror("recvfrom error : ");
   }

   ip = (struct ip*)buffer;
   hlen = ip->ip_hl*4;
   rp = (struct icmp*)(buffer + hlen);

   printf("Reply from %s\n", inet_ntoa(from.sin_addr));
   printf("Type : %d\n", rp->icmp_type);
   printf("Code : %d\n", rp->icmp_code);
   printf("Seq : %d\n", rp->icmp_seq);
   printf("ID : %d\n", rp->icmp_id);

   return 1;
}

int in_cksum(u_short *p, int n)
{
   register u_short answer;
   register long sum = 0;
   u_short odd_byte = 0;

   while(n > 1)
   {
      sum += *p++;
      n -= 2;
   }

   if(n == 1)
   {
      *(u_char*)(&odd_byte) = *(u_char*)p;
      sum += odd_byte;

   }

   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;

   return (answer);
}


