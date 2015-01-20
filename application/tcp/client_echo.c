#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF 80

int main(int argc, char *argv[])
{
   int sd;
//   int fd;
   int str_len;
   struct sockaddr_in serv_addr;
   char message[BUF];
   
   if(argc < 2)
   {
      printf("usage : %s IP_ADDRESS PORT\n", argv[0]);
      exit(0);
   }

//   fd = open("receive.txt", O_WRONLY|O_CREAT|O_TRUNC);

   if((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
   {
      printf("Client : Can't create socket.\n");
      exit(0);
   }
   else
   {
      printf("Client : Socket descriptor number is '%d'.\n", sd);
   }

   memset(&serv_addr, 0, sizeof(serv_addr));
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
   serv_addr.sin_port = htons(atoi(argv[2]));

   if((connect(sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0)
   {
      printf("Client : Can't connect.\n");
      exit(0);
   }

   while(1)
   {
      fputs("Client : Insert the message to server (exit to quit) -> ", stdout);
      fgets(message, BUF, stdin);

      write(sd, message, strlen(message));

      if(!strcmp(message, "exit\n"))
         break;

      str_len = read(sd, message, BUF-1);
      message[str_len] = 0;

      fprintf(stdout, "Server : %s\n", message);
   }
   
   close(sd);

   return 0;
}


