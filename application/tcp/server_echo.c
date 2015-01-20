#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define BUF 1460

int main(int argc, char *argv[])
{
   int serv_sd;
   int clnt_sd;
   int fd;

   struct sockaddr_in serv_addr;
   struct sockaddr_in clnt_addr;

   char message[BUF];
   char message_exit[] = "exit\n";

   int clnt_addr_size;
   int str_len;
   int i = 0;

   if(argc != 2)
   {
      printf("usage : %s [port]\n", argv[0]);
   }

   if((serv_sd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
   {
      printf("Server : Can't open stream socket.\n");
      exit(0);
   }

   memset(&serv_addr, 0, sizeof(serv_addr));
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   serv_addr.sin_port = htons(atoi(argv[1]));
   
   if(bind(serv_sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
   {
      printf("Server : Can't bind local address.\n");
      exit(0);
   }

   if(listen(serv_sd, 5) < 0)
   {
      printf("Server : Can't listening connect.\n");
      exit(0);
   }

   while(1)
   {
      clnt_addr_size = sizeof(clnt_addr);
      if((clnt_sd = accept(serv_sd, (struct sockaddr*)&clnt_addr, &clnt_addr_size)) < 0)
      {
         printf("Server : Accept failed.\n");
         exit(0);
      }

      while((str_len = read(clnt_sd, message, BUF)) != 0)
      {
         if(strcmp(message, message_exit) == 0)
         {
            printf("Bye\n");
            exit(1);
         }

         write(clnt_sd, message, str_len);
         write(1, message, str_len);
      }

      close(clnt_sd);
   }

   close(fd);

   return 0;
}

