#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// 클라이언트는 데이터를 직접 입력하여 서버로 전송하고 서버로부터 에코 데이터를 수신하여 출력
// 클라이언트의 recvfrom()의 경우 소켓에 bind() 과정이 없으므로 문제가 생김
// 하지만 sendto()를 실행시키는 시점에 내부적으로 bind()가 된다고 보면 됨. 따라서 에코 데이터를 수신 가능
// UDP의 경우 bind()를 통해 특정 포트를 할당하지 않아도 상관 없음. 유효한 IP로 sendto 하고, 받는쪽은 recvfrom 함수로 보낸쪽의 IP와 포트번호 확인 가능. 구현하기 나름
main(int argc, char *argv[]) {
    int sd;
    struct sockaddr_in s_addr;
    char sndBuffer[BUFSIZ], recvBuffer[BUFSIZ];
    int n, n_send;
    int addr_len;
 
	// 소켓 생성
    sd = socket(AF_INET, SOCK_DGRAM, 0);
 
	// 연결할 서버 주소 설정
    bzero(&s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    s_addr.sin_port = htons(9200);
 
    while(1) {
        fprintf(stderr, "waiting\n");
 
		// 데이터 직접 입력
        if((n = read(0, sndBuffer, BUFSIZ)) > 0) {
            sndBuffer[n] = '\0';
            if(!strcmp(sndBuffer, "quit\n")) break;
 
            printf("original Data : %s", sndBuffer);
 
	 		// 데이터 송신
			// sock_fd : 소켓 기술자
			// buf : 전송할 자료의 버퍼 주소
			// nbyte : 전송할 자료의 크기(바이트)
			// flags : 특정 옵션을 설정한다. 보통의 경우에는 0을 설정한다.
			// to : 자료를 수신할 호스트 주소(IP 주소와 포트 번호)
			// addrlen : 수신자의 소켓 주소 구조의 크기
            if((n_send = sendto(sd, sndBuffer, strlen(sndBuffer), 0, (struct sockaddr *) &s_addr, sizeof(s_addr))) < 0) {
                printf("sendto() error\n");
                exit(-3);
            }
 
            addr_len = sizeof(s_addr);

			// 데이터 수신
			// sock_fd : 소켓 기술자
			// buf : 수신할 자료를 저장하는 버퍼 주소
			// nbyte : 수신할 자료의 최대 크기
			// flags : 특정 옵션을 설정한다. 보통의 경우 0을 설정한다.
			// from : 자료를 보낸 호스트 주소(IP 주소와 포트 번호)
			// addrlen : 송신자의 소켓 주소 구조의 크기
			// 자료 발신지를 알 필요가 없을 경우 from, addrlen 인자를 NULL 사용
            if((n = recvfrom(sd, recvBuffer, sizeof(recvBuffer), 0, NULL, NULL)) < 0) {
                printf("recvfrom() error\n");
                exit(-3);
            }
            sndBuffer[n] = '\0';
 
            printf("echoed Data : %s", recvBuffer);
        }
    }
    close(sd);
}
