#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
 
// 서버는 클라이언트로부터 받은 데이터를 출력하고 에코 데이터 전송
// UDP의 경우 bind()를 통해 특정 포트를 할당하지 않아도 상관 없음. 유효한 IP로 sendto 하고, 받는쪽은 recvfrom 함수로 보낸쪽의 IP와 포트번호 확인 가능. 구현하기 나름
main(int argc, char *argv[]) {
    int sd;
    struct sockaddr_in s_addr, c_addr;
    char buff[BUFSIZ];
    int n, n_recv;
    int addr_len;
 
	// 소켓을 생성
    sd = socket(AF_INET, SOCK_DGRAM, 0);	
 
	// 연결 요청을 수신할 주소 설정
    bzero(&s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    s_addr.sin_port = htons(9200);
 
	// 소켓을 포트에 연결
    if(bind(sd, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
        printf("bind() error");
        exit(-2);
    }
 
    while(1) {
        printf("waiting\n");
 
        addr_len = sizeof(c_addr);

		// 데이터 수신
		// sock_fd : 소켓 기술자
		// buf : 수신할 자료를 저장하는 버퍼 주소
		// nbyte : 수신할 자료의 최대 크기
		// flags : 특정 옵션을 설정한다. 보통의 경우 0을 설정한다.
		// from : 자료를 보낸 호스트 주소(IP 주소와 포트 번호)
		// addrlen : 송신자의 소켓 주소 구조의 크기
		// 자료 발신지를 알 필요가 없을 경우 from, addrlen 인자를 NULL 사용
        if((n_recv = recvfrom(sd, buff, sizeof(buff), 0, (struct sockaddr *)&c_addr, &addr_len)) < 0) {
            printf("recvfrom() error");
            exit(-3);
        }
		printf("recv data : %s", buff);
 
		// 데이터 송신
		// sock_fd : 소켓 기술자
		// buf : 전송할 자료의 버퍼 주소
		// nbyte : 전송할 자료의 크기(바이트)
		// flags : 특정 옵션을 설정한다. 보통의 경우에는 0을 설정한다.
		// to : 자료를 수신할 호스트 주소(IP 주소와 포트 번호)
		// addrlen : 수신자의 소켓 주소 구조의 크기
        if((n = sendto(sd, buff, n_recv, 0, (struct sockaddr *) &c_addr, sizeof(c_addr))) < 0) {
            printf("sendto() error");
            exit(-3);
        }
	printf("echo send complete\n");
    }
    close(sd);
}
