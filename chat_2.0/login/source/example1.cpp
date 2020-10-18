#include <stdio.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
 
 
#define MAXBUF 1024
#define MAXEPOLLSIZE 10000
 
 
int main(int argc, char *argv[])
{
	//设置端口
	if(argc != 2)
	{  
		printf("请设置端口号！\n");
	}
	int port = atoi(argv[1]);  
	
	int listener, conn_sock, kdpfd, nfds, n, ret, curfds;
	socklen_t len;
	struct sockaddr_in server_addr, client_addr;
	struct epoll_event ev;
	struct epoll_event pevent[MAXEPOLLSIZE];
	struct rlimit rt;
	rt.rlim_max = rt.rlim_cur = MAXEPOLLSIZE;
	
	//设置系统资源，打开最大文件数
	if (setrlimit(RLIMIT_NOFILE, &rt) == -1)
	{
		perror("setrlimit");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("设置系统资源参数成功！\n");
	}
	
	//创建socket
	if( (listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("socket 创建成功！\n");
	}
	
	//设置非堵塞
	if (fcntl(listener, F_SETFL, fcntl(listener, F_GETFL, 0) | O_NONBLOCK) == -1)
	{
		perror("fcntl");
		exit(EXIT_FAILURE);
	}
	
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;  //0.0.0.0所有地址
	
	//绑定
	if ( bind( listener, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) == -1 )
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("IP 地址和端口绑定成功\n");
	}
	
	if (listen(listener, 10) == -1)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("开启服务成功！\n");
	}
 
	//创建epoll为ET模式
	kdpfd = epoll_create(MAXEPOLLSIZE);
	len = sizeof(struct sockaddr_in);
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = listener;
	
	//socket加入epoll
	if( epoll_ctl(kdpfd, EPOLL_CTL_ADD, listener, &ev) < 0 )
	{
		fprintf( stderr, "epoll set insertion error: fd=%d\n", listener );
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("监听 socket 加入 epoll 成功！\n");
	}
	
	//设置延迟和事件个数,事件由累加完成
	curfds = 1;
	//int timeout = 10*1000;
	while(1)
	{
		//等待有事件发生
		//nfds = epoll_wait(kdpfd, pevent, curfds, timeout);
		nfds = epoll_wait(kdpfd, pevent, curfds, -1);
		if( nfds == -1 )
		{
			perror("epoll_wait");
			break;
		}
		else if (nfds == 0)
		{
			printf("waiting for connecting...\n");
			continue;
		}
		
		for (n = 0; n < nfds; ++n)
		{
			if ((pevent[n].events & EPOLLERR) || (pevent[n].events & EPOLLHUP) || (!(pevent[n].events & EPOLLIN)))
			{
				//此FD上发生错误，或者套接字未准备好读取（那么为什么通知我们？）
				fprintf (stderr, "epoll error\n");
				close(pevent[n].data.fd);
				continue;
			}
			else if (pevent[n].data.fd == listener)
			{
				//我们在监听套接字上有一个通知,这意味着一个或多个传入连接
				while (1)
				{
					conn_sock = accept(listener, (struct sockaddr*)&client_addr, &len);
					if( conn_sock == -1 )
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
						{
							//我们已经处理了所有传入的连接
							break;
						}
						else
						{
							perror ("accept error");
							break;
						}
					}
					//else	
					//	printf("有连接来自于： %s:%d， 分配的 socket 为:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), conn_sock);
					
					char hbuf[1024], sbuf[1024];
					if ( 0 == getnameinfo((struct sockaddr*)&client_addr, len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))
						printf("Accepted connection on descriptor %d (host=%s, port=%s)\n", conn_sock, hbuf, sbuf);
					
					if (fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK) == -1)
					{
						perror("fcntl");
						break;
					}
 
					ev.events = EPOLLIN | EPOLLET;
					ev.data.fd = conn_sock;
					
					if( -1 == epoll_ctl( kdpfd, EPOLL_CTL_ADD, conn_sock, &ev))
					{
						fprintf(stderr, "把 socket '%d' 加入 epoll 失败！%s\n", conn_sock, strerror(errno));
						exit(EXIT_FAILURE);
					}
					
					curfds ++;					
				}
				continue;
			}
			else
			{
				if (do_use_fd(pevent[n].data.fd) < 0)
				{
					printf ("关闭 %d\n", pevent[n].data.fd);					
					epoll_ctl(kdpfd, EPOLL_CTL_DEL, pevent[n].data.fd,&ev);
                    close(pevent[n].data.fd);
					curfds--;
				}
			}
		}
	}
	
	close(listener);
	close(kdpfd);
	return 0;
}
 
int do_use_fd(int connfd)
{
	int done = 0;
	
	while(1)
	{
		char buf[MAXBUF + 1];
		bzero(buf, MAXBUF + 1);
		int nread;
		
		//读取客户端socket流
		nread = recv(connfd, buf, MAXBUF, 0);
		if (nread == -1)
		{
			if (errno != EAGAIN)
			{
				perror ("recv");
				done = -1;
			}
			break;
		}
		else if (nread == 0)
		{
			done = -1;
			break;
		}
		
		printf("%d接收消息成功:'%s'，共%d个字节的数据\n", connfd, buf, nread);
		
		//响应客户端 
		if ( -1 == send(connfd, buf, strlen(buf), 0))
			perror ("write");
	}
 
    return done;
}