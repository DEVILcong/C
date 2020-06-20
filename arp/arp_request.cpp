#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <thread>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

using namespace std;

//#define NETWORK_DEVICE_NAME "wlp3s0"
#define uchar unsigned char

struct arp_packet{
    //first layer
    char dest_MAC[6];
    char srce_MAC[6];
    uchar type[2];

    //second layer
    uchar hw_t[2];
    uchar protocol_t[2];
    uchar hw_size;
    uchar protocol_size;
    uchar opcode[2];

    char src_MAC[6];
    u_int32_t src_IP;
    char dst_MAC[6];
    u_int32_t dst_IP;

    char padding[18];
};

extern int h_errno;
extern int errno;

void recv_cout(int recv_socket){
    unsigned char buf[80];
    memset(buf, 0, 80);

    struct in_addr convert;

    arp_packet* tmp_packet = nullptr;

    struct timeval tv = {3, 0};      //set receive timeout 3s
    if(setsockopt(recv_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0){
        cout << "ERROR: failed to set socket receive timeout" << endl;
        cout << strerror(errno) << endl;
    }

    for(int i = 0; i < 5000; ++i){
        if(recvfrom(recv_socket, buf, sizeof(buf), 0, NULL, NULL) < 0){
            if(errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else{
                cout << "ERROR: during receiving" << endl;
                cout << strerror(errno) << endl;
            }
        }
        tmp_packet = (arp_packet*)buf;
        convert.s_addr = tmp_packet->src_IP;
        cout << inet_ntoa(convert) << "\t";
        for(char i = 0; i < 6; ++i)
            cout << hex << (unsigned int)((unsigned char)tmp_packet->src_MAC[i]) << " ";
        cout << endl;
        memset(tmp_packet, 0, sizeof(tmp_packet));
    }

    return;
}

int main(int argc, char** argv){
    if(argc != 2){
        cout << "usage for example: arpScan wlp3s0" << endl;
        return 0;
    }

    char hostname[15];
    hostent* host = nullptr;
    struct in_addr ipaddr;
    unsigned int ip_in_dec;
    unsigned int tmp_ip_addr;
    int packet_socket;
    struct ifreq get_Mac;
    char MAC[6];
    struct sockaddr_ll send_addr;
    struct arp_packet packet_to_send;

    memset(hostname, 0, 15);

    //get hostname
    gethostname(hostname, 15);
    cout << "hostname: " << hostname << endl;

    //get IP addr use hostname
    host = gethostbyname(hostname);
    if(host == nullptr){
        cout << "ERROR:" << hstrerror(h_errno) << endl;
        return 0;
    }

    ipaddr.s_addr = *(uint32_t*)(host->h_addr);
    cout << "IP address: " << inet_ntoa(ipaddr)<< endl;
    ip_in_dec = ntohl((ipaddr.s_addr) & 0x00ffffff);
    //ipaddr.s_addr = htonl(ip_in_dec);
    //cout << inet_ntoa(ipaddr) << endl;
    
    //open socket
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(packet_socket < 0){
        cout << "ERROR: create packet socket failed" << endl;
        cout << strerror(errno) << endl;
        return 0;
    }
    //const int const_int_1 = 1;
    //if(int result = setsockopt(packet_socket, SOL_SOCKET, SO_BROADCAST, &const_int_1, sizeof(const_int_1)) < 0){
    //    cout << "ERROR: setsockopt failed " << result << endl;
    //}

    //get MAC address
    strcpy(get_Mac.ifr_name, argv[1]);
    if(ioctl(packet_socket, SIOCGIFHWADDR, &get_Mac) < 0){
        cout << "ERROR: failed to get MAC address, error is "  << strerror(errno) << endl;
        cout << "One possible reason is that you didn't run it as root" << endl;
        close(packet_socket);
        return 0;
    }
    strncpy(MAC, get_Mac.ifr_hwaddr.sa_data, 6);
    cout  << "MAC address: " ;
    for(char i = 0; i < 6; ++i)
        cout << hex << (unsigned int)((unsigned char)MAC[i]) << " ";
    cout << endl;
    
    memset(&get_Mac, 0, sizeof(get_Mac));
    strcpy(get_Mac.ifr_name, argv[1]);
    if(ioctl(packet_socket, SIOCGIFINDEX, &get_Mac) < 0){
        cout << "ERROR: failed to get interface index, error is "  << strerror(errno) << endl;
        cout << "One possible reason is that you didn't run it as root" << endl;
        close(packet_socket);
        return 0;
    }

    //prepare send addr
    memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_protocol = htons(ETH_P_ARP);
    send_addr.sll_pkttype = PACKET_BROADCAST;
    send_addr.sll_ifindex = get_Mac.ifr_ifindex;
    send_addr.sll_halen = 0x06;
    memset(send_addr.sll_addr, 0xff, 6);

    //prepare package to send
    memset(packet_to_send.dest_MAC, 0xff, 6);
    memcpy(packet_to_send.srce_MAC, MAC, 6);
    packet_to_send.type[0] = 0x08;
    packet_to_send.type[1] = 0x06;         //config first layer

    packet_to_send.hw_t[0] = 0x00;
    packet_to_send.hw_t[1] = 0x01;
    packet_to_send.protocol_t[0] = 0x08;
    packet_to_send.protocol_t[1] = 0x00;
    packet_to_send.hw_size = 0x06;
    packet_to_send.protocol_size = 0x04;
    packet_to_send.opcode[0] = 0x00;
    packet_to_send.opcode[1] = 0x01;

    memcpy(packet_to_send.src_MAC, MAC, 6);
    packet_to_send.src_IP = ipaddr.s_addr;
    memset(packet_to_send.dst_MAC, 0, 6);   //config second layer

    thread recv1(recv_cout, packet_socket);  //create receive thread

    //send package
    for(int i = 0; i < 254; ++i){
        ip_in_dec += 1;
        tmp_ip_addr = htonl(ip_in_dec);
        memcpy(&(packet_to_send.dst_MAC[6]), &tmp_ip_addr, 4);
        if(int length = sendto(packet_socket, &packet_to_send, sizeof(packet_to_send), 0,(struct sockaddr*) &send_addr, sizeof(send_addr)) < 0){
            cout << "WARNING: packet " << i << " failed to send" << endl;
            cout << strerror(errno) << endl;
        }
        else{
            //cout << sizeof(packet_to_send) << "  " << sizeof(send_addr) << endl;
            //cout << length << endl;
        }
    }

    recv1.join();
    close(packet_socket);
    return 0;
}
