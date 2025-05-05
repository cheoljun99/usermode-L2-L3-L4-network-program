#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>         

#include <thread>
#include <mutex>

#include <linux/ethtool.h>
#include <linux/sockios.h>


using namespace std;


std::mutex send_lock;  // 전역 뮤텍스


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


typedef struct iface {
    Ip ip;
    Mac mac;
}IFACE;

#define PUBLIC_IFACE_NAME_HARDCODE "wlo1"
#define PRIVATE_IFACE_NAME_HARDCODE "enx8cb0e9e8cf94"
#define PUBLIC_GATEWAY_IP_HARDCODE "192.168.0.1"
#define PRIVATE_GATEWAY_IP_HARDCODE "192.168.0.111"

IFACE* get_iface_IP_and_MAC(const char* ifname) {
    printf("Get interface IP and MAC, and disable offload features\n");
    struct ifreq s;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        perror("socket creation failed");
        return nullptr;
    }

    IFACE* iface = new IFACE;
    strncpy(s.ifr_name, ifname, IFNAMSIZ - 1);

    // MAC 주소 가져오기
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        unsigned char* mac = (unsigned char*)s.ifr_hwaddr.sa_data;
        iface->mac = Mac(mac);
        printf("Network interface %s MAC: %s\n", ifname, std::string(iface->mac).c_str());
    } else {
        perror("Failed to get MAC address");
        close(fd);
        delete iface;
        return nullptr;
    }

    // IP 주소 가져오기
    if (ioctl(fd, SIOCGIFADDR, &s) == 0) {
        struct sockaddr_in* ipaddr = (struct sockaddr_in*)&s.ifr_addr;
        iface->ip = htonl(ipaddr->sin_addr.s_addr);
        printf("Network interface %s IP: %s\n", ifname, std::string(iface->ip).c_str());
    } else {
        perror("Failed to get IP address");
        close(fd);
        delete iface;
        return nullptr;
    }

    // 오프로드 끄기 함수 정의
    auto disable_offload = [&](__u32 cmd, const char* name) {
        struct ethtool_value eval = {0};
        struct ifreq ifr = {0};
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        eval.cmd = cmd;
        eval.data = 0;
        ifr.ifr_data = (caddr_t)&eval;

        if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
            fprintf(stderr, "Failed to disable %s on %s: %s\n", name, ifname, strerror(errno));
        } else {
            printf("Disabled %s on %s\n", name, ifname);
        }
    };

    disable_offload(ETHTOOL_SGSO, "GSO");
    disable_offload(ETHTOOL_SGRO, "GRO");

    close(fd);
    return iface;
}


Mac get_gateway_mac_using_ARP_request(IFACE * iface, Ip gateway_ip, pcap_t* handle) {

    EthArpPacket send_packet;
    send_packet.eth_.dmac_ = Mac::broadcastMac();
    send_packet.eth_.smac_ = iface->mac;
    send_packet.eth_.type_ = htons(EthHdr::Arp);
    send_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    send_packet.arp_.pro_ = htons(EthHdr::Ip4);
    send_packet.arp_.hln_ = Mac::SIZE;
    send_packet.arp_.pln_ = Ip::SIZE;
    send_packet.arp_.op_ = htons(ArpHdr::Request);
    send_packet.arp_.smac_ = Mac(iface->mac);
    send_packet.arp_.sip_ = htonl(iface->ip);
    send_packet.arp_.tmac_ = Mac::nullMac();
    send_packet.arp_.tip_ = htonl(gateway_ip);

    printf("ARP Request to find Mac Address for gateway IP %s \n", std::string(gateway_ip).c_str());
    
	time_t start_time = time(nullptr); // 시작 시간 기록

    int send_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&send_packet), sizeof(EthArpPacket));
    if (send_res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(handle));
    }
	struct pcap_pkthdr* header;
	const u_char* recive_packet;
	int receive_res;
	while ((receive_res = pcap_next_ex(handle, &header, &recive_packet)) >= 0) {
		if (receive_res == 0) {
			if (difftime(time(nullptr), start_time) > 5) { 
				// 패킷은 수신을 못하여 타임아웃을 발생했을 때 5초가 지난경우
				// 5초 경과 확인
				printf("Timeout after 5 seconds while waiting for ARP reply.\n");
				return Mac::nullMac(); // 타임아웃 시 빈 MAC 주소 반환
			}
			else
				continue; // 타임아웃 발생 시 루프 계속
		}
		EthArpPacket* arp_reply = (EthArpPacket*)recive_packet;
		if (arp_reply->eth_.type() == EthHdr::Arp && arp_reply->arp_.op() == ArpHdr::Reply && arp_reply->arp_.sip() == gateway_ip){
		
			printf("Success get gateway MAC : %s, gateway IP : %s\n", string(arp_reply->arp_.smac()).c_str(),string(arp_reply->arp_.sip()).c_str());
			return arp_reply->arp_.smac();// 응답 패킷에서 상대방의 MAC 주소 추출
		}

		if (difftime(time(nullptr), start_time) > 5) { 
			// 패킷은 수신하지만 5초 동안 쓸잘데기 없는 패킷만 받은 경우
			// 5초 경과 확인
			printf("Timeout after 5 seconds while waiting for ARP reply.\n");
			return Mac::nullMac(); // 타임아웃 시 빈 MAC 주소 반환
		}
	
	}
		printf("ailed to capture ARP reply and mac for gateway IP : \n");
		return Mac::nullMac(); // 실패 시 빈 MAC 주소 반환
}


void iface_monitor_loop_thread_func(pcap_t*handle) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (true) {
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue; // 타임아웃 발생 시 루프 계속
		else if (res == -1 || res == -2) {
			cerr << "Error occurred while capturing packets" << endl;
			break;
		}
		EthHdr* ethPacket = (EthHdr*)packet;
		if (ethPacket->type() == EthHdr::Ip4) {
			cout << "IP4 packet detected from interface. " << endl;
			// 이더넷 헤더 뒤에 IP 헤더가 붙어있음
			IpHdr* iphdr = (IpHdr*)(packet + sizeof(EthHdr));
						// 출력
			printf( "Src MAC: %s\n",string(ethPacket->smac()).c_str());
			printf( "Dst MAC: %s\n",string(ethPacket->dmac()).c_str());
			printf("Src IP: %s\n", string(iphdr->sip()).c_str() );
			printf("Dst IP: %s\n", string(iphdr->dip()).c_str() );

		}
	}
}



void monitor_iface_and_send_to_other_iface_loop_thread_func( pcap_t*receive_handle, pcap_t*send_handle, IFACE * receive_iface, IFACE * send_iface,IFACE * receive_network_gateway, IFACE * send_network_gateway) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (true) {
		int res = pcap_next_ex(receive_handle, &header, &packet);
		if (res == 0)
			continue; // 타임아웃 발생 시 루프 계속
		else if (res == -1 || res == -2) {
			printf("Error occurred while capturing packets\n");
			break;
		}
		
		EthHdr* ethPacket = (EthHdr*)packet;
		IpHdr* iphdr = (IpHdr*)(packet + sizeof(EthHdr));
		if (ethPacket->smac() == receive_network_gateway->mac&&ethPacket->type() ==EthHdr::Ip4&&iphdr->dip()!=receive_iface->ip){

			ethPacket->smac_ = send_iface->mac;
			ethPacket->dmac_ = send_network_gateway->mac;			
				
			std::lock_guard<std::mutex> lock(send_lock);
			int res = pcap_sendpacket(send_handle, packet, header->len);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s header->len=%d \n", res, pcap_geterr(send_handle),header->len);
			}
		}
	}
}


void monitor_arp_and_send_arp_loop_thread_func( pcap_t*receive_handle, IFACE * receive_iface,IFACE * receive_network_gateway,pcap_t*private_handle, IFACE * private_iface,IFACE * private_network_gateway) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (true) {
		int res = pcap_next_ex(receive_handle, &header, &packet);
		if (res == 0)
			continue; // 타임아웃 발생 시 루프 계속
		else if (res == -1 || res == -2) {
			printf("Error occurred while capturing packets\n");
			break;
		}
	
		EthArpPacket* ethArpPacket = (EthArpPacket*)packet;

		if(ethArpPacket->eth_.type() == EthHdr::Arp && ethArpPacket->arp_.op() == ArpHdr::Request){
				printf("ARP request detected from gateway. Reapplying ARP response...\n");
				//센더에게 타겟맥이 내 맥이라고 속이기.
				EthArpPacket response_packet;
				response_packet.eth_.dmac_ = receive_network_gateway->mac;
				response_packet.eth_.smac_ = receive_iface->mac;
				response_packet.eth_.type_ = htons(EthHdr::Arp);
				response_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
				response_packet.arp_.pro_ = htons(EthHdr::Ip4);
				response_packet.arp_.hln_ = Mac::SIZE;
				response_packet.arp_.pln_ = Ip::SIZE;
				response_packet.arp_.op_ = htons(ArpHdr::Reply);
				response_packet.arp_.smac_ = receive_iface->mac;
				response_packet.arp_.sip_ = htonl(private_network_gateway->ip);
				response_packet.arp_.tmac_ = receive_network_gateway->mac;
				response_packet.arp_.tip_ = htonl(receive_network_gateway->ip);
				std::lock_guard<std::mutex> lock(send_lock);
				int res = pcap_sendpacket(receive_handle, reinterpret_cast<const u_char*>(&response_packet), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s header->len=%d \n", res, pcap_geterr(receive_handle),header->len);
					exit(-1);
				}

		}
		else{
			EthHdr* ethPacket = (EthHdr*)packet;
			IpHdr* iphdr = (IpHdr*)(packet + sizeof(EthHdr));
			if (ethPacket->smac() == receive_network_gateway->mac&&ethPacket->type() ==EthHdr::Ip4&&iphdr->dip()!=receive_iface->ip){

				ethPacket->smac_ = private_iface->mac;
				ethPacket->dmac_ = private_network_gateway->mac;
				std::lock_guard<std::mutex> lock(send_lock);		
				int res = pcap_sendpacket(private_handle, packet, header->len);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s header->len=%d \n", res, pcap_geterr(private_handle),header->len);
				}
			}
		}
		


	}
}


int main() {

	printf("Enter name of public network interface : ");
	char buf[100];
	char public_iface_name[100];
	int ch;
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		printf("Input error\n");
		return -1;
	}
	if (strchr(buf, '\n') != NULL){
		buf[strcspn(buf, "\n")] = '\0';
	}
	else{
		while ((ch = getchar()) != '\n' && ch != EOF);
	}
	if(sscanf(buf,"%99s", public_iface_name)!=1){
		printf("Invalid number\n");
		return -1;
	}

	printf("Enter name of private network interface : ");
	char private_iface_name[100];
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		printf("Input error\n");
		return -1;
	}
	if (strchr(buf, '\n') != NULL){
		buf[strcspn(buf, "\n")] = '\0';
	}
	else{
		while ((ch = getchar()) != '\n' && ch != EOF);
	}
	if(sscanf(buf,"%99s", private_iface_name)!=1){
		printf("Invalid number\n");
		return -1;
	}


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* public_iface_handle = pcap_open_live(public_iface_name, BUFSIZ, 1, 1, errbuf); // 타임아웃을 1000ms로 설정
	if (public_iface_handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", public_iface_name, errbuf);
		return -1;
	}
	pcap_t* private_iface_handle = pcap_open_live(private_iface_name, BUFSIZ, 1, 1, errbuf); // 타임아웃을 1000ms로 설정
	if (private_iface_handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", private_iface_name, errbuf);
		return -1;
	}

	IFACE * public_iface = get_iface_IP_and_MAC(public_iface_name);
    if (!public_iface) {
        fprintf(stderr, "Failed to get public interface's IP and MAC address\n");
        return -1;
    }

	IFACE * private_iface = get_iface_IP_and_MAC(private_iface_name);
    if (!private_iface) {
        fprintf(stderr, "Failed to get private interface's IP and MAC address\n");
        return -1;
    }


	printf("Enter ip of public network gateway : ");
	char public_network_gateway_ip[100];
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		printf("Input error\n");
		return -1;
	}
	if (strchr(buf, '\n') != NULL){
		buf[strcspn(buf, "\n")] = '\0';
	}
	else{
		while ((ch = getchar()) != '\n' && ch != EOF);
	}
	if(sscanf(buf,"%99s", public_network_gateway_ip)!=1){
		printf("Invalid number\n");
		return -1;
	}

	printf("Enter ip of private network gateway : ");
	char private_network_gateway_ip[100];
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		printf("Input error\n");
		return -1;
	}
	if (strchr(buf, '\n') != NULL){
		buf[strcspn(buf, "\n")] = '\0';
	}
	else{
		while ((ch = getchar()) != '\n' && ch != EOF);
	}
	if(sscanf(buf,"%99s", private_network_gateway_ip)!=1){
		printf("Invalid number\n");
		return -1;
	}


	IFACE public_network_gateway = {Ip(public_network_gateway_ip),get_gateway_mac_using_ARP_request(public_iface,Ip(public_network_gateway_ip),public_iface_handle)};
	IFACE private_network_gateway = {Ip(private_network_gateway_ip),get_gateway_mac_using_ARP_request(private_iface,Ip(private_network_gateway_ip),private_iface_handle)};
	
	thread monitor_iface_and_send_to_other_iface_loop_thread(monitor_iface_and_send_to_other_iface_loop_thread_func, private_iface_handle,public_iface_handle,private_iface,public_iface,&private_network_gateway,&public_network_gateway);
	thread monitor_arp_and_send_arp_loop_thread(monitor_arp_and_send_arp_loop_thread_func,public_iface_handle,public_iface,&public_network_gateway,private_iface_handle,private_iface,&private_network_gateway);
	
	monitor_iface_and_send_to_other_iface_loop_thread.join();
	monitor_arp_and_send_arp_loop_thread.join();



	pcap_close(public_iface_handle);

	pcap_close(private_iface_handle);
}
