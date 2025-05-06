#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <pcap.h>
#include <unistd.h>         
#include <thread>
#include <mutex>

#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "udphdr.h"
#include "checksum.h"

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>

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

#define INTERNET_IFACE_NAME_HARDCODE "wlo1"
#define ISOLATED_IFACE_NAME_HARDCODE "enx8cb0e9e8cf94"
#define INTERNET_GATEWAY_IP_HARDCODE "192.168.0.1"
#define ISOLATED_TARGET_IP_HARDCODE "10.10.10.111"
#define INTERNET_PAKE_IP_HARDCODE "192.168.0.111"

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
	disable_offload(ETHTOOL_STSO, "TSO");      
	disable_offload(ETHTOOL_STXCSUM, "TX Checksum");

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


void monitor_iface_and_send_to_other_iface_loop_thread_func( pcap_t*isolated_iface_handle,
	 pcap_t*internet_iface_handle,
	  IFACE * isolated_iface,
	  IFACE * internet_iface,
	  IFACE * isolated_network_target,
	  IFACE * internet_network_gateway,
	  Ip internet_network_fake_ip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (true) {
		int res = pcap_next_ex(isolated_iface_handle, &header, &packet);
		if (res == 0)
			continue; // 타임아웃 발생 시 루프 계속
		else if (res == -1 || res == -2) {
			printf("Error occurred while capturing packets\n");
			break;
		}
		// 캡처 부족 여부 체크
		if (header->caplen < header->len) {
			printf("[DEBUG] WARNNING 캡처된 길이가 부족합니다: caplen=%d, len=%d\n",
				   header->caplen, header->len);
		}

		
		EthHdr* ethPacket = (EthHdr*)packet;
		IpHdr* iphdr = (IpHdr*)(packet + sizeof(EthHdr));
		
		if (ethPacket->smac() == isolated_network_target->mac&&ethPacket->type() ==EthHdr::Ip4&&iphdr->sip()==isolated_network_target->ip){

			// 1. MAC 주소 수정
			ethPacket->smac_ = internet_iface->mac;
			ethPacket->dmac_ = internet_network_gateway->mac;

			// 2. IP 주소 수정 (src ip인 isolated_network_target_ip를 fake_ip로 변경)
			iphdr->sip_ = htonl(internet_network_fake_ip);                    // src IP
	
			// 3. IP 체크섬 재계산
			iphdr->sum = 0;
			iphdr->sum = CalcIpChecksum(iphdr);
			

			// 4. TCP or UDP 체크섬 재계산
			if (iphdr->p == IPPROTO_TCP) {
				// 헤더 길이 계산
				int ip_header_len = (iphdr->vhl & 0x0F) * 4;
				TcpHdr* tcph = (TcpHdr*)((uint8_t*)iphdr + ip_header_len);
				int tcp_header_len = tcph->dataOffset() * 4;
				int total_ip_len = ntohs(iphdr->len);
				int payload_len = total_ip_len - ip_header_len - tcp_header_len;
				const uint8_t* payload = (uint8_t*)tcph + tcp_header_len;

				// 실제 캡처된 packet에서 payload가 이만큼 있나 확인
				int offset = (uint8_t*)payload - packet;
				int max_payload_available = header->caplen - offset;
				if (payload_len > max_payload_available) {
					printf("[DEBUG] WARNNING TCP payload truncated: expected %d, available %d\n", payload_len, max_payload_available);
					payload_len = max_payload_available;
				}

				tcph->sum = 0;
				tcph->sum = CalcTcpChecksum(iphdr, tcph, payload, payload_len);
			}
			else if (iphdr->p == IPPROTO_UDP) {
				int ip_header_len = (iphdr->vhl & 0x0F) * 4;
				UdpHdr* udph = (UdpHdr*)((uint8_t*)iphdr + ip_header_len);
				int udp_len = ntohs(udph->len_);
				int payload_len = udp_len - sizeof(UdpHdr);
				const uint8_t* payload = (uint8_t*)udph + sizeof(UdpHdr);

				// 실제 캡처된 packet에서 payload가 이만큼 있나 확인
				int offset = (uint8_t*)payload - packet;
				int max_payload_available = header->caplen - offset;
				if (payload_len > max_payload_available) {
					printf("[DEBUG] WARNNING UDP payload truncated: expected %d, available %d\n", payload_len, max_payload_available);
					payload_len = max_payload_available;
				}
		
				udph->sum_ = 0;
				udph->sum_ = CalcUdpChecksum(iphdr, udph, payload, payload_len);
			}

				
			std::lock_guard<std::mutex> lock(send_lock);
			int res = pcap_sendpacket(internet_iface_handle, packet, header->len);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s header->len=%d \n", res, pcap_geterr(internet_iface_handle),header->len);
			}
		}
		
	}
}


void monitor_arp_and_send_arp_loop_thread_func( pcap_t*internet_iface_handle, 
	IFACE * internet_iface,
	IFACE * internet_network_gateway,
	pcap_t* isolated_iface_handle, 
	IFACE * isolated_iface,IFACE * isolated_network_target,Ip internet_network_fake_ip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (true) {
		int res = pcap_next_ex(internet_iface_handle, &header, &packet);
		if (res == 0)
			continue; // 타임아웃 발생 시 루프 계속
		else if (res == -1 || res == -2) {
			printf("Error occurred while capturing packets\n");
			break;
		}
		// 캡처 부족 여부 체크
		if (header->caplen < header->len) {
			printf("[DEBUG] WARNNING 캡처된 길이가 부족합니다: caplen=%d, len=%d\n",
				   header->caplen, header->len);
		}
	
		EthArpPacket* ethArpPacket = (EthArpPacket*)packet;

		if(ethArpPacket->eth_.type() == EthHdr::Arp && ethArpPacket->arp_.op() == ArpHdr::Request){
				printf("ARP request detected from gateway. Reapplying ARP response...\n");
				//센더에게 타겟맥이 내 맥이라고 속이기.
				EthArpPacket response_packet;
				response_packet.eth_.dmac_ = internet_network_gateway->mac;
				response_packet.eth_.smac_ = internet_iface->mac;
				response_packet.eth_.type_ = htons(EthHdr::Arp);
				response_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
				response_packet.arp_.pro_ = htons(EthHdr::Ip4);
				response_packet.arp_.hln_ = Mac::SIZE;
				response_packet.arp_.pln_ = Ip::SIZE;
				response_packet.arp_.op_ = htons(ArpHdr::Reply);
				response_packet.arp_.smac_ = internet_iface->mac;
				response_packet.arp_.sip_ = htonl(internet_network_fake_ip);
				response_packet.arp_.tmac_ = internet_network_gateway->mac;
				response_packet.arp_.tip_ = htonl(internet_network_gateway->ip);
				std::lock_guard<std::mutex> lock(send_lock);
				int res = pcap_sendpacket(internet_iface_handle, reinterpret_cast<const u_char*>(&response_packet), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s header->len=%d \n", res, pcap_geterr(internet_iface_handle),header->len);
					exit(-1);
				}

		}
		else{
			EthHdr* ethPacket = (EthHdr*)packet;
			IpHdr* iphdr = (IpHdr*)(packet + sizeof(EthHdr));
			if (ethPacket->smac() == internet_network_gateway->mac&&ethPacket->type() ==EthHdr::Ip4&&iphdr->dip()==internet_network_fake_ip){
				//1. mac 수정
				ethPacket->smac_ = isolated_iface->mac;
				ethPacket->dmac_ = isolated_network_target->mac;

				// 2. IP 주소 수정 (dest ip인 fake_ip를 isolated_network_target_ip로 변경)
				iphdr->dip_ = htonl(isolated_network_target->ip);// dest IP
		
				// 3. IP 체크섬 재계산
				iphdr->sum = 0;
				iphdr->sum = CalcIpChecksum(iphdr);
				// 4. TCP or UDP 체크섬 재계산
				if (iphdr->p == IPPROTO_TCP) {
					// 헤더 길이 계산
					int ip_header_len = (iphdr->vhl & 0x0F) * 4;
					TcpHdr* tcph = (TcpHdr*)((uint8_t*)iphdr + ip_header_len);
					int tcp_header_len = tcph->dataOffset() * 4;
					int total_ip_len = ntohs(iphdr->len);
					int payload_len = total_ip_len - ip_header_len - tcp_header_len;
					const uint8_t* payload = (uint8_t*)tcph + tcp_header_len;

					// 실제 캡처된 packet에서 payload가 이만큼 있나 확인
					int offset = (uint8_t*)payload - packet;
					int max_payload_available = header->caplen - offset;
					if (payload_len > max_payload_available) {
						printf("[DEBUG] WARNNING TCP payload truncated: expected %d, available %d\n", payload_len, max_payload_available);
						payload_len = max_payload_available;
					}

					tcph->sum = 0;
					tcph->sum = CalcTcpChecksum(iphdr, tcph, payload, payload_len);
				}
				else if (iphdr->p == IPPROTO_UDP) {
					int ip_header_len = (iphdr->vhl & 0x0F) * 4;
					UdpHdr* udph = (UdpHdr*)((uint8_t*)iphdr + ip_header_len);
					int udp_len = ntohs(udph->len_);
					int payload_len = udp_len - sizeof(UdpHdr);
					const uint8_t* payload = (uint8_t*)udph + sizeof(UdpHdr);

					// 실제 캡처된 packet에서 payload가 이만큼 있나 확인
					int offset = (uint8_t*)payload - packet;
					int max_payload_available = header->caplen - offset;
					if (payload_len > max_payload_available) {
						printf("[DEBUG] WARNNING UDP payload truncated: expected %d, available %d\n", payload_len, max_payload_available);
						payload_len = max_payload_available;
					}
			
					udph->sum_ = 0;
					udph->sum_ = CalcUdpChecksum(iphdr, udph, payload, payload_len);
				}
				std::lock_guard<std::mutex> lock(send_lock);		
				int res = pcap_sendpacket(isolated_iface_handle, packet, header->len);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s header->len=%d \n", res, pcap_geterr(isolated_iface_handle),header->len);
				}
			}
		}
		
		


	}
}


int main() {

	printf("Enter internet network interface name : ");
	char buf[100];
	char internet_iface_name[100];
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
	if(sscanf(buf,"%99s", internet_iface_name)!=1){
		printf("Invalid number\n");
		return -1;
	}

	printf("Enter isolated network interface name : ");
	char isolated_iface_name[100];
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
	if(sscanf(buf,"%99s", isolated_iface_name)!=1){
		printf("Invalid number\n");
		return -1;
	}


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* internet_iface_handle = pcap_open_live(internet_iface_name, BUFSIZ, 1, 1, errbuf); // 타임아웃을 1000ms로 설정
	if (internet_iface_handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", internet_iface_name, errbuf);
		return -1;
	}
	pcap_t* isolated_iface_handle = pcap_open_live(isolated_iface_name, BUFSIZ, 1, 1, errbuf); // 타임아웃을 1000ms로 설정
	if (isolated_iface_handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", isolated_iface_name, errbuf);
		return -1;
	}

	IFACE * internet_iface = get_iface_IP_and_MAC(internet_iface_name);
    if (!internet_iface) {
        fprintf(stderr, "Failed to get internet interface's IP and MAC address\n");
        return -1;
    }

	IFACE * isolated_iface = get_iface_IP_and_MAC(isolated_iface_name);
    if (!isolated_iface) {
        fprintf(stderr, "Failed to get isolated interface's IP and MAC address\n");
        return -1;
    }


	

	printf("Enter internet network gateway ip : ");
	char internet_network_gateway_ip[100];
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
	if(sscanf(buf,"%99s", internet_network_gateway_ip)!=1){
		printf("Invalid number\n");
		return -1;
	}


	printf("Enter isolated network target ip : ");
	char isolated_network_target_ip[100];
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
	if(sscanf(buf,"%99s", isolated_network_target_ip)!=1){
		printf("Invalid number\n");
		return -1;
	}

	printf("Enter internet network fake ip (arp spoofing ip) : ");
	char internet_network_fake_ip[100];
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
	if(sscanf(buf,"%99s", internet_network_fake_ip)!=1){
		printf("Invalid number\n");
		return -1;
	}



	IFACE internet_network_gateway = {Ip(internet_network_gateway_ip),
		get_gateway_mac_using_ARP_request(internet_iface,Ip(internet_network_gateway_ip),internet_iface_handle)};
	IFACE isolated_network_target = {Ip(isolated_network_target_ip),
		get_gateway_mac_using_ARP_request(isolated_iface,Ip(isolated_network_target_ip),isolated_iface_handle)};
	
	thread monitor_iface_and_send_to_other_iface_loop_thread(monitor_iface_and_send_to_other_iface_loop_thread_func,
		 isolated_iface_handle,
		 internet_iface_handle,
		 isolated_iface,internet_iface,
		 &isolated_network_target,
		 &internet_network_gateway,
		 Ip(internet_network_fake_ip));
		 
	thread monitor_arp_and_send_arp_loop_thread(monitor_arp_and_send_arp_loop_thread_func,
		internet_iface_handle,internet_iface,
		&internet_network_gateway,isolated_iface_handle,
		isolated_iface,
		&isolated_network_target,
		Ip(internet_network_fake_ip));
	
	monitor_iface_and_send_to_other_iface_loop_thread.join();
	monitor_arp_and_send_arp_loop_thread.join();

	pcap_close(internet_iface_handle);
	pcap_close(isolated_iface_handle);
}