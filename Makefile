LDLIBS = -lpcap

# 디렉토리 경로 설정
SRC_DIR = source
INC_DIR = header
OBJ_DIR = object

# 컴파일 옵션에 헤더 경로 포함
CXXFLAGS = -I$(INC_DIR) -std=c++17 -Wall

# 오브젝트 목록
OBJS = \
	$(OBJ_DIR)/main.o \
	$(OBJ_DIR)/arphdr.o \
	$(OBJ_DIR)/ethhdr.o \
	$(OBJ_DIR)/ip.o \
	$(OBJ_DIR)/mac.o \
	$(OBJ_DIR)/iphdr.o \
	$(OBJ_DIR)/tcphdr.o \
	$(OBJ_DIR)/udphdr.o \
	$(OBJ_DIR)/checksum.o

# 결과 바이너리는 현재 디렉토리에 생성
TARGET = inter-nic-relayer

all: $(OBJ_DIR) $(TARGET)


$(TARGET): $(OBJS)
	$(LINK.cc) $^ $(LDLIBS) -o $@


# obj 디렉토리 없으면 생성
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/main.o: $(INC_DIR)/mac.h $(INC_DIR)/ip.h $(INC_DIR)/ethhdr.h $(INC_DIR)/arphdr.h $(INC_DIR)/iphdr.h $(INC_DIR)/tcphdr.h $(INC_DIR)/udphdr.h $(INC_DIR)/checksum.h $(SRC_DIR)/main.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/main.cpp -o $@

$(OBJ_DIR)/arphdr.o: $(INC_DIR)/mac.h $(INC_DIR)/ip.h $(INC_DIR)/arphdr.h $(SRC_DIR)/arphdr.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/arphdr.cpp -o $@

$(OBJ_DIR)/iphdr.o: $(INC_DIR)/ip.h $(INC_DIR)/iphdr.h $(SRC_DIR)/iphdr.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/iphdr.cpp -o $@

$(OBJ_DIR)/tcphdr.o: $(INC_DIR)/tcphdr.h $(SRC_DIR)/tcphdr.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/tcphdr.cpp -o $@

$(OBJ_DIR)/udphdr.o: $(INC_DIR)/udphdr.h $(SRC_DIR)/udphdr.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/udphdr.cpp -o $@

$(OBJ_DIR)/ethhdr.o: $(INC_DIR)/mac.h $(INC_DIR)/ethhdr.h $(SRC_DIR)/ethhdr.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/ethhdr.cpp -o $@

$(OBJ_DIR)/ip.o: $(INC_DIR)/ip.h $(SRC_DIR)/ip.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/ip.cpp -o $@

$(OBJ_DIR)/mac.o: $(INC_DIR)/mac.h $(SRC_DIR)/mac.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/mac.cpp -o $@

$(OBJ_DIR)/checksum.o: $(INC_DIR)/iphdr.h $(INC_DIR)/ip.h $(INC_DIR)/tcphdr.h $(INC_DIR)/udphdr.h $(INC_DIR)/checksum.h $(SRC_DIR)/checksum.cpp
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/checksum.cpp -o $@


clean:
	rm -rf $(TARGET) $(OBJ_DIR)
