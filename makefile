CXX = g++
CXXFLAGS = -I/usr/include/mysql -L/usr/lib/mysql -lpcap -lpthread -lmysqlclient -O2
TARGET = dpcs
OBJS = DistributePacketCapture.cpp
$(TARGET):$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(CFLAGS)
