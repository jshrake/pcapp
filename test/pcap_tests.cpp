#include "gtest/gtest.h"
#include <pcap_cpp/pcap.hpp>
namespace pcap_tests {

TEST(pcap_tests, get_default) {
  auto device = libpcap::find_default_device_name();
  std::cout << "Default device found: " << device << "\n";
  EXPECT_FALSE(device.empty());
}

TEST(pcap_tests, find_all_devices_test) {
  auto devices = libpcap::find_all_devices();
  std::cout << "All devices:\n";
  for (const auto &device : devices) {
    std::cout << device << "\n"; 
  }
  EXPECT_FALSE(devices.empty());  
}


} //namespace test_vector
