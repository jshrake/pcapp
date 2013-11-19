#include "gtest/gtest.h"
#include <pcap_cpp/pcap.hpp>
namespace {
  pcap_t *get_default_device() {
    auto device_name = libpcap::find_default_device_name();
    return libpcap::create(device_name);
  }
}

namespace pcap_tests {

TEST(pcap_tests, get_default) {
  auto device_name = libpcap::find_default_device_name();
  std::cout << "Default device found: " << device_name << "\n";
  EXPECT_FALSE(device_name.empty());
} 

TEST(pcap_tests, find_all_devices_test) {
  auto devices = libpcap::find_all_devices();
  std::cout << "All devices:\n";
  for (const auto &device : devices) {
    std::cout << device << "\n"; 
  }
  EXPECT_FALSE(devices.empty());  
}

TEST(pcap_tests, create_default_devie_and_activate_test) {
  auto device = get_default_device(); 
  EXPECT_TRUE(device);
  libpcap::activate(device);
}

TEST(pcap_tests, default_device_ip_and_netmask_test) {
  auto device_name = libpcap::find_default_device_name();
  auto ip_netmask = libpcap::get_device_ip_and_netmask(device_name);
  std::cout << "device ip: " << libpcap::qtos(std::get<0>(ip_netmask)) << "\n";
  std::cout << "device netmask: " << libpcap::qtos(std::get<1>(ip_netmask)) << "\n";
  EXPECT_FALSE(ip_netmask == std::make_tuple(0, 0)); 
}

TEST(pcap_tests, default_device_time_stamp_types_test) {
  auto device = get_default_device();
  auto time_stamps = libpcap::get_time_stamp_types(device);
  std::cout << "Time stamp types for default device:\n";
  for (const auto &time_stamp : time_stamps) {
    std::cout << time_stamp << "\n";
  }
  EXPECT_TRUE(true);
}



} //namespace test_vector
