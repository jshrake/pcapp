#include "gtest/gtest.h"
#include <pcap_cpp/pcap.hpp>
#include <pcap_cpp/utility.hpp>
#include <memory>

namespace pcap_tests {

TEST(pcap_tests, get_default) {
  auto device_name = libpcap::find_default_device_name();
  std::cout << "Default device found: " << device_name << "\n";
  EXPECT_FALSE(device_name.empty());
} 

TEST(pcap_tests, find_all_devices_test) {
  auto devices = libpcap::find_all_devices();
  EXPECT_FALSE(devices.empty());  
  std::cout << "All devices:\n";
  for (const auto &device : devices) {
    EXPECT_FALSE(device.empty());
    std::cout << device << "\n";
    auto pcap_device = libpcap::create(device);
    EXPECT_TRUE(pcap_device.get());
  }
}

TEST(pcap_tests, create_default_devie_and_activate_test) {
  auto device = libpcap::get_default_device(); 
  EXPECT_TRUE(device.get());
  libpcap::activate(device.get());
}

TEST(pcap_tests, default_device_ip_and_netmask_test) {
  auto device_name = libpcap::find_default_device_name();
  auto ip_netmask = libpcap::get_device_ip_and_netmask(device_name);
  std::cout << "device ip: " << libpcap::qtos(std::get<0>(ip_netmask)) << "\n";
  std::cout << "device netmask: " << libpcap::qtos(std::get<1>(ip_netmask)) << "\n";
  EXPECT_FALSE(ip_netmask == std::make_tuple(0, 0)); 
}

TEST(pcap_tests, default_device_time_stamp_types_test) {
  auto device = libpcap::get_default_device();
  auto time_stamps = libpcap::get_time_stamp_types(device.get());
  std::cout << "Time stamp types for default device:\n";
  for (const auto &time_stamp : time_stamps) {
    std::cout << time_stamp << "\n";
  }
  EXPECT_TRUE(true);
}

TEST(pcap_tests, default_device_set_stuff_then_activate_test) {
  auto device = libpcap::get_default_device();
  libpcap::set_promiscuous_mode(device.get(), false);
  libpcap::set_monitor_mode(device.get(), false);
  libpcap::set_timeout(device.get(), std::chrono::seconds{1});
  libpcap::activate(device.get());
  auto filter = libpcap::compile_filter(device.get(), "tcp port 80", true, PCAP_NETMASK_UNKNOWN);
  libpcap::set_filter(device.get(), filter.get());
}

TEST(pcap_tests, expect_already_activated_errors_test) {
  auto scoped_device = libpcap::get_default_device();
  auto device = scoped_device.get();
  libpcap::activate(device);
  ASSERT_THROW(libpcap::set_timeout(device, std::chrono::seconds{1}), libpcap::pcap_already_activated_error);
  ASSERT_THROW(libpcap::set_buffer_size(device, 1), libpcap::pcap_already_activated_error);
  ASSERT_THROW(libpcap::set_snapshot_length(device, 1), libpcap::pcap_already_activated_error);
  ASSERT_THROW(libpcap::set_promiscuous_mode(device, false), libpcap::pcap_already_activated_error);
  ASSERT_THROW(libpcap::set_monitor_mode(device, false), libpcap::pcap_already_activated_error);
}

} //namespace pcap_tests
