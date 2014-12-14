#include "gtest/gtest.h"
#include <pcapp/pcapp.hpp>

namespace device_tests {
using namespace pcapp;

TEST(device_tests, get_default) {
  auto dev = device::get_default();
  EXPECT_FALSE(dev.name().empty());
}

TEST(device_tests, find_all_devices_test) {
  auto devices = device::find_all_devices();
  for (const auto &device : devices) {
    EXPECT_FALSE(device.name().empty());
  }
}

TEST(device_tests, listen_to_http_port_on_all_devices_and_break_test) {
  auto devices = device::find_all_devices();
  auto callback = [](unsigned char *user, const pcap_pkthdr *header,
                     const unsigned char *) {
    const auto time_now = std::chrono::system_clock::now();
    std::cout << "device name: " << reinterpret_cast<device *>(user)->name()
              << "\n";
    std::cout << "time: " << std::chrono::system_clock::to_time_t(time_now)
              << "\n";
    std::cout << "header length: " << header->len << "\n";
    std::cout << "header cap:    " << header->caplen << "\n";
  };
  for (auto &device : devices) {
    device.set_promiscuous_mode(false);
    device.set_monitor_mode(false);
    device.set_timeout(std::chrono::seconds{1});
    device.activate();
    device.set_filter("tcp port 80", true);
    device.async_loop(callback, -1, reinterpret_cast<unsigned char *>(&device));
  }
  std::this_thread::sleep_for(std::chrono::seconds{1});
  for (auto &device : devices) {
    device.break_loop();
  }
}

}  // namespace device_tests
