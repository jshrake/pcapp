#include <pcap_cpp/device.hpp>
#include <pcap_cpp/pcap.hpp>
#include <thread>

namespace libpcap {

device::device(const std::string device_name)
    : device_name_{ device_name }, device_{ create(device_name) } {

    libpcap::set_promiscuous_mode(device_, false);
    libpcap::set_timeout(device_, std::chrono::seconds{10});
    libpcap::set_buffer_size(device_, BUFSIZ);
    }

device::device(pcap_if_t *pcap_device) : device{ pcap_device->name } {}

device::~device() {
  break_loop();
  pcap_close(device_); 
}

void device::set_promiscuous_mode(const bool flag) {
  libpcap::set_promiscuous_mode(device_, flag);
}

void device::set_monitor_mode(const bool flag) {
  libpcap::set_monitor_mode(device_, flag);
}

bool device::can_set_monitor_mode() {
  return libpcap::can_set_monitor_mode(device_);
}

void device::set_snapshot_length(const int snapshot_length) {
  libpcap::set_snapshot_length(device_, snapshot_length);
}

void device::set_timeout(const std::chrono::milliseconds time) {
  libpcap::set_timeout(device_, time);
}

void device::set_buffer_size(const int bytes) {
  libpcap::set_buffer_size(device_, bytes);
}

void device::set_time_stamp(const time_stamp &tstamp) {
  libpcap::set_time_stamp(device_, tstamp);
}

void device::set_capture_direction(const capture_direction &direction) {
  libpcap::set_capture_direction(device_, direction);
}

void device::set_filter(filter_program filter) {
  filter_ = filter;
  libpcap::set_filter(device_, filter_.get());
}

void device::loop(pcap_handler handler, const int count, unsigned char *user_arguments) {
  auto loop_thread = std::thread{[=]() -> void {
    libpcap::loop(device_, handler, count, user_arguments);
  }};
  loop_thread.detach();
}

void device::break_loop() {
  pcap_breakloop(device_);
}

std::vector<device::device> device::find_all_devices() {
  const auto all_devices = libpcap::find_all_devices();
  auto devices = std::vector<device>{};
  for (const auto &device : all_devices) {
    devices.emplace_back(device); 
  }
  return devices;
}

}
