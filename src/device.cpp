#include <pcap_cpp/device.hpp>
#include <pcap_cpp/pcap.hpp>
#include <thread>
#include <iostream>

namespace libpcap {

device::device(const std::string device_name)
    : device_name_{ device_name }, device_{ create(device_name) } {
}

device::device(pcap_t *pcap_device)
    : device_name_{"unknown"}, device_{pcap_device, &pcap_close} {
}

device::device(pcap_if_t *pcap_device) : device{ pcap_device->name } {}

device::~device() {
  if (loop_running_) {
    break_loop();
  }
}

void device::activate() {
  libpcap::activate(device_.get());
}

void device::set_promiscuous_mode(const bool flag) {
  libpcap::set_promiscuous_mode(device_.get(), flag);
}

void device::set_monitor_mode(const bool flag) {
  libpcap::set_monitor_mode(device_.get(), flag);
}

bool device::can_set_monitor_mode() {
  return libpcap::can_set_monitor_mode(device_.get());
}

void device::set_snapshot_length(const int snapshot_length) {
  libpcap::set_snapshot_length(device_.get(), snapshot_length);
}

void device::set_timeout(const std::chrono::milliseconds time) {
  libpcap::set_timeout(device_.get(), time);
}

void device::set_buffer_size(const int bytes) {
  libpcap::set_buffer_size(device_.get(), bytes);
}

void device::set_time_stamp(const time_stamp &tstamp) {
  libpcap::set_time_stamp(device_.get(), tstamp);
}

void device::set_capture_direction(const capture_direction &direction) {
  libpcap::set_capture_direction(device_.get(), direction);
}

void device::set_filter(const std::string expression, const bool optimize, const bpf_u_int32 netmask) { 
  filter_ = libpcap::compile_filter(device_.get(), expression.data(), optimize, netmask);
  libpcap::set_filter(device_.get(), filter_.get());
}

void device::loop(pcap_handler handler, const int count,
                  unsigned char *user_arguments, const bool block) {
  if (block) {
    libpcap::loop(device_.get(), handler, count, user_arguments);
  } else {
    auto loop_thread = std::thread{[ = ]()->void {
      libpcap::loop(device_.get(), handler, count, user_arguments);
    }};
    loop_thread.detach();
  }
  loop_running_ = true;
}

void device::break_loop() { pcap_breakloop(device_.get()); loop_running_ = false; }

std::vector<device> device::find_all_devices() {
  const auto all_devices = libpcap::find_all_devices();
  auto devices = std::vector<device>{};
  for (const auto &device : all_devices) {
    devices.emplace_back(device); 
  }
  return devices;
}

device device::get_default() {
  return device{libpcap::find_default_device_name()};
}

}
