#pragma once
#include <pcap/pcap.h>
#include <pcap_cpp/pcap_types.hpp>
#include <chrono>
#include <string>
#include <vector>

namespace libpcap {
class device {
public: 
  static std::vector<device> find_all_devices();
  static device get_default();
  device(const std::string device_name); 
  device(pcap_t  *pcap_device);
  device(pcap_if_t *pcap_device);
  ~device();

  device() = delete;
  device(const device &) = delete;
  device(device &&) = default;
  device &operator=(const device &) = delete;
  device &operator=(device &&) = default;
  void activate();
  void set_promiscuous_mode(const bool flag);
  void set_monitor_mode(const bool flag);
  bool can_set_monitor_mode();
  void set_snapshot_length(const int snapshot_length);
  void set_timeout(const std::chrono::milliseconds time);
  void set_buffer_size(const int bytes); 
  void set_time_stamp(const time_stamp &tstamp);
  void set_capture_direction(const capture_direction &direction);
  void set_filter(const std::string expression, const bool optimize, const bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN);
  void loop(pcap_handler handler, const int count = -1, unsigned char *user_arguments = nullptr, const bool block = false);
  void break_loop();

  const std::string &name() const {
    return device_name_;
  }
  
  pcap_t *get() const {
    return device_.get();
  }

private:
  const std::string device_name_{"unknown"};
  unique_pcap_t device_{nullptr, &pcap_close};
  unique_bpf_program filter_{nullptr, &pcap_freecode};
  mutable bool loop_running_{false};
};
}
