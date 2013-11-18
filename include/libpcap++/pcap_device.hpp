#pragma once
#include <pcap/pcap.h>

#include <libpcap++/pcap_capture_direction_type.hpp>
#include <libpcap++/pcap_filter_program.hpp>
#include <libpcap++/pcap_time_stamp_type.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace libpcap {
class device {
public: 
  static std::vector<device> find_all_devices();
  device(const std::string device_name); 
  device(pcap_if_t *device);
  ~device();

  device() = delete;
  device(const device &) = default;
  device(device &&) = default;
  device &operator=(const device &) = default;
  device &operator=(device &&) = default;

  void set_promiscuous_mode(const bool flag);
  void set_monitor_mode(const bool flag);
  bool can_set_monitor_mode();
  void set_snapshot_length(const int snapshot_length);
  void set_timeout(const std::chrono::milliseconds time);
  void set_buffer_size(const int bytes); 
  void set_time_stamp_type(const time_stamp_type &tstamp);
  void set_capture_direction(const capture_direction &direction);
  void set_filter(filter_program filter);
  void loop(pcap_handler handler, const int count = -1, unsigned char *user_arguments = nullptr);
  void break_loop();

  const std::string &name() const {
    return device_name_;
  }
  
  pcap_t *get() const {
    return device_;
  }

private:
  const std::string device_name_;
  pcap_t *device_;
  filter_program filter_;
};
}
