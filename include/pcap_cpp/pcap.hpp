#pragma once
#include <pcap/pcap.h>

#include <pcap_cpp/capture_direction.hpp>
#include <pcap_cpp/time_stamp.hpp>
#include <pcap_cpp/filter_program.hpp>
#include <pcap_cpp/device.hpp>

#include <chrono>
#include <iosfwd>
#include <string>
#include <vector>

namespace libpcap {

pcap_t *create(const std::string &device_name);
void activate(pcap_t &device);
std::string find_default_device_name();
std::tuple<bpf_u_int32, bpf_u_int32>
get_device_ip_and_netmask(const std::string &device_name);
bpf_program *compile_filter(pcap_t *source, const std::string &expression,
                            const bool optimize, const bpf_u_int32 netmask);
void set_filter(pcap_t *source, bpf_program *filter_program);
void set_snapshot_length(pcap_t *source, const int snapshot_length);
void set_promiscuous_mode(pcap_t *source, const bool flag);
void set_monitor_mode(pcap_t *source, const bool flag);
bool can_set_monitor_mode(pcap_t *source);
void set_timeout(pcap_t *source, const std::chrono::milliseconds &time);
void set_buffer_size(pcap_t *source, const int bytes);
void set_time_stamp(pcap_t *source, const time_stamp &tstamp);   
std::vector<time_stamp> get_time_stamp_types(pcap_t *source);
void set_capture_direction(pcap_t *source, const capture_direction &dir);
void loop(pcap_t *source, pcap_handler handler, const int count, unsigned char *user_args);
std::vector<std::string> find_all_devices();
void set_logger(std::ostream &os);
}
