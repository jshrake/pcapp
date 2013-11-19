#pragma once
#include <pcap/pcap.h>

#include <libpcap++/pcap_capture_direction_type.hpp>
#include <libpcap++/pcap_time_stamp_type.hpp>
#include <libpcap++/pcap_filter_program.hpp>
#include <libpcap++/pcap_device.hpp>

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace libpcap {
pcap_t *create(const std::string &device_name);
void activate(pcap_t &device, std::ostream &os = std::cerr);
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
void set_time_stamp_type(pcap_t *source, const time_stamp_type &tstamp,
                         std::ostream &os = std::cerr);
std::vector<time_stamp_type> get_time_stamp_types(pcap_t *source);
void set_capture_direction(pcap_t *source, const capture_direction &dir);
void loop(pcap_t *source, pcap_handler handler, const int count, unsigned char *user_args, std::ostream &os = std::cerr);
std::vector<pcap_if_t*> find_all_devices();
}
