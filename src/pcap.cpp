#include <pcap_cpp/pcap.hpp>
#include <pcap_cpp/error.hpp>
#include <iostream>

namespace {
  std::ostream *logger{&std::cerr};
}

namespace libpcap {

void set_logger(std::ostream &os) {
  logger = &os;
}

std::string find_default_device_name() {
  auto error_buffer = pcap_error_buffer{};
  auto device_name = std::string{ pcap_lookupdev(error_buffer.data()) };
  if (device_name.empty()) {
    throw pcap_error{ "Couldn't find default device\n" +
                      error_string(error_buffer) };
  }
  return device_name;
}

pcap_t *create(const std::string &device_name) {
  auto error_buffer = pcap_error_buffer{};
  auto device = pcap_create(device_name.data(), error_buffer.data());
  if (!device) {
    throw pcap_error{ "Couldn't create device " + device_name + "\n" +
                      error_string(error_buffer) };
  }
  return device;
}

void activate(pcap_t *device) {
  const auto result = pcap_activate(device);
  switch (result) {
  case 0:
    return;
  case PCAP_WARNING_PROMISC_NOTSUP:
    *logger << "Device doesn't support promiscuous mode\n" << warning_string(device);
    break;
  case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
    *logger << "Capture source doesn't support time stamp type\n"
       << warning_string(device);
    break;
  case PCAP_WARNING:
    *logger << "pcap_activate warning\n" << warning_string(device);
    break;
  case PCAP_ERROR_ACTIVATED:
    throw pcap_error{ "Capture source already activated\n" +
                      error_string(device) };
    break;
  case PCAP_ERROR_NO_SUCH_DEVICE:
    throw pcap_error{ "Capture source does not exist\n" +
                      error_string(device) };
    break;
  case PCAP_ERROR_PERM_DENIED:
    throw pcap_error{ "Insufficient permissions to open capture source\n" +
                      error_string(device) };
  case PCAP_ERROR_PROMISC_PERM_DENIED:
    throw pcap_error{
      "Insufficient permissions to open capture source in promiscuous mode\n" +
      error_string(device)
    };
  case PCAP_ERROR_RFMON_NOTSUP:
    throw pcap_error{ "Capture source does not support monitor mode\n" +
                      error_string(device) };
  case PCAP_ERROR_IFACE_NOT_UP:
    throw pcap_error{ "Capture source is not up\n" + error_string(device) };
  case PCAP_ERROR:
    throw pcap_error{ "pcap_activate error\n" + error_string(device) };
  default:
    throw pcap_error{ "pcap_activate unhandled error\n" +
                      error_string(device) };
  }
}

std::tuple<bpf_u_int32, bpf_u_int32>
get_device_ip_and_netmask(const std::string &device_name) {
  auto ip = bpf_u_int32{};
  auto netmask = bpf_u_int32{};
  auto error_buffer = pcap_error_buffer{};
  if (pcap_lookupnet(device_name.data(), &ip, &netmask, error_buffer.data()) ==
      -1) {
    throw pcap_error{ "Couldn't get netmask for device " + device_name + "\n" +
                      error_string(error_buffer) };
  }
  return { ip, netmask };
}

bpf_program *compile_filter(pcap_t *source, const std::string &expression,
                           const bool optimize, const bpf_u_int32 netmask) {
  bpf_program *filter_program = nullptr;
  if (pcap_compile(source, filter_program, expression.data(), optimize,
                   netmask) == -1 ||
      !filter_program) {
    throw pcap_error{ "Couldn't compile filter " + expression + "\n" +
                      error_string(source) };
  }
  return filter_program;
}

void set_filter(pcap_t *source, bpf_program *filter_program) {
  if (pcap_setfilter(source, filter_program) == -1) {
    throw pcap_error{ "Couldn't set filter\n" + error_string(source) };
  }
}

void set_snapshot_length(pcap_t *source, const int snapshot_length) {
  if (pcap_set_snaplen(source, snapshot_length) != 0) {
    throw pcap_already_activated_error{ source };
  }
}

void set_promiscuous_mode(pcap_t *source, const bool flag) {
  if (pcap_set_promisc(source, flag) != 0) {
    throw pcap_already_activated_error{ source };
  }
}

void set_monitor_mode(pcap_t *source, const bool flag) {
  if (pcap_set_rfmon(source, flag) != 0) {
    throw pcap_already_activated_error{ source };
  }
}

bool can_set_monitor_mode(pcap_t *source) {
  const auto result = pcap_can_set_rfmon(source);
  switch (result) {
  case 0:
    return false;
  case 1:
    return true;
  case PCAP_ERROR_NO_SUCH_DEVICE:
    throw pcap_error{ "Capture source does not exist\n" +
                      error_string(source) };
  case PCAP_ERROR_PERM_DENIED:
    throw pcap_error{ "Insufficient permissions to check whether monitor mode "
                      "could be supported\n" +
                      error_string(source) };
  case PCAP_ERROR_ACTIVATED:
    throw pcap_already_activated_error{ source };
  case PCAP_ERROR:
    throw pcap_error{ "pcap_can_set_rfmon error\n" + error_string(source) };
  default:
    throw pcap_error{ "pcap_can_set_rfmon unknown error\n" +
                      error_string(source) };
  }
}

void set_timeout(pcap_t *source, const std::chrono::milliseconds &time) {
  if (pcap_set_timeout(source, time.count()) != 0) {
    throw pcap_already_activated_error{ source };
  }
}

void set_buffer_size(pcap_t *source, const int bytes) {
  if (pcap_set_buffer_size(source, bytes) != 0) {
    throw pcap_already_activated_error{ source };
  }
}

void set_time_stamp(pcap_t *source, const time_stamp &tstamp) {
  const auto ts_type = static_cast<int>(tstamp);
  const auto result = pcap_set_tstamp_type(source, ts_type);
  switch (result) {
  case 0:
    return;
  case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
    *logger << "Time stamp type " << pcap_tstamp_type_val_to_name(ts_type)
       << " not supported by device\n" + warning_string(source);
    break;
  case PCAP_ERROR_ACTIVATED:
    throw pcap_already_activated_error{ source };
  case PCAP_ERROR_CANTSET_TSTAMP_TYPE:
    throw pcap_error{
      "Capture source doesn't support setting the time stamp type\n" +
      error_string(source)
    };
  default:
    throw pcap_error{ "pcap_set_tstampt_type unknown error\n" +
                      error_string(source) };
  }
}

std::vector<time_stamp> get_time_stamp_types(pcap_t *source) {
  int **time_stamp_types = nullptr;
  const auto num_time_stamp_types =
      pcap_list_tstamp_types(source, time_stamp_types);
  std::vector<time_stamp> time_stamps;
  for (auto k = 0; k < num_time_stamp_types; ++k) {
    time_stamps.push_back(static_cast<time_stamp>(*time_stamp_types[k]));
  }
  pcap_free_tstamp_types(*time_stamp_types);
  if (num_time_stamp_types == PCAP_ERROR) {
    throw pcap_error{ "pcap_list_tstamp_types error\n" + error_string(source) };
  }
  return time_stamps;
}

void set_capture_direction(pcap_t *source, const capture_direction &dir) {
  if (pcap_setdirection(source, static_cast<pcap_direction_t>(dir)) != 0) {
    throw pcap_error{ "pcap_setdirection error\n" + error_string(source) };
  }
}

void loop(pcap_t *source, pcap_handler handler, const int count, unsigned char *user_args) {
  const auto result = pcap_loop(source, count, handler, user_args);
  switch (result) {
    case 0:
      *logger << "pcap_loop finished successfully\n";
      break;
    case -1:
      throw pcap_error{"pcap_loop error\n" + error_string(source)};
    case -2:
      *logger << "pcap_loop stopped by call to pcap_breaklook\n";
      break;
    default:
      *logger << "pcap_loop unknown error\n" + error_string(source);
  }
}

std::vector<pcap_if_t*> find_all_devices() {
  pcap_if_t **all_devices = nullptr;
  auto error_buffer = pcap_error_buffer{};
  const auto result = pcap_findalldevs(all_devices, error_buffer.data());
  if (result != 0) {
    pcap_freealldevs(*all_devices);
    throw pcap_error{"pcap_findalldevs error\n" + error_string(error_buffer)};
  }
  std::vector<pcap_if_t*> devices;
  for (auto device = all_devices[0]; device != nullptr; device = device->next) {
    devices.emplace_back(device);
  }
  pcap_freealldevs(*all_devices);
  return devices;
}

}
