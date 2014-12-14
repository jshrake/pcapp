#pragma once
#include <pcap/pcap.h>
#include <array>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace pcapp {
/*
==============================================================================
typedefs and enums
==============================================================================
*/
using unique_pcap_t = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using unique_bpf_program =
    std::unique_ptr<bpf_program, decltype(&pcap_freecode)>;

enum class timestamp_t : int {
  host = PCAP_TSTAMP_HOST,
  host_lowprec = PCAP_TSTAMP_HOST_LOWPREC,
  host_highprec = PCAP_TSTAMP_HOST_HIPREC,
  adapter = PCAP_TSTAMP_ADAPTER,
  adapter_unsynced = PCAP_TSTAMP_ADAPTER_UNSYNCED
};
std::ostream &operator<<(std::ostream &os, const timestamp_t &tstamp);

enum class capture_direction : int {
  in = PCAP_D_IN,
  out = PCAP_D_OUT,
  inout = PCAP_D_INOUT
};

/*
==============================================================================
error handling
==============================================================================
*/
using error_buffer = std::array<char, PCAP_ERRBUF_SIZE>;
struct error : public std::runtime_error {
  error(const std::string &msg);
  error(pcap_t *source);
};

struct already_activated_error : public error {
  already_activated_error(pcap_t *source);
};

std::string error_string(const error_buffer &error_buffer);
std::string error_string(pcap_t *source);
std::string warning_string(pcap_t *source);

/*
==============================================================================
free-functions
==============================================================================
*/

/**
 * @return a string representing the default device name
 */
std::string find_default_device_name();
/**
 * @return a std::unique_ptr to the default device given by
 * find_default_device_name
 */
unique_pcap_t get_default_device();
/**
 * @param device_name the name of the device to create (en0, en1, lo0, etc.)
 * @return a std::unique_ptr to the device specified by device_name
 */
unique_pcap_t create(const std::string &device_name);
/**
 * @breif is used to activate a packet capture handle to look at packets on the
 * network, with the options that were set on the handle being in effect.
 * @param device a pointer to the pcap_t handler to activate
 */
int activate(pcap_t *device);
/**
 * @brief todo(jshrake) write documentations
 */
std::tuple<bpf_u_int32, bpf_u_int32> get_device_ip_and_netmask(
    const std::string &device_name);
/**
 * @brief todo(jshrake) write documentations
 */
unique_bpf_program compile_filter(pcap_t *source, const std::string &expression,
                                  const bool optimize,
                                  const bpf_u_int32 netmask);
/**
 * @brief todo(jshrake) write documentations
 */
void set_filter(pcap_t *source, bpf_program *filter_program);
/**
 * @brief todo(jshrake) write documentations
 */
void set_snapshot_length(pcap_t *source, const int snapshot_length);
/**
 * @brief todo(jshrake) write documentations
 */
void set_promiscuous_mode(pcap_t *source, const bool flag);
/**
 * @brief todo(jshrake) write documentations
 */
void set_monitor_mode(pcap_t *source, const bool flag);
/**
 * @brief todo(jshrake) write documentations
 */
bool can_set_monitor_mode(pcap_t *source);
/**
 * @brief todo(jshrake) write documentations
 */
void set_timeout(pcap_t *source, const std::chrono::milliseconds &time);
/**
 * @brief todo(jshrake) write documentations
 */
void set_buffer_size(pcap_t *source, const int bytes);

/**
 * @brief sets the time stamp type to be used by a capture device
 * @param source is the pcap handle
 * @param tstamp is the timestamp type desired
 * @return 0 on sucess, one of PCAP_WARNING_TSTAMP_TYPE_NOTSUP,
 *  PCAP_ERROR_ACTIVATED, PCAP_ERROR_CANTSET_TSTAMP_TYPE on error
 */
int set_timestamp_type(pcap_t *source, const timestamp_t &tstamp);

/**
 * @brief gets the available timestamp types for the given source
 * @param source is the pcap handle
 * @return a vector of all timestamp types supported by the source
 */
std::vector<timestamp_t> get_timestamp_types(pcap_t *source);

/**
 * @brief todo(jshrake) write documentations
 */
void set_capture_direction(pcap_t *source, const capture_direction &dir);

/**
 * @brief todo(jshrake) write documentations
 */
int loop(pcap_t *source, pcap_handler handler, const int count,
         unsigned char *user_args);
/**
 * @brief todo(jshrake) write documentations
 */
std::future<int> async_loop(pcap_t *source, pcap_handler handler,
                            const int count, unsigned char *user_args);
/**
 * @brief todo(jshrake) write documentations
 */
std::vector<std::string> find_all_devices();
/**
 * @brief todo(jshrake) write documentations
 */
std::string qtos(const bpf_u_int32 q);

/*
==============================================================================
device type
==============================================================================
*/

/**
 * @brief todo(jshrake) write documentations
 */
class device {
 public:
  /*
   * @brief equivalent to
   for(auto const & name : find_all_devices()) {v.push_back(device{name});}
   */
  static std::vector<device> find_all_devices();
  /*
   * @brief equiavlent to device(find_default_device_name());
   */
  static device get_default();
  /*
 * @brief constructor wraps pcap_open_dead()
 */
  static device open_live(char const *const device_name, int snapshot_length,
                          bool promiscuous_mode,
                          std::chrono::milliseconds const timeout);
  device(const std::string device_name);
  device(pcap_t *pcap_device);
  device(pcap_if_t *pcap_device);
  ~device();

  device() = delete;
  device(const device &) = delete;
  device(device &&) = default;
  device &operator=(const device &) = delete;
  device &operator=(device &&) = default;
  int activate();
  void set_promiscuous_mode(const bool flag);
  void set_monitor_mode(const bool flag);
  bool can_set_monitor_mode();
  void set_snapshot_length(const int snapshot_length);
  void set_timeout(const std::chrono::milliseconds time);
  void set_buffer_size(const int bytes);
  int set_timestamp_type(const timestamp_t &tstamp);
  void set_capture_direction(const capture_direction &direction);
  void set_filter(const std::string expression, const bool optimize,
                  const bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN);
  int loop(pcap_handler handler, const int count = -1,
           unsigned char *user_arguments = nullptr);
  std::future<int> async_loop(pcap_handler handler, const int count = -1,
                              unsigned char *user_args = nullptr);
  void break_loop();

  const std::string &name() const { return device_name_; }

  pcap_t *get() const { return device_.get(); }

 private:
  std::string const device_name_{"unknown"};
  unique_pcap_t device_{nullptr, &pcap_close};
  unique_bpf_program filter_{nullptr, &pcap_freecode};
  mutable bool loop_running_{false};
};

/*
==============================================================================
Implementations
==============================================================================
*/
inline std::ostream &operator<<(std::ostream &os, const timestamp_t &tstamp) {
  os << pcap_tstamp_type_val_to_name(static_cast<int>(tstamp));
  return os;
}

inline error::error(const std::string &msg) : std::runtime_error{msg} {}

inline error::error(pcap_t *source) : error{error_string(source)} {}

inline already_activated_error::already_activated_error(pcap_t *source)
    : error{"Capture source already activated\n" + error_string(source)} {}

inline std::string error_string(const error_buffer &error_buffer) {
  return "pcap error: " +
         std::string{error_buffer.cbegin(), error_buffer.cend()} + "\n";
}

inline std::string error_string(pcap_t *source) {
  return std::string{"pcap error: "} + pcap_geterr(source) + "\n";
}

inline std::string warning_string(pcap_t *source) {
  return std::string{"pcap warning: "} + pcap_geterr(source) + "\n";
}

inline std::string find_default_device_name() {
  auto buf = error_buffer{};
  auto device_name = std::string{pcap_lookupdev(buf.data())};
  if (device_name.empty()) {
    throw error{"Couldn't find default device\n" + error_string(buf)};
  }
  return device_name;
}

inline unique_pcap_t get_default_device() {
  return pcapp::create(find_default_device_name());
}

inline unique_pcap_t create(const std::string &device_name) {
  auto buf = error_buffer{};
  auto device = pcap_create(device_name.data(), buf.data());
  if (!device) {
    throw error{"Couldn't create device " + device_name + "\n" +
                error_string(buf)};
  }
  return unique_pcap_t{device, &pcap_close};
}

inline int activate(pcap_t *device) { return pcap_activate(device); }

inline std::tuple<bpf_u_int32, bpf_u_int32> get_device_ip_and_netmask(
    const std::string &device_name) {
  auto ip = bpf_u_int32{};
  auto netmask = bpf_u_int32{};
  auto buf = error_buffer{};
  if (pcap_lookupnet(device_name.data(), &ip, &netmask, buf.data()) == -1) {
    throw error{"Couldn't get netmask for device " + device_name + "\n" +
                error_string(buf)};
  }
  return {ip, netmask};
}

inline unique_bpf_program compile_filter(pcap_t *source,
                                         const std::string &expression,
                                         const bool optimize,
                                         const bpf_u_int32 netmask) {
  auto filter_program = unique_bpf_program{new bpf_program, &pcap_freecode};
  if (pcap_compile(source, filter_program.get(), expression.data(), optimize,
                   netmask) == -1 ||
      !filter_program) {
    throw error{"Couldn't compile filter " + expression + "\n" +
                error_string(source)};
  }
  return filter_program;
}

inline void set_filter(pcap_t *source, bpf_program *filter_program) {
  if (pcap_setfilter(source, filter_program) == -1) {
    throw error{"Couldn't set filter\n" + error_string(source)};
  }
}

inline void set_snapshot_length(pcap_t *source, const int snapshot_length) {
  if (pcap_set_snaplen(source, snapshot_length) != 0) {
    throw already_activated_error{source};
  }
}

inline void set_promiscuous_mode(pcap_t *source, const bool flag) {
  if (pcap_set_promisc(source, flag) != 0) {
    throw already_activated_error{source};
  }
}

inline void set_monitor_mode(pcap_t *source, const bool flag) {
  if (pcap_set_rfmon(source, flag) != 0) {
    throw already_activated_error{source};
  }
}

inline bool can_set_monitor_mode(pcap_t *source) {
  const auto result = pcap_can_set_rfmon(source);
  switch (result) {
    case 0:
      return false;
    case 1:
      return true;
    case PCAP_ERROR_NO_SUCH_DEVICE:
      throw error{"Capture source does not exist\n" + error_string(source)};
    case PCAP_ERROR_PERM_DENIED:
      throw error{
          "Insufficient permissions to check whether monitor mode "
          "could be supported\n" +
          error_string(source)};
    case PCAP_ERROR_ACTIVATED:
      throw already_activated_error{source};
    case PCAP_ERROR:
      throw error{"pcap_can_set_rfmon error\n" + error_string(source)};
    default:
      throw error{"pcap_can_set_rfmon unknown error\n" + error_string(source)};
  }
}

inline void set_timeout(pcap_t *source, const std::chrono::milliseconds &time) {
  if (pcap_set_timeout(source, time.count()) != 0) {
    throw already_activated_error{source};
  }
}

inline void set_buffer_size(pcap_t *source, const int bytes) {
  if (pcap_set_buffer_size(source, bytes) != 0) {
    throw already_activated_error{source};
  }
}

inline int set_timestamp_type(pcap_t *source, const timestamp_t &tstamp) {
  const auto ts_type = static_cast<int>(tstamp);
  return pcap_set_tstamp_type(source, ts_type);
}

inline std::vector<timestamp_t> get_timestamp_types(pcap_t *source) {
  int *timestamp_t_types = nullptr;
  const auto num_timestamp_t_types =
      pcap_list_tstamp_types(source, &timestamp_t_types);
  std::vector<timestamp_t> timestamp_ts;
  for (auto k = 0; k < num_timestamp_t_types; ++k) {
    timestamp_ts.push_back(static_cast<timestamp_t>(timestamp_t_types[k]));
  }
  pcap_free_tstamp_types(timestamp_t_types);
  if (num_timestamp_t_types == PCAP_ERROR) {
    throw error{"pcap_list_tstamp_types error\n" + error_string(source)};
  }
  return timestamp_ts;
}

inline void set_capture_direction(pcap_t *source,
                                  const capture_direction &dir) {
  if (pcap_setdirection(source, static_cast<pcap_direction_t>(dir)) != 0) {
    throw error{"pcap_setdirection error\n" + error_string(source)};
  }
}

inline int loop(pcap_t *source, pcap_handler handler, const int count,
                unsigned char *user_args) {
  return pcap_loop(source, count, handler, user_args);
}

inline std::future<int> async_loop(pcap_t *source, pcap_handler handler,
                                   const int count, unsigned char *user_args) {
  std::packaged_task<int(pcap_t *, pcap_handler, const int, unsigned char *)>
      task(loop);
  auto result = task.get_future();
  std::thread task_thread(std::move(task), source, handler, count, user_args);
  task_thread.detach();
  return result;
}

inline std::vector<std::string> find_all_devices() {
  pcap_if_t *all_devices = nullptr;
  auto buf = error_buffer{};
  const auto result = pcap_findalldevs(&all_devices, buf.data());
  if (result != 0) {
    pcap_freealldevs(all_devices);
    throw error{"pcap_findalldevs error\n" + error_string(buf)};
  }
  std::vector<std::string> devices;
  for (auto device = all_devices; device != nullptr; device = device->next) {
    devices.emplace_back(device->name);
  }
  pcap_freealldevs(all_devices);
  return devices;
}

inline std::string qtos(const bpf_u_int32 q) {
  const auto one = q & 0xff;
  const auto two = (q >> 8) & 0xff;
  const auto three = (q >> 16) & 0xff;
  const auto four = (q >> 24) & 0xff;
  return std::to_string(one) + "." + std::to_string(two) + "." +
         std::to_string(three) + "." + std::to_string(four);
}

inline device::device(const std::string device_name)
    : device_name_{device_name}, device_{create(device_name)} {}

inline device::device(pcap_t *pcap_device)
    : device_name_{"unknown"}, device_{pcap_device, &pcap_close} {}

inline device::device(pcap_if_t *pcap_device) : device{pcap_device->name} {}

inline device::~device() {
  if (loop_running_) {
    break_loop();
  }
}

inline int device::activate() { return pcapp::activate(device_.get()); }

inline void device::set_promiscuous_mode(const bool flag) {
  pcapp::set_promiscuous_mode(device_.get(), flag);
}

inline void device::set_monitor_mode(const bool flag) {
  pcapp::set_monitor_mode(device_.get(), flag);
}

inline bool device::can_set_monitor_mode() {
  return pcapp::can_set_monitor_mode(device_.get());
}

inline void device::set_snapshot_length(const int snapshot_length) {
  pcapp::set_snapshot_length(device_.get(), snapshot_length);
}

inline void device::set_timeout(const std::chrono::milliseconds time) {
  pcapp::set_timeout(device_.get(), time);
}

inline void device::set_buffer_size(const int bytes) {
  pcapp::set_buffer_size(device_.get(), bytes);
}

inline int device::set_timestamp_type(const timestamp_t &tstamp) {
  return pcapp::set_timestamp_type(device_.get(), tstamp);
}

inline void device::set_capture_direction(const capture_direction &direction) {
  pcapp::set_capture_direction(device_.get(), direction);
}

inline void device::set_filter(const std::string expression,
                               const bool optimize, const bpf_u_int32 netmask) {
  filter_ = pcapp::compile_filter(device_.get(), expression.data(), optimize,
                                  netmask);
  pcapp::set_filter(device_.get(), filter_.get());
}

inline int device::loop(pcap_handler handler, const int count,
                        unsigned char *user_arguments) {
  loop_running_ = true;
  return pcapp::loop(device_.get(), handler, count, user_arguments);
}

inline std::future<int> device::async_loop(pcap_handler handler,
                                           const int count,
                                           unsigned char *user_arguments) {
  loop_running_ = true;
  return pcapp::async_loop(device_.get(), handler, count, user_arguments);
}

inline void device::break_loop() {
  loop_running_ = false;
  pcap_breakloop(device_.get());
}

inline device device::open_live(char const *const device_name,
                                int snapshot_length, bool promiscuous_mode,
                                std::chrono::milliseconds const timeout) {
  device d{device_name};
  d.set_snapshot_length(snapshot_length);
  d.set_promiscuous_mode(promiscuous_mode);
  d.set_timeout(timeout);
  d.activate();
  return d;
}

inline std::vector<device> device::find_all_devices() {
  const auto all_devices = pcapp::find_all_devices();
  auto devices = std::vector<device>{};
  for (const auto &device : all_devices) {
    devices.emplace_back(device);
  }
  return devices;
}

inline device device::get_default() {
  return device{pcapp::find_default_device_name()};
}
}