#pragma once

// Generated runtime management protocol. Browser and C++ consume names from
// the same versioned schema instead of duplicating command prefixes.

namespace router::runtime_protocol {
inline constexpr unsigned version = 1;
inline constexpr char snapshot[] = "snapshot";
inline constexpr char hardware_insert_card[] = "hardware:insert-card:";
inline constexpr char hardware_remove_card[] = "hardware:remove-card:";
inline constexpr char hardware_insert_mda[] = "hardware:insert-mda:";
inline constexpr char hardware_remove_mda[] = "hardware:remove-mda:";
inline constexpr char link_up[] = "link:up:";
inline constexpr char link_down[] = "link:down:";
inline constexpr char project_provisioning[] = "project:provisioning|";
inline constexpr char provisioning_absent[] = "absent";
inline constexpr char project_hosts[] = "project:hosts|";
inline constexpr char project_links[] = "project:links|";
inline constexpr char project_running[] = "project:running|";
inline constexpr char capture_prepare[] = "capture:prepare";
inline constexpr char capture_start[] = "capture:start";
inline constexpr char capture_stop[] = "capture:stop";
inline constexpr char checkpoint_prepare[] = "checkpoint:prepare";
inline constexpr char checkpoint_import[] = "checkpoint:import";
inline constexpr char terminal_complete[] = "terminal:complete:";
inline constexpr char terminal_execute[] = "terminal:";
inline constexpr char terminal_state[] = "terminal:state";
inline constexpr char host_ping[] = "host:ping:";
}  // namespace router::runtime_protocol
