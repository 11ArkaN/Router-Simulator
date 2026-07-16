#pragma once

// Generated protocol 3 operation identities. Payload fields use netstrings;
// packet bytes and mutable runtime addresses never cross this text boundary.

#include <string_view>

namespace router::lab_runtime_protocol {
inline constexpr unsigned version = 3;
inline constexpr std::string_view snapshot{"snapshot"};
inline constexpr std::string_view router_create{"router-create"};
inline constexpr std::string_view router_delete{"router-delete"};
inline constexpr std::string_view system_name_set{"system-name-set"};
inline constexpr std::string_view router_configuration_replace{"router-configuration-replace"};
inline constexpr std::string_view host_create{"host-create"};
inline constexpr std::string_view host_create_configured{"host-create-configured"};
inline constexpr std::string_view host_delete{"host-delete"};
inline constexpr std::string_view host_name_set{"host-name-set"};
inline constexpr std::string_view host_update{"host-update"};
inline constexpr std::string_view hardware_card_set{"hardware-card-set"};
inline constexpr std::string_view hardware_mda_set{"hardware-mda-set"};
inline constexpr std::string_view hardware_card_admin_set{"hardware-card-admin-set"};
inline constexpr std::string_view hardware_mda_admin_set{"hardware-mda-admin-set"};
inline constexpr std::string_view port_configure{"port-configure"};
inline constexpr std::string_view interface_configure{"interface-configure"};
inline constexpr std::string_view interface_delete{"interface-delete"};
inline constexpr std::string_view static_route_add{"static-route-add"};
inline constexpr std::string_view static_route_delete{"static-route-delete"};
inline constexpr std::string_view link_create{"link-create"};
inline constexpr std::string_view link_delete{"link-delete"};
inline constexpr std::string_view link_admin_set{"link-admin-set"};
inline constexpr std::string_view link_properties_set{"link-properties-set"};
inline constexpr std::string_view host_configure{"host-configure"};
inline constexpr std::string_view router_ping_start{"router-ping-start"};
inline constexpr std::string_view router_ping_status{"router-ping-status"};
inline constexpr std::string_view host_ping_start{"host-ping-start"};
inline constexpr std::string_view host_ping_status{"host-ping-status"};
inline constexpr std::string_view session_create{"session-create"};
inline constexpr std::string_view session_close{"session-close"};
inline constexpr std::string_view session_state{"session-state"};
inline constexpr std::string_view session_execute{"session-execute"};
inline constexpr std::string_view session_poll{"session-poll"};
inline constexpr std::string_view session_cancel{"session-cancel"};
inline constexpr std::string_view session_complete{"session-complete"};
inline constexpr std::string_view capture_point_set{"capture-point-set"};
inline constexpr std::string_view capture_selection_replace{"capture-selection-replace"};
} // namespace router::lab_runtime_protocol
