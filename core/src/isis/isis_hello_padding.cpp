// Pure padding policy depends only on the source-bound mode and the circuit's
// copied local state. Encoding, MTU selection and scheduling remain upstream.
#include "router/isis_hello_padding.hpp"
namespace router::isis {
std::optional<HelloPadding> parse_hello_padding(std::string_view text) noexcept {
  for (const auto mode : {HelloPadding::adaptive,HelloPadding::loose,HelloPadding::strict,HelloPadding::none})
    if (format_hello_padding(mode)==text) return mode;
  return std::nullopt;
}
std::string_view format_hello_padding(HelloPadding mode) noexcept {
  switch (mode) {
  case HelloPadding::adaptive: return "adaptive";
  case HelloPadding::loose: return "loose";
  case HelloPadding::strict: return "strict";
  case HelloPadding::none: return "none";
  }
  return {};
}
std::optional<bool> p2p_hello_padding(HelloPadding mode,ThreeWayState state,bool legacy) noexcept {
  if (state!=ThreeWayState::down && state!=ThreeWayState::initializing && state!=ThreeWayState::up)
    return std::nullopt;
  switch (mode) {
  case HelloPadding::none: return false;
  case HelloPadding::strict: return true;
  case HelloPadding::adaptive: return legacy || state!=ThreeWayState::up;
  case HelloPadding::loose: return legacy ? std::nullopt : std::optional{state==ThreeWayState::down};
  }
  return std::nullopt;
}
std::optional<bool> lan_hello_padding(HelloPadding mode,bool any_up) noexcept {
  switch (mode) {
  case HelloPadding::none: return false;
  case HelloPadding::strict: return true;
  case HelloPadding::adaptive: case HelloPadding::loose: return !any_up;
  }
  return std::nullopt;
}
}
