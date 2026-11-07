// Existing P2P decision owners use the shared instance-local SPF translator.
// Mutable generations remain owned by SpfInput on the instance control shard.

#pragma once

#include "router/isis_spf_input.hpp"

namespace router::isis {
using P2pSpfInput = SpfInput;
} // namespace router::isis
