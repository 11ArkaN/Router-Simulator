// Control-owned IS-IS intent projection for the versioned browser snapshot.
// This serializer borrows detached values synchronously and owns no live state.
#pragma once
#include "router/isis_configuration.hpp"
#include <ostream>
namespace router::lab::isis_projection {
// Validated canonical intent only. The stream owns output storage; serialization
// may throw allocation or stream errors. No runtime or UI object is consulted.
void write_json(std::ostream &, const isis::RouterConfiguration &);
}
