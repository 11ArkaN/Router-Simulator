// Receiver-window tests cover fixed right edges, thresholded application reads,
// zero-window reopening, corrupt owner input and exact checkpoint restore.

#include "router/tcp_receive_window.hpp"

#include <stdexcept>

void tcp_receive_window_tests() {
  using namespace router::transport::tcp;

  ReceiveWindow window{10000U, 1460U};
  if (!window.valid() || window.advertised() != 10000U)
    throw std::runtime_error("TCP receive window rejected its arena");
  window.receive_next_advanced(2000U);
  if (window.advertised() != 8000U ||
      window.application_space_available(9000U) ||
      window.advertised() != 8000U ||
      !window.application_space_available(9460U) ||
      window.advertised() != 9460U)
    throw std::runtime_error("TCP receive SWS advertised a tiny increment");

  window.receive_next_advanced(9460U);
  if (window.advertised() != 0U ||
      window.application_space_available(1459U) ||
      !window.application_space_available(1460U) ||
      window.advertised() != 1460U)
    throw std::runtime_error("TCP receive SWS reopened zero window too early");

  const auto saved = window.checkpoint();
  ReceiveWindow restored{10000U, 1460U};
  if (!restored.restore(saved) || restored.advertised() != 1460U)
    throw std::runtime_error("TCP receive-window checkpoint changed its edge");
  auto invalid = saved;
  invalid.advertised = 10001U;
  if (restored.restore(invalid))
    throw std::runtime_error("TCP receive window restored beyond its arena");

  ReceiveWindow odd{9U, 100U};
  odd.receive_next_advanced(9U);
  if (odd.application_space_available(4U) ||
      !odd.application_space_available(5U))
    throw std::runtime_error("TCP receive SWS rounded half capacity down");
}
