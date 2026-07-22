// DNSSEC augmentation for an authoritative answer selected by dns::Zone. The
// zone remains the owner of immutable signed records. This module adds borrowed
// RRSIG, DS and NSEC views only when the request carries DO.

#pragma once

#include "router/dns_authoritative.hpp"
#include "router/dnssec_validation.hpp"

namespace router::dnssec {

// Returns false if a signed-zone record is malformed or allocation fails. The
// caller must then fail the request instead of serving an unverifiable partial
// DNSSEC response.
[[nodiscard]] bool augment_authoritative_answer(
    const dns::Zone &zone, const packet::dns::Question &question,
    dns::AuthoritativeAnswer &answer,
    const DigestCalculator *digests = nullptr) noexcept;

} // namespace router::dnssec
