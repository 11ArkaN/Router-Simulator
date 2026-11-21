// Two LAN owners exchange authenticated encoded Hellos through a physical
// queue and link. Each owner selects padding from its own accepted neighbors.
#include "router/isis_lan_circuit.hpp"
#include "router/multi_device_fabric.hpp"
#include <memory>
#include <stdexcept>
#include <source_location>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value,std::source_location location=std::source_location::current()) { if (!value) throw std::runtime_error("LAN Hello padding invariant at "+std::to_string(location.line())); }
void peer(void *,const LanPeerEvent &) noexcept {}
void designated(void *,const std::optional<DisSelection> &,const std::optional<DisSelection> &) noexcept {}
LanCircuitConfiguration configured(std::uint8_t id,HelloPadding mode) {
  LanCircuitConfiguration value;
  value.mac={2U,0U,0U,0U,0U,id};
  value.local={{1U,2U,3U,4U,5U,id},value.mac,64U,id};
  value.type=packet::isis::PduType::lan_hello_l1;
  value.levels=Levels::level1;
  value.hello_destination={1U,0x80U,0xc2U,0U,0U,0x14U};
  NeighborArea area; area.bytes[0]=0x49U;area.bytes[2]=1U;area.length=3U;
  value.areas={area};value.protocols={packet::isis::ipv4_nlpid};
  value.ipv4_addresses={{192U,0U,2U,id}};
  value.maximum_area_addresses=3U;
  value.holding_seconds=value.designated_holding_seconds=3U;
  value.hello_interval=value.designated_hello_interval=1s;
  value.maximum_pdu_octets=1492U;value.peer_attribute_octets=512U;
  value.limits={4U,3U};value.padding_mode=mode;
  value.receive_authentication=value.transmit_authentication=true;
  return value;
}
struct Exchange {
  std::array<LanCircuit *,2U> circuits;
  AuthenticationKey key;
  LanCircuit::Clock::time_point now;
  LanCircuitObserver observer{nullptr,peer,designated};
};
void delivered(void *opaque,const lab::MultiDeviceFabric::Delivery &delivery) {
  auto &exchange=*static_cast<Exchange *>(opaque);
  const auto index=delivery.destination.node.index;
  require(index<exchange.circuits.size());
  require(exchange.circuits[index]->receive(delivery.frame,exchange.key,exchange.now,exchange.observer)==LanCircuitReceive::accepted);
}
}
void isis_hello_padding_circuit_tests() {
  const auto start=LanCircuit::Clock::time_point{100s};
  const std::array<std::uint8_t,32U> secret{0x5aU,1U,2U,3U};
  const AuthenticationKey key{AuthenticationMethod::hmac_sha256,7U,secret};
  auto scratch=std::make_unique<PduScratch>();
  for (const auto mode : {HelloPadding::adaptive,HelloPadding::loose,HelloPadding::strict,HelloPadding::none}) {
    const auto first_configuration=configured(1U,mode);
    LanCircuit first(first_configuration,123U,start),second(configured(2U,HelloPadding::none),456U,start);
    Exchange exchange{{&first,&second},key,start};
    auto fabric=std::make_unique<lab::MultiDeviceFabric>();
    const lab::LinkHandle cable{0U,1U};
    require(fabric->configure(cable,{lab::node(lab::DeviceHandle{0U,1U}),0U,1U},
        {lab::node(lab::DeviceHandle{1U,1U}),0U,1U},1'000'000'000U,100ns,true));
    const auto round=[&](bool established) {
      for (std::uint8_t index{};index<2U;++index) {
        auto &circuit=*exchange.circuits[index];packet::Frame frame;
        require(circuit.hello(frame,key,*scratch,exchange.now,exchange.observer)==HelloBuildResult::encoded);
        packet::isis::EthernetDecodeError error;
        const auto decoded=packet::isis::parse_ethernet_pdu(frame.view(),error);
        const auto selected=index ? HelloPadding::none : mode;
        const bool padded=selected==HelloPadding::strict || (!established && selected!=HelloPadding::none);
        require(decoded && (padded ? decoded->pdu.bytes.size()==1492U : decoded->pdu.bytes.size()<1491U));
        const bool accepted=fabric->enqueue(cable,index,frame)==lab::MultiDeviceFabric::DropReason::none;
        require(accepted && circuit.complete_hello(accepted,exchange.now));
      }
      fabric->pump_transmit(exchange.now);exchange.now+=1ms;
      fabric->pump_delivery(&exchange,delivered,exchange.now);exchange.now+=1s;
    };
    round(false);round(false);round(true);
    require(first.neighbors().size()==1U && first.neighbors().at(0)->adjacency.state==LanState::up);
    const auto saved=first.checkpoint(exchange.now);
    require(LanCircuit::restore_checkpoint(saved,first_configuration,start+9000s)!=nullptr);
    auto mismatch=first_configuration;mismatch.padding_mode=mode==HelloPadding::none ? HelloPadding::strict : HelloPadding::none;
    require(!LanCircuit::restore_checkpoint(saved,mismatch,start+9000s));
    exchange.now+=3s;
    first.service(exchange.now,4U,exchange.observer);second.service(exchange.now,4U,exchange.observer);
    require(!first.neighbors().size() && !second.neighbors().size());
    round(false);
  }
}
