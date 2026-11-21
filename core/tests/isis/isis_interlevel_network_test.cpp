// Three routers exchange only encoded Hellos, LSPs, SNPs and data over two
// physical links. A bridges L1 to L2; copied real-FIB selection drives its L2
// exports. The fixture owns local port/intent projections and observes routes,
// traffic, carrier withdrawal and quiescent restoration in both shard layouts.
#include "router/network_plane.hpp"
#include "router/isis_instance_program.hpp"
#include "router/isis_runtime_checkpoint.hpp"
#include <algorithm>
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value,std::source_location at=std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS interlevel network invariant at "+std::to_string(at.line()));
}
packet::Ipv4 bytes(std::uint32_t address) {
  return {static_cast<std::uint8_t>(address>>24U),static_cast<std::uint8_t>(address>>16U),
      static_cast<std::uint8_t>(address>>8U),static_cast<std::uint8_t>(address)};
}
std::unique_ptr<lab::RouterForwarderCheckpoint> view(lab::NetworkPlane &plane,lab::DeviceHandle device) {
  using Image=std::optional<lab::RouterForwarderCheckpoint>;
  auto image=std::unique_ptr<Image>{new Image(plane.router_checkpoint(device))};
  return *image ? std::make_unique<lab::RouterForwarderCheckpoint>(std::move(**image)) : nullptr;
}
}
void isis_interlevel_network_tests() {
  for (const auto cpus : {1U,8U}) {
    auto plane=std::make_unique<lab::NetworkPlane>(cpus);
    const std::array devices{lab::DeviceHandle{0U,1U},lab::DeviceHandle{1U,1U},lab::DeviceHandle{2U,1U}};
    std::array<std::vector<lab::IsisCircuitProgram>,3U> circuits;
    std::array<std::vector<lab::ForwardPort>,3U> physical_ports;
    std::array<std::unique_ptr<lab::routing::FibProgram>,3U> base4;
    std::array<std::unique_ptr<lab::routing::Ipv6FibProgram>,3U> base6;
    std::array<UpdateInstanceProgram,3U> programs;
    const std::array<std::uint8_t,2U> protocols{packet::isis::ipv4_nlpid,packet::isis::ipv6_nlpid};
    const UpdateLevelConfiguration level{{32U,32768U},32U,128U,1492U,1200U,60s,60s,
        false,false,false,PurgeRules::iso_10589};
    for (std::size_t device{}; device<devices.size(); ++device) {
      crypto::Sha256Digest secret{}; secret.fill(static_cast<std::uint8_t>(device+1U));
      require(plane->add_router(devices[device],secret));
      InstanceIntent intent; intent.admin_enabled=true;
      intent.system_id=packet::isis::SystemId{1U,2U,3U,4U,5U,static_cast<std::uint8_t>(device+1U)};
      intent.levels=device==0U ? ConfiguredLevels::both : device==1U ? ConfiguredLevels::level1 : ConfiguredLevels::level2;
      intent.areas.push_back(*parse_configured_area(device==2U ? "49.0002" : "49.0001"));
      intent.ipv6_routing=ConfiguredIpv6Routing::native;
      intent.spf_wait={100U,100U,100U};
      const std::size_t ports=device==0U ? 2U : 1U;
      intent.interfaces.reserve(ports); circuits[device].reserve(ports);
      base4[device]=std::make_unique<lab::routing::FibProgram>();
      base6[device]=std::make_unique<lab::routing::Ipv6FibProgram>();
      base4[device]->generation=base6[device]->generation=1U;
      base4[device]->count=base6[device]->count=static_cast<std::uint16_t>(ports);
      std::vector<InstanceOriginInterface> bindings;
      std::vector<packet::Ipv4> addresses4;
      std::vector<packet::Ipv6> addresses6;
      std::array<std::vector<RootPrefix>,2U> prefixes;
      LocalPrefixCatalogProgram local;
      for (std::size_t port{}; port<ports; ++port) {
        const auto ordinal=static_cast<std::uint16_t>(port);
        const auto id=lab::physical_interface_id(ordinal);
        const bool l2=device==2U || (device==0U && port==1U);
        const auto selected_level=l2 ? 1U : 0U;
        lab::ForwardPort physical;
        physical.configured=physical.operational=true; physical.ordinal=ordinal;
        physical.mtu=1514U; physical.speed_mbps=1000U; physical.prefix_length=24U;
        physical.mac={2U,0U,0U,0U,static_cast<std::uint8_t>(device+1U),static_cast<std::uint8_t>(port+1U)};
        physical.address=device==1U ? 0xc6336402U : device==2U ? 0xcb007102U : port ? 0xcb007101U : 0xc6336401U;
        physical.network=physical.address&0xffffff00U;
        physical.ipv6_configured=true; physical.ipv6_prefix_length=64U;
        physical.ipv6_address=*ip::parse_ipv6(l2 ? (device==2U ? "2001:db8:23::2" : "2001:db8:23::1") :
            (device==1U ? "2001:db8:12::2" : "2001:db8:12::1"));
        physical.ipv6_network=*ip::parse_ipv6(l2 ? "2001:db8:23::" : "2001:db8:12::");
        physical.ipv6_link_local=*ip::parse_ipv6(device==1U ? "fe80::201" : device==2U ? "fe80::301" :
            port ? "fe80::102" : "fe80::101");
        require(plane->configure_port(devices[device],physical));
        physical_ports[device].push_back(physical);
        base4[device]->routes[port]={.network=physical.network,.port_ordinal=ordinal,.prefix_length=24U};
        base6[device]->routes[port]={.network=physical.ipv6_network,.interface_id=id,.physical_port_ordinal=ordinal,.prefix_length=64U};
        addresses4.push_back(bytes(physical.address)); addresses6.push_back(physical.ipv6_address);
        InterfaceIntent attached; attached.name="edge"+std::to_string(port);
        attached.type=ConfiguredInterfaceType::point_to_point;
        attached.levels=l2 ? ConfiguredLevels::level2 : ConfiguredLevels::level1;
        attached.level[0U].present=true; attached.level[0U].hello_interval_seconds=std::uint16_t{1U};
        attached.level[selected_level].present=true; attached.level[selected_level].metric=l2 ? 20U : 10U;
        intent.interfaces.push_back(attached);
        const std::array<packet::Ipv4,1U> hello4{bytes(physical.address)};
        const std::array<packet::Ipv6,1U> hello6{physical.ipv6_link_local};
        InterfaceProgramContext transport;
        transport.identity={devices[device],id,7U,ordinal,0U}; transport.interface_name=attached.name;
        transport.default_type=ConfiguredInterfaceType::broadcast; transport.mac=physical.mac;
        transport.destinations={{1U,0x80U,0xc2U,0U,0U,0x14U},
            {{{1U,0x80U,0xc2U,0U,0U,0x14U},{1U,0x80U,0xc2U,0U,0U,0x15U}}}};
        transport.extended_circuit=static_cast<std::uint32_t>(100U+device*4U+port);
        transport.local_circuit=static_cast<std::uint8_t>(port+1U); transport.maximum_areas=3U;
        transport.maximum_pdu_octets=1492U; transport.peer_attribute_octets=512U;
        transport.random=device*4U+port+1U; transport.operational=true;
        transport.protocols=protocols; transport.ipv4_addresses=hello4; transport.ipv6_addresses=hello6;
        const auto prepared=prepare_interface_program(intent,attached,transport);
        require(prepared.status==InterfaceProgramStatus::prepared && prepared.circuit);
        circuits[device].push_back({*prepared.circuit,{lab::node(devices[device]),ordinal,1U}});
        bindings.push_back({intent.interfaces.back().name,id,ConfiguredInterfaceType::broadcast,
            static_cast<std::uint8_t>(port+1U),8U,false});
        const auto four=*ip::parse_ip_prefix(device==1U ? "198.51.100.2/32" : device==2U ? "203.0.113.2/32" :
            port ? "203.0.113.1/32" : "198.51.100.1/32");
        const ip::IpPrefix six{ip::IpAddress{ip::AddressFamily::ipv6,physical.ipv6_address},128U};
        if (device==0U) {
          local.interfaces.push_back({id,ordinal,true});
          for (const auto &prefix : {RootPrefix{four,5U,{}},RootPrefix{six,7U,{}}}) {
            std::array<std::uint8_t,64U> storage{}; packet::isis::TlvWriter writer(storage);
            require(encode_root_prefix(writer,prefix));
            local.units.push_back({static_cast<std::uint8_t>(selected_level),prefix.prefix,{writer.bytes().begin(),writer.bytes().end()},{id}});
          }
        } else {
          prefixes[selected_level].push_back({four,5U,{}}); prefixes[selected_level].push_back({six,7U,{}});
        }
      }
      lab::RoutePolicyProgram policy;
      require(plane->program_route_policy(devices[device],policy) && plane->program_fib(devices[device],*base4[device]) &&
          plane->program_ipv6_fib(devices[device],*base6[device]));
      InstanceProgramContext owner;
      owner.maximum_areas=3U; owner.maximum_circuits=ports; owner.levels={level,level}; owner.fragments={1U,1U};
      owner.transmission={2U,5U,10U,100ms,10U,1492U,1U}; owner.minimum_generation_interval=10ms;
      owner.resource_retry=100ms; owner.random=device+1U; owner.interfaces=bindings;
      owner.ipv4_addresses=addresses4; owner.ipv6_addresses=addresses6; owner.prefixes={prefixes[0U],prefixes[1U]};
      if (device!=2U) owner.hierarchy_decision=P2pDecisionProgram{16U,32U,64U,{},{}};
      for (std::size_t family{}; family<2U; ++family) {
        owner.routing[family].emplace(); owner.routing[family]->calculation={16U,32U,64U,
            family ? packet::isis::ipv6_nlpid : packet::isis::ipv4_nlpid,PrefixCollectionBudget{8U,256U}};
        owner.routing[family]->preferences={P2pRouteFamilyProgram::Preference{15U,160U},P2pRouteFamilyProgram::Preference{18U,165U}};
      }
      auto prepared=prepare_instance_program(intent,owner);
      require(prepared.status==InstanceProgramStatus::prepared && prepared.program);
      programs[device]=std::move(*prepared.program);
      if (!local.units.empty()) { require(valid_local_prefix_catalog(local)); programs[device].origination->prefixes=std::move(local); }
    }
    const lab::NetworkLinkProgram first{{0U,1U},circuits[0U][0U].port,circuits[1U][0U].port,1'000'000'000U,100ns,true};
    const lab::NetworkLinkProgram second{{1U,1U},circuits[0U][1U].port,circuits[2U][0U].port,1'000'000'000U,100ns,true};
    require(plane->configure_link(first) && plane->configure_link(second));
    for (std::size_t device{}; device<devices.size(); ++device) {
      if (!device) {
        auto unsupported=programs[device];
        unsupported.origination->prefixes.reset();
        std::array<std::uint8_t,64U> storage{}; packet::isis::TlvWriter writer(storage);
        require(encode_root_prefix(writer,{*ip::parse_ip_prefix("192.0.2.99/32"),5U,{}}));
        auto &root=unsupported.origination->content.records.front();
        require(!root.level && !root.id[6U]);
        root.options.insert(root.options.end(),writer.bytes().begin(),writer.bytes().end());
        const std::array refused{NewUpdateInstance{0U,unsupported}};
        require(!plane->replace_isis_generation(devices[device],circuits[device],refused,{}, {},{}, {},{}, {},
            InterlevelTemplateBudget{16U,512U,device_catalog::maximum_dynamic_routes_per_router}));
      }
      auto initial=programs[device];
      if (!device) {
        initial.levels[1U].reset(); initial.origination->content.levels[1U].reset();
        initial.origination->automatic_area_attachment=false;
        std::erase_if(initial.origination->content.records,[](const auto &record) { return record.level==1U; });
        for (auto &record : initial.origination->content.records) record.flags=1U;
        for (auto &edge : *initial.origination->neighbors) edge.levels[1U].reset();
        std::erase_if(*initial.origination->neighbors,[](const auto &edge) { return !edge.levels[0U]; });
        std::erase_if(initial.origination->prefixes->units,[](const auto &unit) { return unit.level==1U; });
      }
      const std::array added{NewUpdateInstance{0U,initial}};
      const auto admitted=std::span<const lab::IsisCircuitProgram>{circuits[device]}.first(device ? circuits[device].size() : 1U);
      require(plane->replace_isis_generation(devices[device],admitted,added));
    }
    const auto legacy_ready_by=RuntimeClock::now()+12s;
    for (;;) {
      plane->pump(); const auto state=view(*plane,devices[0U]); require(state!=nullptr);
      if (std::any_of(state->fib.routes.begin(),state->fib.routes.begin()+state->fib.count,[](const auto &route) {
        return route.source==lab::routing::RouteSource::isis && route.network==0xc6336402U && route.prefix_length==32U;
      })) break;
      require(RuntimeClock::now()<legacy_ready_by);
    }
    const auto previous=plane->query_isis_update_instance(devices[0U],0U);
    require(previous && previous->route_published_generation);
    const InterlevelTemplateBudget exports{16U,512U,device_catalog::maximum_dynamic_routes_per_router};
    // An existing source cannot acquire an empty bank while retaining its old
    // owner. Failed cold admission preserves both routes and circuit epochs.
    require(!plane->replace_isis_generation(devices[0U],std::span<const lab::IsisCircuitProgram>{circuits[0U]}.first(1U),
        {},{}, {},{}, {},{}, {},exports));
    for (auto &circuit : circuits[0U]) ++circuit.circuit.identity.configuration_generation;
    const std::array replacement{NewUpdateInstance{0U,programs[0U],true,true}};
    const std::array<std::uint8_t,1U> retired{0U};
    require(!plane->replace_isis_generation(devices[0U],circuits[0U],replacement,retired,{}, {},{}, {},{},
        InterlevelTemplateBudget{0U,512U,device_catalog::maximum_dynamic_routes_per_router}));
    const auto preserved=view(*plane,devices[0U]); require(preserved!=nullptr);
    require(std::any_of(preserved->fib.routes.begin(),preserved->fib.routes.begin()+preserved->fib.count,[](const auto &route) {
      return route.source==lab::routing::RouteSource::isis && route.network==0xc6336402U && route.interface_generation==7U;
    }));
    require(plane->replace_isis_generation(devices[0U],circuits[0U],replacement,retired,{}, {},{}, {},{},exports));
    const auto migrated=plane->query_isis_update_instance(devices[0U],0U);
    require(migrated && migrated->route_installed_generation>previous->route_published_generation);
    auto stale=std::make_unique<routing::RouteGeneration>();
    stale->device=devices[0U]; stale->generation=previous->route_published_generation;
    require(plane->program_isis_routes(*stale)==routing::RouteInstallStatus::stale);
    require(plane->checkpoint().has_value());
    const auto converged=[&](bool present,const char *phase) {
      const auto end=RuntimeClock::now()+12s;
      for (;;) {
        plane->pump(); const auto state=view(*plane,devices[2U]); require(state!=nullptr);
        const auto four=[&](std::uint32_t address,std::uint32_t metric) {
          return std::any_of(state->fib.routes.begin(),state->fib.routes.begin()+state->fib.count,[&](const auto &row) {
            return row.source==lab::routing::RouteSource::isis && row.network==address && row.prefix_length==32U && (!present || row.metric==metric);
          });
        };
        const auto six=[&](const char *address,std::uint32_t metric) {
          const auto target=*ip::parse_ipv6(address);
          return std::any_of(state->ipv6_fib.routes.begin(),state->ipv6_fib.routes.begin()+state->ipv6_fib.count,[&](const auto &row) {
            return row.source==lab::routing::RouteSource::isis && row.network==target && row.prefix_length==128U && (!present || row.metric==metric);
          });
        };
        if (four(0xc6336402U,35U)==present && four(0xc6336401U,25U)==present &&
            six("2001:db8:12::2",37U)==present && six("2001:db8:12::1",27U)==present) break;
        if (RuntimeClock::now()>=end)
          throw std::runtime_error("IS-IS interlevel route timeout CPUs="+std::to_string(cpus)+" phase="+phase+
              " B4="+std::to_string(four(0xc6336402U,35U))+" A4="+std::to_string(four(0xc6336401U,25U))+
              " B6="+std::to_string(six("2001:db8:12::2",37U))+" A6="+std::to_string(six("2001:db8:12::1",27U)));
      }
    };
    converged(true,"initial");
    require(plane->query_isis_update_instance(devices[0U],0U)->local_export_status==InterlevelCompositionStatus::applied);
    const auto ping=[&](std::uint16_t sequence) {
      const auto ready_by=RuntimeClock::now()+6s;
      for (;;) {
        plane->pump(); bool ready=true;
        for (const auto device : devices) {
          const auto state=view(*plane,device); require(state!=nullptr);
          ready=ready && !state->ipv6_dad.empty() && std::all_of(state->ipv6_dad.begin(),state->ipv6_dad.end(),
              [](const auto &address) { return address.state==lab::Ipv6DadState::preferred; });
        }
        if (ready) break;
        require(RuntimeClock::now()<ready_by);
      }
      const auto end=RuntimeClock::now()+6s; bool sent4{},sent6{};
      while (!sent4 || !sent6 || !plane->router_ping_reply(devices[2U],sequence) || !plane->router_ipv6_ping_reply(devices[2U],sequence)) {
        plane->pump();
        if (!sent4) sent4=plane->start_router_ping(devices[2U],0xc6336402U,sequence,RuntimeClock::now());
        if (!sent6) sent6=plane->start_router_ipv6_ping(devices[2U],*ip::parse_ipv6("2001:db8:12::2"),sequence,RuntimeClock::now());
        if (RuntimeClock::now()>=end) {
          std::string detail="IS-IS interlevel forwarding timeout CPUs="+std::to_string(cpus)+
              " sequence="+std::to_string(sequence)+" sent4="+std::to_string(sent4)+" sent6="+std::to_string(sent6)+
              " reply4="+std::to_string(plane->router_ping_reply(devices[2U],sequence))+
              " reply6="+std::to_string(plane->router_ipv6_ping_reply(devices[2U],sequence));
          for (const auto device : devices) {
            const auto state=view(*plane,device); require(state!=nullptr);
            detail+=" device="+std::to_string(device.index)+" drop="+std::to_string(static_cast<unsigned>(state->last_drop));
            for (std::size_t i{};i<state->fib.count;++i) {
              const auto &route=state->fib.routes[i];
              detail+=" v4="+std::to_string(route.network)+"/"+std::to_string(route.prefix_length)+
                  ":"+std::to_string(route.metric)+":"+std::to_string(route.port_ordinal);
            }
            for (const auto &neighbor : state->ipv6_neighbors)
              detail+=" nd="+ip::format_ipv6(neighbor.address)+":"+std::to_string(static_cast<unsigned>(neighbor.state));
            for (std::size_t i{};i<state->ipv6_fib.count;++i) {
              const auto &route=state->ipv6_fib.routes[i];
              detail+=" v6="+ip::format_ipv6(route.network)+"/"+std::to_string(route.prefix_length)+
                  ":"+ip::format_ipv6(route.next_hop)+":"+std::to_string(route.physical_port_ordinal);
            }
          }
          throw std::runtime_error(detail);
        }
      }
    };
    ping(101U);
    auto down=first; down.carrier=false;
    require(plane->configure_link(down));
    for (const auto device : {0U,1U}) {
      auto port=physical_ports[device][0U]; port.operational=false;
      require(plane->configure_port(devices[device],port));
    }
    converged(false,"carrier down");
    require(plane->configure_link(first));
    for (const auto device : {0U,1U}) require(plane->configure_port(devices[device],physical_ports[device][0U]));
    converged(true,"carrier restored"); ping(102U);
    const auto checkpoint=plane->checkpoint();
    require(checkpoint.has_value());
    require(checkpoint->isis.has_value());
    require(checkpoint->isis->selection_producers.size()==1U);
    require(plane->restore(*checkpoint));
    for (std::size_t device{}; device<devices.size(); ++device) {
      lab::RoutePolicyProgram policy;
      require(plane->program_route_policy(devices[device],policy) && plane->program_fib(devices[device],*base4[device]) &&
          plane->program_ipv6_fib(devices[device],*base6[device]));
    }
    converged(true,"checkpoint restored"); ping(103U);
  }
}
