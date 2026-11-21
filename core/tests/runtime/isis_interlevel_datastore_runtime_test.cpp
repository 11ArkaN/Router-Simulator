// Public datastore commands build three independent routers and exercise live
// L1-to-L1/L2 replacement, shared CLI intent, encoded forwarding and recovery.
// The fixture owns only command inputs and copied checkpoints, never peer state.
#include "router/lab_runtime.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
#include "router/isis_configuration.hpp"
#include "router/isis_lsp_identity.hpp"
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <thread>
namespace {
using namespace router::lab;
namespace protocol=router::lab_runtime_protocol;
using namespace std::chrono_literals;
std::string message(std::string_view operation,std::initializer_list<std::string_view> fields={}) {
  std::string result;
  const auto append=[&](std::string_view value) { result+=std::to_string(value.size())+':'; result+=value; result+=','; };
  append(operation); for (const auto field : fields) append(field); return result;
}
void require(bool value,const char *reason) { if (!value) throw std::runtime_error(reason); }
}
void isis_interlevel_datastore_runtime_tests() {
  auto runtime=std::make_unique<LabRuntime>();
  const std::array<std::uint8_t,32U> key{0x61U};
  const std::array<std::uint8_t,4U> context{'l','1','l','2'};
  require(runtime->initialize_secret_vault(key,context),"Interlevel datastore vault failed");
  auto protector=router::vault::SecretVault::create(key,context,1U);
  require(protector.has_value(),"Interlevel checkpoint protector failed");
  const auto operation=[&](std::string_view name,std::initializer_list<std::string_view> fields) {
    const std::string output{runtime->command(message(name,fields))};
    if (output.starts_with("ERROR:")) throw std::runtime_error(std::string{name}+": "+output);
  };
  const auto terminal=[&](std::string_view session,std::string_view command) {
    const std::string output{runtime->command(message(protocol::session_execute,{session,command}))};
    if (output.find("ERROR:")!=std::string::npos || output.find("Error:")!=std::string::npos ||
        output.find("MINOR:")!=std::string::npos || output.find("MAJOR:")!=std::string::npos)
      throw std::runtime_error("Interlevel CLI "+std::string{session}+" "+std::string{command}+": "+output);
    return output;
  };
  const auto capture=[&] {
    const auto bytes=runtime->export_checkpoint();
    require(!bytes.empty(),"Interlevel public checkpoint export failed");
    auto image=checkpoint_v21::decode(bytes,&*protector);
    require(image && image->network.isis,"Interlevel public checkpoint decode failed"); return image;
  };
  for (const auto id : {"il-a","il-b","il-c"}) {
    operation(protocol::router_create,{id,"7750-sr-1",id});
    operation(protocol::port_configure,{id,"1/1/1","1","9212","100000",""});
    operation(protocol::session_create,{id,id,"operational"});
  }
  operation(protocol::port_configure,{"il-a","1/1/2","1","9212","100000",""});
  operation(protocol::interface_configure,{"il-a","left","1/1/1","10.0.12.1/30","","","1"});
  operation(protocol::interface_configure,{"il-a","right","1/1/2","10.0.13.1/30","","","1"});
  operation(protocol::interface_configure,{"il-b","left","1/1/1","10.0.12.2/30","","","1"});
  operation(protocol::interface_configure,{"il-c","right","1/1/1","10.0.13.2/30","","","1"});
  for (const auto &[id,address] : std::array{std::pair{"il-a","10.255.0.1/32"},
      std::pair{"il-b","10.255.0.2/32"},std::pair{"il-c","10.255.0.3/32"}})
    operation(protocol::interface_configure,{id,"system","",address,"","","1"});
  operation(protocol::link_create,{"il-left","il-a","1/1/1","il-b","1/1/1","100","1","0"});
  operation(protocol::link_create,{"il-right","il-a","1/1/2","il-c","1/1/1","100","1","0"});
  for (const auto &[id,suffix] : std::array{std::pair{"il-a","1"},std::pair{"il-b","2"},std::pair{"il-c","3"}}) {
    terminal(id,"edit-config private");
    terminal(id,std::string{"/configure router interface system ipv6 address 2001:db8:ffff::"}+suffix+" prefix-length 128");
    if (std::string_view{id}!="il-c") terminal(id,std::string{"/configure router interface left ipv6 address 2001:db8:12::"}+suffix+" prefix-length 64");
    if (std::string_view{id}!="il-b") terminal(id,std::string{"/configure router interface right ipv6 address 2001:db8:13::"}+
        (std::string_view{id}=="il-a" ? "1" : "2")+" prefix-length 64");
    terminal(id,"commit"); terminal(id,"quit-config");
  }
  for (const auto id : {"il-a","il-b"}) {
    terminal(id,"edit-config private");
    for (const auto command : {"/configure router isis 0 level-capability 1","/configure router isis 0 level 1 wide-metrics-only true",
        "/configure router isis 0 ipv6-routing native","/configure router isis 0 interface system",
        "/configure router isis 0 interface left interface-type point-to-point",
        "/configure router isis 0 interface left level-capability 1",
        "/configure router isis 0 interface left level 1 hello-interval 1",
        "/configure router isis 0 timers spf-wait spf-initial-wait 100",
        "/configure router isis 0 timers spf-wait spf-second-wait 100","/configure router isis 0 timers spf-wait spf-max-wait 100",
        "/configure router isis 0 timers lsp-wait lsp-initial-wait 10",
        "/configure router isis 0 timers lsp-wait lsp-second-wait 100","/configure router isis 0 timers lsp-wait lsp-max-wait 100",
        "/configure router isis 0 admin-state enable","commit","quit-config"}) terminal(id,command);
    const auto dormant=capture();
    const auto inactive=std::find_if(dormant->network.isis->control.devices.begin(),dormant->network.isis->control.devices.end(),
        [&](const auto &device) { return device.handle.index==(std::string_view{id}=="il-a" ? 0U : 1U); });
    require(inactive!=dormant->network.isis->control.devices.end() && inactive->circuits.empty() &&
        inactive->instances.size()==1U && inactive->instances.front().admin_enabled && !inactive->instances.front().areas,
        "Enabled area-less instance did not remain dormant");
    const auto dormant_bytes=runtime->export_checkpoint();
    const std::vector<std::uint8_t> dormant_saved(dormant_bytes.begin(),dormant_bytes.end());
    require(runtime->import_checkpoint(dormant_saved),"Area-less instance checkpoint restore failed");
    terminal(id,"edit-config private"); terminal(id,"/configure router isis 0 area-address[49.0001]");
    terminal(id,"commit"); terminal(id,"quit-config");
  }
  terminal("il-c","//");
  for (const auto command : {"configure router isis 0","area-id 49.0002","level-capability level-2",
      "level 2","wide-metrics-only","exit","ipv6-routing native","timers",
      "spf-wait 100 spf-initial-wait 100 spf-second-wait 100","lsp-wait 100 lsp-initial-wait 10 lsp-second-wait 100","exit",
      "interface system","no shutdown","exit","interface right","interface-type point-to-point",
      "level-capability level-2","level 1","hello-interval 1","exit","no shutdown","exit","no shutdown","exit all"})
    terminal("il-c",command);
  const auto await_route=[&](std::string_view session,std::string_view prefix,bool present,bool ipv6) {
    const auto until=std::chrono::steady_clock::now()+8s; std::string output;
    do {
      output=terminal(session,ipv6 ? "show router route-table ipv6" : "show router route-table");
      if ((output.find(prefix)!=std::string::npos)==present) return;
      std::this_thread::yield();
    } while (std::chrono::steady_clock::now()<until);
    throw std::runtime_error("Interlevel route "+std::string{prefix}+": "+output);
  };
  await_route("il-a","10.255.0.2/32",true,false);
  const auto old=capture();
  require(old->network.isis->selection_producers.empty(),"Single-level public owner unexpectedly admitted an export producer");
  terminal("il-a","edit-config private"); terminal("il-a","/configure router isis 0 level-capability 1/2");
  const std::string refused{runtime->command(message(protocol::session_execute,{"il-a","commit"}))};
  require(refused.find("Candidate commit failed")!=std::string::npos,"Combined activation ignored the disabled level's metric policy");
  terminal("il-a","discard"); terminal("il-a","quit-config");
  await_route("il-a","10.255.0.2/32",true,false);
  terminal("il-a","edit-config private");
  for (const auto command : {"/configure router isis 0 level-capability 1/2",
      "/configure router isis 0 level 2 wide-metrics-only true",
      "/configure router isis 0 interface right interface-type point-to-point",
      "/configure router isis 0 interface right level-capability 2",
      "/configure router isis 0 interface right level 1 hello-interval 1","commit","quit-config"}) terminal("il-a",command);
  const auto await_exports=[&] {
    await_route("il-a","10.255.0.2/32",true,false); await_route("il-a","2001:db8:ffff::2/128",true,true);
    await_route("il-b","0.0.0.0/0",true,false); await_route("il-b","::/0",true,true);
    await_route("il-c","10.255.0.2/32",true,false); await_route("il-c","2001:db8:ffff::2/128",true,true);
    await_route("il-c","10.0.12.0/30",true,false); await_route("il-c","2001:db8:12::/64",true,true);
  };
  await_exports();
  terminal("il-c","configure router isis 0"); terminal("il-c","no interface right"); terminal("il-c","exit all");
  await_route("il-c","10.0.13.0/30",true,false); await_route("il-c","2001:db8:13::/64",true,true);
  await_route("il-c","10.255.0.2/32",false,false); await_route("il-c","2001:db8:ffff::2/128",false,true);
  for (const auto command : {"configure router isis 0","interface right","interface-type point-to-point",
      "level-capability level-2","level 1","hello-interval 1","exit","no shutdown","exit","exit all"}) terminal("il-c",command);
  await_exports();
  terminal("il-b","edit-config private"); terminal("il-b","/delete router isis 0 interface left");
  terminal("il-b","commit"); terminal("il-b","quit-config");
  await_route("il-c","10.255.0.2/32",false,false); await_route("il-c","2001:db8:ffff::2/128",false,true);
  terminal("il-b","edit-config private");
  for (const auto command : {"/configure router isis 0 interface left interface-type point-to-point",
      "/configure router isis 0 interface left level-capability 1",
      "/configure router isis 0 interface left level 1 hello-interval 1","commit","quit-config"}) terminal("il-b",command);
  await_exports();
  const auto before_policy=capture();
  terminal("il-c","//"); terminal("il-c","edit-config private");
  for (const auto command : {"/configure router isis 0 level 2 preference 19",
      "/configure router isis 0 level 2 external-preference 170",
      "/configure router isis 0 timers spf-wait spf-max-wait 550",
      "/configure router isis 0 timers spf-wait spf-initial-wait 10",
      "/configure router isis 0 timers spf-wait spf-second-wait 100","commit","quit-config"}) terminal("il-c",command);
  await_exports();
  auto preference=capture();
  const auto &preference_owner=preference->network.isis->control.devices.back().instances.front();
  const auto &previous_owner=before_policy->network.isis->control.devices.back();
  const auto &current_owner=preference->network.isis->control.devices.back();
  require(preference_owner.admission_epoch==previous_owner.instances.front().admission_epoch &&
      preference_owner.entity_epoch==previous_owner.instances.front().entity_epoch &&
      current_owner.circuits.size()==previous_owner.circuits.size(),"Decision policy replaced the live instance");
  for (std::size_t circuit{}; circuit<current_owner.circuits.size(); ++circuit)
    require(current_owner.circuits[circuit].definition.identity==previous_owner.circuits[circuit].definition.identity &&
        current_owner.circuits[circuit].counters.adjacency_up==previous_owner.circuits[circuit].counters.adjacency_up,
        "Decision policy replaced a circuit epoch or re-established an adjacency");
  require(preference_owner.configuration.spf_delay==router::isis::SpfDelayPolicy{500ms,0ms,100ms} &&
      preference_owner.configuration.routing[0U]->preferences[1U]==router::isis::P2pRouteFamilyProgram::Preference{19U,170U} &&
      preference_owner.configuration.routing[1U]->preferences[1U]==router::isis::P2pRouteFamilyProgram::Preference{19U,170U},
      "Live preference or normalized SPF policy did not reach both family owners");
  auto &preference_intent=preference->portable_routers.back().isis.instances.front();
  preference_intent.level[1U].preference=20U;
  const auto forged_preference=checkpoint_v21::encode(*preference,&*protector);
  require(!forged_preference.empty() && !runtime->import_checkpoint(forged_preference),
      "Checkpoint accepted a managed preference inconsistent with its route owners");
  preference_intent.level[1U].preference=19U; preference_intent.spf_wait.initial=110U;
  const auto forged_spf=checkpoint_v21::encode(*preference,&*protector);
  require(!forged_spf.empty() && !runtime->import_checkpoint(forged_spf),
      "Checkpoint accepted a managed SPF timer inconsistent with its scheduler");
  for (const bool ipv6 : {false,true}) {
    const auto until=std::chrono::steady_clock::now()+8s;
    for (;;) {
      const auto output=terminal("il-c",ipv6 ? "show router route-table ipv6" : "show router route-table");
      const auto begin=output.find(ipv6 ? "2001:db8:ffff::2/128" : "10.255.0.2/32");
      if (begin!=std::string::npos && output.substr(begin,output.find('\n',begin)-begin).find("  19")!=std::string::npos) break;
      require(std::chrono::steady_clock::now()<until,"Live preference did not reach the installed route");
      std::this_thread::yield();
    }
  }
  terminal("il-c","//");
  for (const auto command : {"configure router isis 0","level 2","no preference","no external-preference","exit",
      "timers","spf-wait 100 spf-initial-wait 100 spf-second-wait 100","exit","exit all"}) terminal("il-c",command);
  await_exports();
  const auto restored_policy=capture();
  const auto &restored_intent=restored_policy->portable_routers.back().isis.instances.front();
  require(!restored_intent.level[1U].preference && !restored_intent.level[1U].external_preference,
      "Classic removal retained explicit preference values");
  for (const auto &family : restored_policy->network.isis->control.devices.back().instances.front().configuration.routing)
    require(family && family->preferences[1U]==router::isis::P2pRouteFamilyProgram::Preference{18U,165U},
        "Classic preference removal did not restore the level defaults");
  const auto before_name=capture();
  const auto await_name=[&](std::string_view expected) {
    const auto deadline=std::chrono::steady_clock::now()+8s;
    for (;;) {
      auto image=capture();
      const auto &remote=image->network.isis->control.devices.front().instances.front();
      const auto &source=image->network.isis->control.devices.back().instances.front();
      std::optional<router::packet::isis::LspId> found;
      require(remote.process && remote.process->levels[1U],"Hostname receiver lacks L2 database");
      for (const auto &record : remote.process->levels[1U]->database.database.records) {
        router::packet::isis::DecodeError error{};
        const auto pdu=router::packet::isis::parse(record.bytes,error);
        const auto header=pdu ? router::packet::isis::lsp(*pdu) : std::nullopt;
        if (!header || !header->remaining_seconds || !std::equal(source.configuration.local.begin(),source.configuration.local.end(),header->id.begin()) || header->id[6U]) continue;
        router::packet::isis::TlvCursor options(pdu->tlvs);
        while (const auto option=options.next()) if (option->code==137U &&
            std::string_view{reinterpret_cast<const char *>(option->value.data()),option->value.size()}==expected) found=header->id;
      }
      if (found) {
        const auto report=terminal("il-a","show router isis hostname");
        require(report.find(expected)!=std::string::npos,"MD hostname report disagreed with the received LSP database");
        const auto raw=router::isis::format_lsp_id(*found);
        const auto named=std::string{expected}+raw.substr(14U);
        for (const auto session : {"il-a","il-c"}) for (const bool explicit_instance : {false,true}) {
          const auto prefix=std::string{"show router isis "}+(explicit_instance ? "0 database" : "database");
          for (const auto &selector : {std::string{},raw,named,router::isis::format_configured_system_id(source.configuration.local)}) {
            const auto selected=selector.empty() ? std::string{} : " "+selector;
            for (const auto &suffix : {std::string{},std::string{" level 2"}}) {
              const auto database=terminal(session,prefix+selected+suffix);
              require(database.find(named)!=std::string::npos,"Database summary omitted the accepted remote or local named LSP");
              if (!suffix.empty()) require(database.find("Displaying Level 1")==std::string::npos,"Database level selector leaked another level");
              if (selector==raw || selector==named) require(database.find("Level (2) LSP Count : 1")!=std::string::npos,
                  "Exact LSP selector returned another retained identity");
              const auto detailed=terminal(session,prefix+selected+" detail"+suffix);
              require(detailed.find("Database (detail)")!=std::string::npos && detailed.find("Used Len  :")!=std::string::npos &&
                  detailed.find("IS-Hostname   : "+std::string{expected})!=std::string::npos,
                  "Detailed database report omitted accepted metadata or hostname");
            }
          }
        }
        return image;
      }
      require(std::chrono::steady_clock::now()<deadline,"Changed hostname did not arrive through encoded L2 flooding");
      std::this_thread::sleep_for(2ms);
    }
  };
  terminal("il-c","configure system name il-c-renamed");
  auto renamed=await_name("il-c-renamed");
  const auto l1_names=terminal("il-b","show router isis hostname");
  require(l1_names.find("il-a")!=std::string::npos && l1_names.find("il-b")!=std::string::npos &&
      l1_names.find("il-c-renamed")==std::string::npos,"L1-only hostname report consumed another level or topology configuration");
  const auto l1_database=terminal("il-b","show router isis database level 1");
  require(l1_database.find("il-a.00-00")!=std::string::npos && l1_database.find("il-b.00-00")!=std::string::npos &&
      l1_database.find("il-c-renamed")==std::string::npos,"L1 database summary read another router's topology or level");
  require(terminal("il-b","show router isis 0 database level 2").find("Level (2) LSP Count : 0")!=std::string::npos,
      "Absent L2 database fabricated entries");
  require(terminal("il-c","show router isis 0 hostname").find("il-c-renamed")!=std::string::npos,
      "Classic explicit-instance hostname report omitted the local origin");
  const auto &old_name_owner=before_name->network.isis->control.devices.back();
  const auto &new_name_owner=renamed->network.isis->control.devices.back();
  require(old_name_owner.instances.front().admission_epoch==new_name_owner.instances.front().admission_epoch &&
      old_name_owner.instances.front().entity_epoch==new_name_owner.instances.front().entity_epoch &&
      old_name_owner.circuits.front().definition.identity==new_name_owner.circuits.front().definition.identity &&
      old_name_owner.circuits.front().counters.adjacency_up==new_name_owner.circuits.front().counters.adjacency_up,
      "Hostname change restarted the instance or adjacency");
  const auto renamed_bytes=runtime->export_checkpoint();
  const std::vector<std::uint8_t> renamed_saved(renamed_bytes.begin(),renamed_bytes.end());
  require(runtime->import_checkpoint(renamed_saved),"Active renamed owner checkpoint restore failed");
  static_cast<void>(await_name("il-c-renamed"));
  renamed->devices.entries.back().system_name="forged-name";
  const auto forged_name=checkpoint_v21::encode(*renamed,&*protector);
  require(!forged_name.empty() && !runtime->import_checkpoint(forged_name),"Checkpoint accepted hostname intent inconsistent with root metadata");
  terminal("il-c","//"); terminal("il-c","edit-config private");
  terminal("il-c","/configure system name il-c"); terminal("il-c","commit"); terminal("il-c","quit-config");
  static_cast<void>(await_name("il-c"));
  terminal("il-c","edit-config private");
  const std::string invalid_name{runtime->command(message(protocol::session_execute,
      {"il-c","/configure system name \"\xC3\xB3\""}))};
  require(invalid_name.find("MINOR: MGMT_CORE #2301")!=std::string::npos,"Hostname edit bypassed printable ASCII admission");
  terminal("il-c","discard"); terminal("il-c","quit-config");
  operation(protocol::system_name_set,{"il-c","il-c-from-ui"}); static_cast<void>(await_name("il-c-from-ui"));
  operation(protocol::system_name_set,{"il-c","il-c"}); static_cast<void>(await_name("il-c"));
  terminal("il-c","//");
  auto mismatched=capture();
  const auto wrong=std::find_if(mismatched->portable_routers.begin(),mismatched->portable_routers.end(),
      [](const auto &router) { return router.device.index==0U; });
  require(wrong!=mismatched->portable_routers.end(),"Combined managed owner missing");
  wrong->isis.instances.front().levels=router::isis::ConfiguredLevels::level1;
  require(!runtime->import_checkpoint(checkpoint_v21::encode(*mismatched,&*protector)),
      "Checkpoint accepted managed levels inconsistent with the running owner");
  wrong->isis.instances.front().levels=router::isis::ConfiguredLevels::both;
  wrong->isis.instances.front().areas.clear();
  require(!runtime->import_checkpoint(checkpoint_v21::encode(*mismatched,&*protector)),
      "Checkpoint accepted active circuits under empty canonical manual areas");
  std::size_t ping_ordinal{};
  const auto ping=[&](std::string_view session,std::string_view address) {
    ++ping_ordinal;
    const auto ready_by=std::chrono::steady_clock::now()+8s;
    for (;;) {
      const auto image=capture();
      if (std::all_of(image->network.routers.begin(),image->network.routers.end(),[](const auto &device) {
        return std::all_of(device.forwarding.ipv6_dad.begin(),device.forwarding.ipv6_dad.end(),
            [](const auto &dad) { return dad.state==Ipv6DadState::preferred; });
      }) && std::all_of(image->network.isis->control.devices.begin(),image->network.isis->control.devices.end(),
          [](const auto &device) {
            return std::all_of(device.circuits.begin(),device.circuits.end(),[](const auto &circuit) {
              const auto *common=circuit.definition.common();
              return common && common->ipv6_addresses_ready;
            });
          })) break;
      require(std::chrono::steady_clock::now()<ready_by,"Interlevel DAD or protocol readiness did not finish"); std::this_thread::yield();
    }
    const bool ipv6=address.find(':')!=std::string_view::npos;
    await_route(session,session=="il-b" ? (ipv6 ? "::/0" : "0.0.0.0/0") :
        std::string{address}+(ipv6 ? "/128" : "/32"),true,ipv6);
    auto output=terminal(session,"ping "+std::string{address}+" count 1");
    const auto until=std::chrono::steady_clock::now()+5s;
    while (output.find("PING Statistics")==std::string::npos && std::chrono::steady_clock::now()<until) {
      output+=runtime->command(message(protocol::session_poll,{session})); std::this_thread::yield();
    }
    if (output.find("1 packets transmitted, 1 packets received")==std::string::npos)
      throw std::runtime_error("Interlevel public Echo #"+std::to_string(ping_ordinal)+" "+std::string{session}+" to "+std::string{address}+": "+output+
          "\nC routes: "+terminal("il-c","show router route-table")+"\nA adjacency: "+terminal("il-a","show router isis 0 adjacency"));
  };
  ping("il-c","10.255.0.2"); ping("il-c","2001:db8:ffff::2");
  ping("il-b","10.255.0.3"); ping("il-b","2001:db8:ffff::3");
  for (const auto command : {"configure router isis 0","level 1","wide-metrics-only","exit",
      "level-capability level-1/2","exit all"}) terminal("il-c",command);
  await_exports(); ping("il-c","10.255.0.2"); ping("il-c","2001:db8:ffff::2");
  terminal("il-a","//"); terminal("il-a","configure router isis 0");
  terminal("il-a","no level-capability"); terminal("il-a","exit all"); await_exports();
  auto defaulted=capture();
  const auto intent=std::find_if(defaulted->portable_routers.begin(),defaulted->portable_routers.end(),
      [](const auto &router) { return router.device.index==0U; });
  require(intent!=defaulted->portable_routers.end() && !intent->isis.instances.front().levels,
      "Classic level-capability removal retained explicit presence");
  terminal("il-a","//"); terminal("il-a","edit-config private");
  terminal("il-a","/configure router isis 0 level-capability 1/2"); terminal("il-a","commit");
  terminal("il-a","/delete router isis 0 level-capability"); terminal("il-a","commit"); terminal("il-a","quit-config");
  await_exports();
  terminal("il-a","edit-config private"); terminal("il-a","/delete router isis 0 area-address[49.0001]");
  terminal("il-a","commit"); terminal("il-a","quit-config");
  await_route("il-c","10.255.0.2/32",false,false); await_route("il-c","2001:db8:ffff::2/128",false,true);
  const auto unaddressed=runtime->export_checkpoint();
  const std::vector<std::uint8_t> unaddressed_saved(unaddressed.begin(),unaddressed.end());
  require(runtime->import_checkpoint(unaddressed_saved),"Combined area-less checkpoint restore failed");
  terminal("il-a","//"); terminal("il-a","configure router isis 0");
  terminal("il-a","area-id 49.0001"); terminal("il-a","exit all"); await_exports();
  ping("il-c","10.255.0.2"); ping("il-c","2001:db8:ffff::2");
  terminal("il-a","configure router isis 0"); terminal("il-a","no area-id 49.0001");
  terminal("il-a","exit all"); await_route("il-c","10.255.0.2/32",false,false);
  terminal("il-a","configure router isis 0"); terminal("il-a","area-id 49.0001");
  terminal("il-a","exit all"); await_exports();
  operation(protocol::port_configure,{"il-a","1/1/1","0","9212","100000",""});
  await_route("il-c","10.255.0.2/32",false,false); await_route("il-c","2001:db8:ffff::2/128",false,true);
  await_route("il-c","10.0.12.0/30",false,false); await_route("il-c","2001:db8:12::/64",false,true);
  operation(protocol::port_configure,{"il-a","1/1/1","1","9212","100000",""}); await_exports();
  terminal("il-a","//"); terminal("il-a","edit-config private");
  terminal("il-a","/configure router isis 0 admin-state disable"); terminal("il-a","commit");
  terminal("il-a","/delete router isis 0 area-address[49.0001]"); terminal("il-a","commit");
  const auto disabled=capture();
  require(!disabled->network.isis->control.devices.front().instances.front().admin_enabled,
      "Area edit enabled a disabled instance");
  terminal("il-a","/configure router isis 0 area-address[49.0001]"); terminal("il-a","commit");
  terminal("il-a","/configure router isis 0 admin-state enable"); terminal("il-a","commit");
  terminal("il-a","quit-config"); await_exports();
  const auto bytes=runtime->export_checkpoint(); const std::vector<std::uint8_t> saved(bytes.begin(),bytes.end());
  runtime.reset(); runtime=std::make_unique<LabRuntime>();
  require(runtime->initialize_secret_vault(key,context) && runtime->import_checkpoint(saved),"Combined fresh-owner checkpoint restore failed");
  const auto restored=capture();
  require(restored->network.isis->selection_producers.size()==2U,"Combined checkpoint lost the real selection producer");
  await_exports(); ping("il-c","10.255.0.2"); ping("il-c","2001:db8:ffff::2");
}
