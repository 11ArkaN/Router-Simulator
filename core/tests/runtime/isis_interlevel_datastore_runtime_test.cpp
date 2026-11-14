// Public datastore commands build three independent routers and exercise live
// L1-to-L1/L2 replacement, shared CLI intent, encoded forwarding and recovery.
// The fixture owns only command inputs and copied checkpoints, never peer state.
#include "router/lab_runtime.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
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
    if (output.starts_with("ERROR:") || output.find("MINOR:")!=std::string::npos || output.find("MAJOR:")!=std::string::npos)
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
    for (const auto command : {"/configure router isis 0 area-address[49.0001]",
        "/configure router isis 0 level-capability 1","/configure router isis 0 level 1 wide-metrics-only true",
        "/configure router isis 0 ipv6-routing native","/configure router isis 0 interface system",
        "/configure router isis 0 interface left interface-type point-to-point",
        "/configure router isis 0 interface left level-capability 1",
        "/configure router isis 0 interface left level 1 hello-interval 1",
        "/configure router isis 0 timers spf-wait spf-initial-wait 100",
        "/configure router isis 0 timers spf-wait spf-second-wait 100","/configure router isis 0 timers spf-wait spf-max-wait 100",
        "/configure router isis 0 timers lsp-wait lsp-initial-wait 10",
        "/configure router isis 0 timers lsp-wait lsp-second-wait 100","/configure router isis 0 timers lsp-wait lsp-max-wait 100",
        "/configure router isis 0 admin-state enable","commit","quit-config"}) terminal(id,command);
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
    await_route("il-c","10.255.0.2/32",true,false); await_route("il-c","2001:db8:ffff::2/128",true,true);
    await_route("il-c","10.0.12.0/30",true,false); await_route("il-c","2001:db8:12::/64",true,true);
  };
  await_exports();
  auto mismatched=capture();
  const auto wrong=std::find_if(mismatched->portable_routers.begin(),mismatched->portable_routers.end(),
      [](const auto &router) { return router.device.index==0U; });
  require(wrong!=mismatched->portable_routers.end(),"Combined managed owner missing");
  wrong->isis.instances.front().levels=router::isis::ConfiguredLevels::level1;
  require(!runtime->import_checkpoint(checkpoint_v21::encode(*mismatched,&*protector)),
      "Checkpoint accepted managed levels inconsistent with the running owner");
  const auto ping=[&](std::string_view session,std::string_view address) {
    const auto ready_by=std::chrono::steady_clock::now()+8s;
    for (;;) {
      const auto image=capture();
      if (std::all_of(image->network.routers.begin(),image->network.routers.end(),[](const auto &device) {
        return std::all_of(device.forwarding.ipv6_dad.begin(),device.forwarding.ipv6_dad.end(),
            [](const auto &dad) { return dad.state==Ipv6DadState::preferred; });
      })) break;
      require(std::chrono::steady_clock::now()<ready_by,"Interlevel DAD did not finish"); std::this_thread::yield();
    }
    auto output=terminal(session,"ping "+std::string{address}+" count 1");
    const auto until=std::chrono::steady_clock::now()+5s;
    while (output.find("PING Statistics")==std::string::npos && std::chrono::steady_clock::now()<until) {
      output+=runtime->command(message(protocol::session_poll,{session})); std::this_thread::yield();
    }
    require(output.find("1 packets transmitted, 1 packets received")!=std::string::npos,"Interlevel public Echo did not return");
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
  operation(protocol::port_configure,{"il-a","1/1/1","0","9212","100000",""});
  await_route("il-c","10.255.0.2/32",false,false); await_route("il-c","2001:db8:ffff::2/128",false,true);
  await_route("il-c","10.0.12.0/30",false,false); await_route("il-c","2001:db8:12::/64",false,true);
  operation(protocol::port_configure,{"il-a","1/1/1","1","9212","100000",""}); await_exports();
  const auto bytes=runtime->export_checkpoint(); const std::vector<std::uint8_t> saved(bytes.begin(),bytes.end());
  runtime.reset(); runtime=std::make_unique<LabRuntime>();
  require(runtime->initialize_secret_vault(key,context) && runtime->import_checkpoint(saved),"Combined fresh-owner checkpoint restore failed");
  const auto restored=capture();
  require(restored->network.isis->selection_producers.size()==2U,"Combined checkpoint lost the real selection producer");
  await_exports(); ping("il-c","10.255.0.2"); ping("il-c","2001:db8:ffff::2");
}
