// A real control pthread owns local LSP publication and read-only name queries.
// Tests supply only local semantic programs, observe accepted LSDB incarnations
// and retain detached query results. Foreign names are tested through links by
// the public datastore fixture.
#include "router/isis_operational.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value,std::source_location where=std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS hostname query invariant at "+std::to_string(where.line()));
}
std::vector<std::uint8_t> name_options(std::string_view name) {
  std::vector<std::uint8_t> result{137U,static_cast<std::uint8_t>(name.size())};
  result.insert(result.end(),name.begin(),name.end()); return result;
}
}
void isis_hostname_query_tests() {
  auto channels=std::make_unique<ControlChannels>();
  auto worker=std::make_unique<ControlWorker>(*channels,1U,4U);
  const CircuitIdentity identity{{0U,1U},1U,1U,0U,0U};
  std::uint64_t next{};
  const auto execute=[&](ControlCommand request) {
    request.id=++next; request.identity=identity;
    const auto deadline=RuntimeClock::now()+4s;
    while (!worker->submit(std::move(request))) { require(RuntimeClock::now()<deadline); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now()<deadline); std::this_thread::yield(); }
    require(result.id==next); return result;
  };
  ControlCommand request; request.kind=ControlCommandKind::register_device;
  require(execute(std::move(request)).error==ControlError::none);
  const UpdateLevelConfiguration level{{8U,8192U},8U,128U,1492U,1200U,60s,60s,false,false,false,PurgeRules::iso_10589};
  UpdateInstanceProgram program{{1U,2U,3U,4U,5U,6U},3U,{level,level},1U,{1U,5U,5U,1s,10U,1492U,1U}};
  program.origination.emplace(); program.origination->resource_retry=100ms;
  auto &content=program.origination->content; content.random=17U;
  content.levels={LocalLspLevelProgram{1200U,1492U,1ms,600s},LocalLspLevelProgram{1200U,1492U,1ms,600s}};
  packet::isis::LspId root{1U,2U,3U,4U,5U,6U,0U,0U}, fragment=root, pseudonode=root;
  fragment[7U]=1U; pseudonode[6U]=1U;
  content.records={{0U,root,3U,name_options("older-l1"),true},{0U,fragment,3U,{},false},
      {0U,pseudonode,3U,name_options("ignored-pseudonode"),true},{1U,root,3U,name_options("older-l2"),true}};
  request={}; request.kind=ControlCommandKind::add_update_instance; request.update=program;
  require(execute(std::move(request)).error==ControlError::none);
  const auto query=[&](std::size_t rows=8U,std::size_t bytes=1024U,std::uint32_t version=1U) {
    auto result=std::make_shared<HostnameQuery>();
    result->device=identity.device; result->instance=identity.instance;
    result->maximum_rows=rows; result->maximum_name_octets=bytes; result->version=version;
    ControlCommand value; value.kind=ControlCommandKind::query_hostnames; value.hostname_query=result;
    const auto status=execute(std::move(value)).error;
    return std::pair{status,std::move(result)};
  };
  const auto original=query(); require(original.first==ControlError::none && original.second->rows.size()==1U);
  const auto original_name=original.second->rows.front().hostname;
  require(original_name=="older-l1" || original_name=="older-l2");
  const auto replace=[&](std::size_t level_index,const packet::isis::LspId &id,std::vector<std::uint8_t> options) {
    ControlCommand value; value.kind=ControlCommandKind::replace_local_content;
    value.local_content=LocalLspContent{static_cast<std::uint8_t>(level_index),id,3U,std::move(options),true};
    require(execute(std::move(value)).error==ControlError::none);
  };
  const auto await_sequence=[&](std::size_t level_index,const packet::isis::LspId &id,std::uint32_t sequence,bool live) {
    const auto deadline=RuntimeClock::now()+4s;
    for (;;) {
      ControlCommand value; value.kind=ControlCommandKind::query_update_instance;
      value.level=static_cast<std::uint8_t>(level_index); value.selected_lsp=id;
      const auto result=execute(std::move(value)); require(result.error==ControlError::none);
      if (result.selected_lsp && result.selected_lsp->sequence>=sequence && bool(result.selected_lsp->remaining_seconds)==live) return;
      require(RuntimeClock::now()<deadline); std::this_thread::yield();
    }
  };
  replace(0U,fragment,name_options("n")); await_sequence(0U,fragment,1U,true);
  replace(0U,pseudonode,name_options("newer-but-ignored")); await_sequence(0U,pseudonode,2U,true);
  const auto bounded=query(1U,1U);
  require(bounded.first==ControlError::none && bounded.second->rows.size()==1U && bounded.second->rows.front().hostname=="n");
  require(original.second->rows.front().hostname==original_name);
  for (const auto &[rows,bytes,version] : {std::tuple{0U,1U,1U},std::tuple{1U,0U,1U},std::tuple{1U,1U,2U}}) {
    const auto invalid=query(rows,bytes,version); require(invalid.first==ControlError::invalid_argument && invalid.second->rows.empty());
  }
  replace(0U,fragment,{137U,1U,0x80U}); await_sequence(0U,fragment,2U,true);
  const auto fallback=query();
  require(fallback.first==ControlError::none && fallback.second->rows.size()==1U &&
      (fallback.second->rows.front().hostname=="older-l1" || fallback.second->rows.front().hostname=="older-l2"));
  const auto capacity=query(1U,1U); require(capacity.first==ControlError::capacity && capacity.second->rows.empty());
  replace(0U,fragment,{137U,0U}); await_sequence(0U,fragment,3U,true);
  for (std::size_t level_index{}; level_index<2U; ++level_index) {
    replace(level_index,root,{8U,0U}); await_sequence(level_index,root,2U,true);
  }
  replace(0U,fragment,name_options("temporary")); await_sequence(0U,fragment,4U,true);
  require(query().second->rows.front().hostname=="temporary");
  ControlCommand withdraw; withdraw.kind=ControlCommandKind::withdraw_local_content;
  withdraw.local_content=LocalLspContent{0U,fragment,3U,{},false};
  require(execute(std::move(withdraw)).error==ControlError::none);
  await_sequence(0U,fragment,4U,false);
  const auto empty=query(); require(empty.first==ControlError::none && empty.second->rows.empty());
}
