// The fixture restores explicit export-refusal state under a real control
// barrier. Its derived retry must preserve the last complete L2 root while
// remaining independent of RIB publication and protocol process ownership.
#include "router/isis_control_checkpoint.hpp"
#include "router/isis_instance_program.hpp"
#include <memory>
#include <algorithm>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value,std::source_location at=std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS export retry invariant at "+std::to_string(at.line()));
}
}
void isis_interlevel_retry_tests() {
  auto channels=std::make_unique<ControlChannels>();
  auto worker=std::make_unique<ControlWorker>(*channels,1U,2U);
  const lab::DeviceHandle device{0U,1U}; std::uint64_t serial{};
  const auto command=[&](ControlCommand request) {
    request.id=++serial; request.identity.device=device;
    const auto end=RuntimeClock::now()+3s;
    while (!worker->submit(std::move(request))) { require(RuntimeClock::now()<end); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now()<end); std::this_thread::yield(); }
    require(result.id==serial); return result;
  };
  const auto operation=[&](ControlCommandKind kind) { ControlCommand request; request.kind=kind; return command(std::move(request)); };
  require(operation(ControlCommandKind::register_device).error==ControlError::none);
  InstanceIntent intent; intent.admin_enabled=true; intent.levels=ConfiguredLevels::both;
  intent.system_id=packet::isis::SystemId{1U,2U,3U,4U,5U,6U}; intent.areas.push_back(*parse_configured_area("49.0001"));
  InterfaceIntent attached; attached.name="edge"; attached.type=ConfiguredInterfaceType::point_to_point;
  intent.interfaces.push_back(attached);
  const std::array bindings{InstanceOriginInterface{"edge",lab::physical_interface_id(0U),
      ConfiguredInterfaceType::point_to_point,1U,1U,false}};
  InstanceProgramContext context; context.maximum_areas=3U; context.maximum_circuits=1U;
  context.interfaces=bindings;
  const UpdateLevelConfiguration level{{8U,8192U},8U,128U,1492U,1200U,60s,60s,false,false,false,PurgeRules::iso_10589};
  context.levels={level,level}; context.fragments={1U,1U}; context.transmission={1U,5U,5U,100ms,10U,1492U,1U};
  context.minimum_generation_interval=10ms; context.resource_retry=100ms; context.random=1U;
  context.hierarchy_decision=P2pDecisionProgram{8U,8U,8U,{},{}};
  const auto program=prepare_instance_program(intent,context);
  require(program.status==InstanceProgramStatus::prepared && program.program);
  ControlCommand admission; admission.kind=ControlCommandKind::prepare_generation;
  admission.interlevel_export=InterlevelTemplateBudget{4U,64U,4U}; admission.new_instances.push_back({0U,*program.program});
  const auto admitted=command(admission);
  if (admitted.error!=ControlError::none)
    throw std::runtime_error("IS-IS retry fixture admission error="+std::to_string(static_cast<unsigned>(admitted.error)));
  require(operation(ControlCommandKind::commit_generation).error==ControlError::none);
  const auto before=operation(ControlCommandKind::query_update_instance);
  require(before.error==ControlError::none && before.local_export_status==InterlevelCompositionStatus::applied);
  const auto barrier=operation(ControlCommandKind::begin_checkpoint_barrier); require(barrier.error==ControlError::none);
  ControlWorkerCheckpoint image;
  ControlCommand capture; capture.kind=ControlCommandKind::capture_checkpoint;
  capture.checkpoint_barrier_epoch=barrier.checkpoint_barrier_epoch;
  capture.checkpoint_now_nanoseconds=barrier.checkpoint_anchor_nanoseconds;
  capture.checkpoint_transfer=reinterpret_cast<std::uintptr_t>(&image);
  require(command(capture).error==ControlError::none && image.devices.size()==1U && image.devices[0U].instances.size()==1U);
  auto &instance=image.devices[0U].instances[0U];
  instance.composition_status=InterlevelCompositionStatus::conflicting_attributes;
  instance.composition_retry={checkpoint_time::DeadlineKind::relative,10'000'000'000LL};
  instance.local_roots_dirty[1U]=true;
  ControlCommand restore; restore.kind=ControlCommandKind::prepare_checkpoint_restore;
  restore.checkpoint_barrier_epoch=barrier.checkpoint_barrier_epoch; restore.checkpoint_source_epoch=image.barrier_epoch;
  restore.checkpoint_now_nanoseconds=barrier.checkpoint_anchor_nanoseconds;
  restore.checkpoint_transfer=reinterpret_cast<std::uintptr_t>(&image);
  const auto valid=image;
  // Dirty composition may retain old bytes. A settled root cannot contain
  // an export unsupported by the restored local intent and selected bank.
  image.devices[0U].instances[0U].composition_status=InterlevelCompositionStatus::applied;
  image.devices[0U].instances[0U].composition_retry={checkpoint_time::DeadlineKind::minimum,0};
  image.devices[0U].instances[0U].local_roots_dirty[1U]=false;
  auto &entries=image.devices[0U].instances[0U].local->entries;
  const auto root=std::find_if(entries.begin(),entries.end(),[](const auto &entry) {
    return entry.content.level==1U && !entry.content.id[6U] && !entry.content.id[7U];
  });
  require(root!=entries.end());
  std::array<std::uint8_t,32U> bytes{}; packet::isis::TlvWriter writer(bytes);
  require(encode_root_prefix(writer,{*ip::parse_ip_prefix("192.0.2.99/32"),9U,{}}));
  root->content.options.insert(root->content.options.end(),writer.bytes().begin(),writer.bytes().end());
  require(command(restore).error!=ControlError::none); image=valid;
  image.devices[0U].instances[0U].local_roots_dirty[1U]=false;
  require(command(restore).error!=ControlError::none); image=valid;
  image.devices[0U].instances[0U].composition_status=InterlevelCompositionStatus::applied;
  require(command(restore).error!=ControlError::none); image=valid;
  image.devices[0U].interlevel.reset();
  require(command(restore).error!=ControlError::none); image=valid;
  require(command(restore).error==ControlError::none);
  restore.kind=ControlCommandKind::commit_checkpoint_restore; require(command(restore).error==ControlError::none);
  ControlCommand resume; resume.kind=ControlCommandKind::end_checkpoint_barrier;
  resume.checkpoint_barrier_epoch=barrier.checkpoint_barrier_epoch; require(command(resume).error==ControlError::none);
  const auto after=operation(ControlCommandKind::query_update_instance);
  require(after.error==ControlError::none && after.update_status==UpdateStatus::applied &&
      after.local_export_status==InterlevelCompositionStatus::conflicting_attributes && after.local_export_retry_pending &&
      after.local_root_sequences[1U]==before.local_root_sequences[1U]);
}
