// Source-bound policy cases use caller-owned states. No runtime, network or
// timer is substituted by this test.
#include "router/isis_hello_padding.hpp"
#include <stdexcept>
void isis_hello_padding_tests() {
  using namespace router::isis;
  const auto require=[](bool ok) { if (!ok) throw std::runtime_error("Hello padding policy invariant"); };
  for (const auto mode : {HelloPadding::adaptive,HelloPadding::loose,HelloPadding::strict,HelloPadding::none})
    require(parse_hello_padding(format_hello_padding(mode))==mode);
  for (const auto invalid : {"", "Adaptive", "none ", "disabled", "0"}) require(!parse_hello_padding(invalid));
  require(format_hello_padding(static_cast<HelloPadding>(0U)).empty());
  require(format_hello_padding(static_cast<HelloPadding>(5U)).empty());
  for (const auto state : {ThreeWayState::down,ThreeWayState::initializing,ThreeWayState::up}) {
    require(p2p_hello_padding(HelloPadding::none,state,false)==false);
    require(p2p_hello_padding(HelloPadding::strict,state,false)==true);
    require(p2p_hello_padding(HelloPadding::adaptive,state,false)==(state!=ThreeWayState::up));
    require(p2p_hello_padding(HelloPadding::loose,state,false)==(state==ThreeWayState::down));
    require(p2p_hello_padding(HelloPadding::adaptive,state,true)==true);
    require(!p2p_hello_padding(HelloPadding::loose,state,true));
  }
  for (const bool up : {false,true}) {
    require(lan_hello_padding(HelloPadding::none,up)==false);
    require(lan_hello_padding(HelloPadding::strict,up)==true);
    require(lan_hello_padding(HelloPadding::adaptive,up)==!up);
    require(lan_hello_padding(HelloPadding::loose,up)==!up);
    require(!lan_hello_padding(static_cast<HelloPadding>(0U),up));
  }
  require(!p2p_hello_padding(HelloPadding::strict,static_cast<ThreeWayState>(3U),false));
  require(!p2p_hello_padding(static_cast<HelloPadding>(0U),ThreeWayState::down,false));
}
