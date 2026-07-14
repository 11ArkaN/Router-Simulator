// Visible manual scenario for fresh hardware, mismatch, lifecycle, forwarding,
// capture and failure cascade through the real multithreaded runtime.

#include "router/runtime.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

int main() {
  auto runtime = std::make_unique<router::Runtime>();
  const auto run = [&](std::string_view command) {
    std::cout << "\n>>> " << command << '\n' << runtime->command(std::string(command)) << '\n';
  };

  run("terminal:show router interface");
  run("host:ping:host-a:host-b");
  run("project:provisioning|iom4-e|me10-10gb-sfp+");
  run("hardware:insert-card");
  run("hardware:insert-mda:me1-100gb-cfp2");
  run("terminal:show port");
  run("host:ping:host-a:host-b");
  run("hardware:remove-mda");
  run("hardware:insert-mda:me10-10gb-sfp+");
  std::this_thread::sleep_for(std::chrono::milliseconds(3200));
  run("terminal:show router interface");
  run("terminal:show router fib");
  run("host:ping:host-a:host-b");
  run("terminal:show router arp");
  run("capture:prepare");
  run("link:down:1/1/2");
  run("terminal:show router interface");
  run("terminal:show router fib");
  run("host:ping:host-a:host-b");
  run("snapshot");
  run("link:up:1/1/2");
  run("terminal://");
  run("terminal:show port");
}
