// Human-readable product smoke session. Every action uses protocol 4 and the
// same multi-device facade as the browser Worker.

#include "router/generated_lab_runtime_protocol.hpp"
#include "router/lab_runtime.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <string_view>

namespace {
std::string message(std::initializer_list<std::string_view> fields) {
  std::string value;
  for (const auto field : fields) {
    value += std::to_string(field.size());
    value += ':';
    value.append(field);
    value += ',';
  }
  return value;
}
}

int main() {
  auto runtime = std::make_unique<router::lab::LabRuntime>();
  const auto run = [&](std::initializer_list<std::string_view> fields) {
    const auto input = message(fields);
    std::cout << "\n>>> " << input << '\n' << runtime->command(input) << '\n';
  };
  run({router::lab_runtime_protocol::snapshot});
  run({router::lab_runtime_protocol::router_create, "r1", "7750-sr-1", "R1"});
  run({router::lab_runtime_protocol::host_create, "h1", "H1"});
  run({router::lab_runtime_protocol::session_create, "console-r1", "r1",
       "operational"});
  run({router::lab_runtime_protocol::session_execute, "console-r1", "//"});
  run({router::lab_runtime_protocol::session_execute, "console-r1", "//"});
  run({router::lab_runtime_protocol::session_execute, "console-r1",
       "configure exclusive"});
  run({router::lab_runtime_protocol::session_execute, "console-r1", "back"});
  run({router::lab_runtime_protocol::session_execute, "console-r1",
       "configure exclusive"});
  run({router::lab_runtime_protocol::snapshot});
  const auto checkpoint = runtime->export_checkpoint();
  std::cout << "\ncheckpoint bytes: " << checkpoint.size() << '\n';
  return checkpoint.empty() ? 2 : 0;
}
