// superwintab_publish.h -- live pressure-calibration entry point.
//
// The pen state channel is owned by input.cpp: it is written from the input
// backend every time a pen sample arrives. The web UI's calibration card needs
// to change the advertised axis maximum and the user gain while Sunshine is
// running, so that single operation gets its own entry point instead of the
// HTTP layer reaching into the input backend.
//
// Keep this header dependency-free; both input.cpp and confighttp.cpp include
// it on Windows only.

#pragma once

#include <cstdint>

namespace platf {
  // device_max: WinTab axis maximum to advertise, i.e. the digitizer's real
  //             pressure range. 0 keeps whatever is already published.
  // user_max:   highest pressure the user can actually reach, 0..1. <= 0 or
  //             >= 1 disables the gain (straight 1:1 mapping).
  void
  superwintab_set_pressure_scaling(std::uint32_t device_max, float user_max);

  // Reads back what is currently published. Returns false when the channel has
  // not been created yet (nothing has streamed and nothing has calibrated).
  bool
  superwintab_get_pressure_scaling(std::uint32_t &device_max, float &user_max);
}  // namespace platf
