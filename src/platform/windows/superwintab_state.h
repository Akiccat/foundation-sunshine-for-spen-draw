// superwintab_state.h -- shared-memory pen channel between Sunshine and the
// in-process Wintab32.dll.
//
// MIRRORED FILE. The canonical copy lives at
//   E:/DshProject/sunshine-mod/superwintab/include/superwintab_state.h
// It is duplicated here because Sunshine's build has no dependency on the
// superwintab tree. Change both together -- the layout is baked into the
// Wintab32.dll on the other side of the mapping.
//
// WHY THIS EXISTS
// ---------------
// Windows' synthetic pen injection (InjectSyntheticPointerInput) is clamped to
// 1024 pressure steps by the pointer stack; measured, not assumed (see
// tools/pen_pressure_probe.py in the Sunshine tree). Everything that reads pen
// data from the Ink channel -- WinTab shims included -- inherits that ceiling:
// the SuperDisplay Wintab32.dll reports a pressure AXIS with axMax = 1023.
//
// So instead of trying to push more than 1024 through a pipe that drops it, we
// stop using that pipe for pressure. Sunshine writes the pen state into a
// shared memory section at full float precision, and our own Wintab32.dll --
// loaded from the drawing app's own directory -- reads it directly and hands
// WinTab PACKETs to the app. The pressure value never touches the pointer
// stack, so there is nothing left to clamp it.
//
// This header is plain C and dependency-free: Sunshine (C++) and the DLL
// (C++) both include it, and the Python mock producer mirrors the layout.
//
// Concurrency: single producer (Sunshine), multiple consumers (one DLL instance
// per drawing app). Guarded by a seqlock -- the writer bumps seq before and
// after the store, so a reader can detect a torn read by checking that seq is
// even and unchanged across the copy.

#ifndef SUPERWINTAB_STATE_H
#define SUPERWINTAB_STATE_H

#include <stdint.h>

#define SUPERWINTAB_MAGIC 0x5350454Eu /* "SPEN" */
#define SUPERWINTAB_VERSION 2u

/* Session-local so it cannot collide across user sessions. */
#define SUPERWINTAB_MAP_NAME "Local\\SuperSunPenState"
#define SUPERWINTAB_MAP_SIZE 512

/* pen_state.flags */
#define SWPEN_FLAG_IN_RANGE 0x0001u /* pen is within hover distance */
#define SWPEN_FLAG_IN_CONTACT 0x0002u /* tip is touching */
#define SWPEN_FLAG_ERASER 0x0004u /* tool is an eraser */
#define SWPEN_FLAG_BARREL 0x0008u /* barrel button held */
#define SWPEN_FLAG_TILT_VALID 0x0010u
#define SWPEN_FLAG_ROT_VALID 0x0020u

/* Pressure range advertised over WinTab. 4096 matches the S Pen's real
 * ABS_PRESSURE range, which is what the Android side reports natively. The
 * Ink path could only ever expose 1024 of these.
 *
 * This is now only a FALLBACK: Sunshine fills pressure_max from the value the
 * client reports for its digitizer (see the calibration card in the web UI), so
 * a pen with a different hardware range gets a matching axis instead of being
 * rescaled onto a 4096 grid that does not exist. */
#define SUPERWINTAB_PRESSURE_MAX 4096

/* Accepted bounds for the negotiated axis maximum. Below 256 the drawing app
 * would visibly stair-step; above 65536 nothing on the Android side can fill
 * it anyway. */
#define SUPERWINTAB_PRESSURE_MIN 256u
#define SUPERWINTAB_PRESSURE_MAX_LIMIT 65536u

typedef struct superwintab_state {
  uint32_t magic;
  uint32_t version;

  /* seqlock: odd while the writer is mid-store, even when stable. */
  volatile uint32_t seq;
  uint32_t reserved0;

  volatile uint64_t timestamp_us; /* producer clock (QPC us) */
  volatile uint64_t sample_id; /* monotonically increasing per sample */

  volatile uint32_t flags;
  volatile uint32_t buttons; /* bit0 = tip switch, bit1 = barrel */

  /* Normalized to the streamed desktop, 0..1. The DLL scales these onto the
   * tablet context's input extents. */
  volatile float x;
  volatile float y;

  /* Full-precision pressure, 0..1. This is the entire point of the exercise. */
  volatile float pressure;

  volatile float tilt_x; /* degrees, -90..90 */
  volatile float tilt_y;
  volatile float rotation; /* degrees, 0..360 */

  /* Size of the streamed desktop in pixels, so the reader can build tablet
   * coordinates without guessing. */
  volatile uint32_t screen_w;
  volatile uint32_t screen_h;

  /* ---------------------------------------------------------------- v2 --
   * Pressure calibration. Written by Sunshine, read by the DLL.
   *
   * pressure_max is the WinTab axis maximum the DLL advertises. It should match
   * the digitizer's real range (the S Pen's ABS_PRESSURE tops out at 4095, so
   * 4096). The web UI's calibration card sets it from the device report instead
   * of trusting a compiled-in constant; 0 means "fall back to
   * SUPERWINTAB_PRESSURE_MAX".
   */
  volatile uint32_t pressure_max;

  /* The highest pressure the *user* can physically reach, 0..1, captured by
   * pressing as hard as possible on the calibration canvas. Dividing by this
   * maps "as hard as I can press" onto the full axis, which is what a user with
   * a light touch actually wants. <= 0 or >= 1 means no rescaling. */
  volatile float pressure_user_max;
} superwintab_state_t;

#endif /* SUPERWINTAB_STATE_H */
