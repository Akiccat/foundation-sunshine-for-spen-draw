/**
 * @file src/platform/windows/frame_keepalive.h
 * @brief 帧率保活：让桌面一直有新画面，从而让编码循环跑满客户端帧率。
 *
 * 背景：Sunshine 的编码循环是「等新画面 -> 编码」。桌面完全静止时等不到新画面，
 * 这一轮等待就白费，编码耗时再叠加上去，一帧的实际周期变成「间隔 + 编码」，
 * 60fps 的流会掉到 30~45fps，延迟也跟着在 6~9ms 之间来回摆。
 *
 * 与其在编码侧做栅格推算（那要跟采集层的 frame_pacing_group 抢节拍、很难稳），
 * 不如让桌面一直有变化：采集层自然会按客户端帧率持续出帧。
 */
#pragma once

namespace platf::frame_keepalive {
  /**
   * @brief 开启保活像素。幂等——重复调用只生效一次。
   *
   * 会在每块显示器左上角放一个 1x1 像素的置顶小窗，按约 60Hz 在两档只差
   * 1/255 的暗色之间切换。对 DXGI 是真实脏区域，对肉眼几乎不可见。
   */
  void start();

  /** @brief 停止并从桌面移除保活像素。 */
  void stop();
}  // namespace platf::frame_keepalive
