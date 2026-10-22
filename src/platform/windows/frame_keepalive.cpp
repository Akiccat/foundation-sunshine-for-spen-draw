/**
 * @file src/platform/windows/frame_keepalive.cpp
 * @brief 帧率保活的实现：每块显示器左上角一个按约 60Hz 微微变色的 1x1 像素。
 *
 * 实现要点：
 *  - 窗口必须**真实可见**才会被桌面合成，隐藏窗口不产生任何脏区域，所以用
 *    WS_EX_TOPMOST + SW_SHOWNOACTIVATE 显示出来，但只有 1x1 像素。
 *  - WS_EX_TRANSPARENT 让点击穿透（鼠标不会被这 1 个像素挡住），
 *    WS_EX_NOACTIVATE / WS_EX_TOOLWINDOW 保证不抢焦点、不进任务栏。
 *  - 每块显示器都放一个：这样不用去猜哪块是被采集的那块（虚拟屏还是物理屏），
 *    被采集的那块必然在里面。
 *  - 颜色在两档只差 1/255 的暗色之间切换：对 DXGI 是真实脏区域，
 *    对肉眼基本看不出。
 *
 * ★ 健壮性（2026-10-18 重写，修「偶尔失效、必须重启 Sunshine」）：
 *  1. 原来用 std::call_once：工作线程一旦退出（类注册失败 / 窗口创建全失败 /
 *     任何提前 return），本进程内永久不再重试。现在改成「健康标志 + 可重启」，
 *     每次进串流调用 start() 都会自检并在需要时重新拉起。
 *  2. 原来只在第一次启动时枚举一次显示器。会话中途改分辨率 / 增删显示器 /
 *     虚拟屏重建后，1x1 像素会停留在旧坐标，可能落到**没被采集的那块屏**上，
 *     被采集的屏于是又回到「桌面静止」→ 掉帧。现在每秒对账一次显示器布局，
 *     布局一变就整组重建。
 *  3. 置顶可能被别的置顶窗口顶掉、窗口可能被隐藏。现在每秒重新断言一次
 *     TOPMOST + SHOWWINDOW，并用 IsWindow 检查句柄有效性。
 *  4. 15ms 定时原来用 sleep_for，受系统时钟精度影响可能被拉到 ~31ms（正好
 *     看着像 30fps）。现在优先用高精度可等待定时器
 *     （CREATE_WAITABLE_TIMER_HIGH_RESOLUTION），拿不到才退回 sleep_for。
 *  5. 加心跳：每 60 秒记一次实测脉冲频率；低于 40Hz 或窗口被重建时记 warning。
 *     以后再出问题，日志里能直接看出是「没在跑」还是「跑慢了」。
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include "frame_keepalive.h"
#include "src/logging.h"

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace platf::frame_keepalive {
  namespace {
    constexpr wchar_t kWindowClass[] = L"SunshineFrameKeepAlive";

    // 15ms ≈ 66Hz，留出余量保证不低于 60fps；再快只会白烧 CPU。
    constexpr int kIntervalMs = 15;

    // 两档只差 1/255 的暗色：DXGI 能看到差别，肉眼基本看不出。
    constexpr COLORREF kShadeA = RGB(0, 0, 0);
    constexpr COLORREF kShadeB = RGB(0, 0, 1);

    // 显示器布局对账间隔。EnumDisplayMonitors 只要几十微秒，一秒一次足够。
    constexpr auto kReconcilePeriod = std::chrono::seconds(1);

    // 心跳日志间隔。
    constexpr auto kReportPeriod = std::chrono::seconds(60);

    // 低于这个实测频率就认为保活没真正生效（60fps 需要至少 ~60）。
    constexpr double kMinHealthyHz = 40.0;

    std::mutex g_state_mutex;
    bool g_worker_alive {false};  // 受 g_state_mutex 保护
    std::atomic<bool> g_running {false};
    std::atomic<bool> g_shade {false};
    HBRUSH g_brush_a {nullptr};
    HBRUSH g_brush_b {nullptr};

    struct monitor_window {
      HMONITOR monitor {nullptr};
      HWND hwnd {nullptr};
      RECT rect {};
    };

    using pulse_clock = std::chrono::steady_clock;

    LRESULT CALLBACK keepalive_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
      switch (msg) {
        case WM_ERASEBKGND:
          // 交给 WM_PAINT 统一重绘，避免多一次擦除造成闪烁。
          return 1;

        case WM_PAINT: {
          PAINTSTRUCT ps;
          HDC dc = BeginPaint(hwnd, &ps);
          RECT rc;
          GetClientRect(hwnd, &rc);
          FillRect(dc, &rc, g_shade.load() ? g_brush_b : g_brush_a);
          EndPaint(hwnd, &ps);
          return 0;
        }

        default:
          return DefWindowProcW(hwnd, msg, wparam, lparam);
      }
    }

    BOOL CALLBACK collect_monitor(HMONITOR monitor, HDC, LPRECT, LPARAM lparam) {
      auto *out = reinterpret_cast<std::vector<RECT> *>(lparam);
      MONITORINFO info {};
      info.cbSize = sizeof(MONITORINFO);
      if (GetMonitorInfoW(monitor, &info)) {
        out->push_back(info.rcMonitor);
      }
      return TRUE;
    }

    std::vector<RECT> current_monitor_rects() {
      std::vector<RECT> monitors;
      EnumDisplayMonitors(nullptr, nullptr, collect_monitor, reinterpret_cast<LPARAM>(&monitors));
      if (monitors.empty()) {
        // 理论上不该发生；兜底放到虚拟桌面原点，至少还有一个像素在工作。
        monitors.push_back(RECT {0, 0, 1, 1});
      }
      // EnumDisplayMonitors 的回调顺序没有保证。不排序的话，顺序偶尔翻转就会被
      // 误判成「布局变了」，进而在每秒重建一次窗口。
      std::sort(monitors.begin(), monitors.end(), [](const RECT &a, const RECT &b) {
        if (a.top != b.top) {
          return a.top < b.top;
        }
        return a.left < b.left;
      });
      return monitors;
    }

    bool same_layout(const std::vector<monitor_window> &windows, const std::vector<RECT> &monitors) {
      if (windows.size() != monitors.size()) {
        return false;
      }
      for (std::size_t i = 0; i < monitors.size(); ++i) {
        const auto &a = windows[i].rect;
        const auto &b = monitors[i];
        if (a.left != b.left || a.top != b.top || a.right != b.right || a.bottom != b.bottom) {
          return false;
        }
      }
      return true;
    }

    void destroy_windows(std::vector<monitor_window> &windows) {
      for (auto &entry : windows) {
        if (entry.hwnd) {
          DestroyWindow(entry.hwnd);
        }
      }
      windows.clear();
    }

    /**
     * @brief 按当前显示器布局重建 1x1 像素窗。
     *
     * 整组重建而不是逐个对账：显示器变动不频繁，重建只是一次几毫秒的操作，
     * 但能彻底避免「窗口留在旧坐标」这类难查的半失效状态。
     */
    bool rebuild_windows(std::vector<monitor_window> &windows, HINSTANCE instance, const std::vector<RECT> &monitors) {
      destroy_windows(windows);
      for (const auto &rc : monitors) {
        HWND hwnd = CreateWindowExW(
          WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
          kWindowClass,
          L"",
          WS_POPUP,
          rc.left,
          rc.top,
          1,
          1,
          nullptr,
          nullptr,
          instance,
          nullptr);
        if (!hwnd) {
          BOOST_LOG(warning) << "Frame keep-alive: CreateWindowExW failed (" << GetLastError() << ")";
          continue;
        }
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        windows.push_back(monitor_window {nullptr, hwnd, rc});

        // DPI 虚拟化 / 坐标系不一致时窗口不会落在预期位置，而它一旦落错屏，
        // 被采集那块屏就完全收不到脏区域。这里核对一次，失配就记下来。
        RECT actual {};
        if (GetWindowRect(hwnd, &actual)) {
          if (actual.left != rc.left || actual.top != rc.top) {
            BOOST_LOG(warning) << "Frame keep-alive: keep-alive pixel placed at (" << actual.left << ',' << actual.top
                               << ") instead of (" << rc.left << ',' << rc.top << "); display may be DPI-virtualized";
          }
        }
      }
      return !windows.empty();
    }

    /** @brief 每秒一次的轻量维护：窗口还活着吗、还在最上层吗、布局变了没。 */
    void maintain(std::vector<monitor_window> &windows, HINSTANCE instance, bool &rebuilt) {
      for (auto &entry : windows) {
        if (!entry.hwnd || !IsWindow(entry.hwnd)) {
          entry.hwnd = nullptr;  // 交给 rebuild 处理
        }
      }
      const bool any_dead = [&windows] {
        for (const auto &entry : windows) {
          if (!entry.hwnd) {
            return true;
          }
        }
        return false;
      }();

      const auto monitors = current_monitor_rects();
      if (any_dead || !same_layout(windows, monitors)) {
        BOOST_LOG(info) << "Frame keep-alive: display layout changed (" << windows.size() << " -> "
                        << monitors.size() << " monitor(s)), rebuilding keep-alive windows";
        if (!rebuild_windows(windows, instance, monitors)) {
          BOOST_LOG(warning) << "Frame keep-alive: no window could be created after rebuild, feature inactive";
        }
        rebuilt = true;
        return;
      }

      // 重新断言置顶 + 可见。另一个置顶窗口（游戏/覆盖层）可能把像素顶到下面，
      // 被遮挡的窗口不再产生有意义的脏区域。
      for (auto &entry : windows) {
        if (!entry.hwnd) {
          continue;
        }
        if (!IsWindowVisible(entry.hwnd)) {
          ShowWindow(entry.hwnd, SW_SHOWNOACTIVATE);
        }
        SetWindowPos(entry.hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_SHOWWINDOW);
      }
    }

    void keepalive_worker() {
      const auto worker_start = pulse_clock::now();
      HINSTANCE instance = GetModuleHandleW(nullptr);

      WNDCLASSEXW wc {};
      wc.cbSize = sizeof(wc);
      wc.lpfnWndProc = keepalive_wnd_proc;
      wc.hInstance = instance;
      wc.lpszClassName = kWindowClass;
      if (!RegisterClassExW(&wc)) {
        const DWORD error = GetLastError();
        // 类已存在是可接受的（上一次工作线程留下的），其余错误才是真失败。
        if (error != ERROR_CLASS_ALREADY_EXISTS) {
          BOOST_LOG(warning) << "Frame keep-alive: RegisterClassExW failed (" << error << ")";
        }
      }

      g_brush_a = CreateSolidBrush(kShadeA);
      g_brush_b = CreateSolidBrush(kShadeB);
      if (!g_brush_a || !g_brush_b) {
        BOOST_LOG(warning) << "Frame keep-alive: CreateSolidBrush failed (" << GetLastError() << ")";
        goto cleanup;
      }

      {
        std::vector<monitor_window> windows;
        if (!rebuild_windows(windows, instance, current_monitor_rects())) {
          BOOST_LOG(warning) << "Frame keep-alive: no window could be created, feature inactive";
          goto cleanup;
        }

        BOOST_LOG(info) << "Frame keep-alive active: 1x1 pixel pulsing on " << windows.size()
                        << " monitor(s) at ~" << (1000 / kIntervalMs) << "Hz to keep the capture fed";

        // 高精度定时器：sleep_for(15ms) 在默认 15.625ms 时钟精度下可能被拉到
        // ~31ms，正好表现成「掉到 30fps」。拿不到高精度定时器才退回 sleep。
        HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        if (!timer) {
          timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS);
          if (timer) {
            BOOST_LOG(warning) << "Frame keep-alive: high-resolution timer unavailable, using standard timer";
          }
        }
        if (timer) {
          LARGE_INTEGER due {};
          due.QuadPart = -static_cast<LONGLONG>(kIntervalMs) * 10000LL;  // 相对时间，100ns 单位
          if (!SetWaitableTimer(timer, &due, kIntervalMs, nullptr, nullptr, FALSE)) {
            CloseHandle(timer);
            timer = nullptr;
          }
        }
        if (!timer) {
          BOOST_LOG(warning) << "Frame keep-alive: waitable timer unavailable, falling back to sleep_for";
        }

        auto last_reconcile = pulse_clock::now();
        auto last_report = pulse_clock::now();
        std::uint64_t pulses_since_report = 0;
        bool rebuilt = false;

        while (g_running.load()) {
          MSG msg;
          while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
          }

          const auto now = pulse_clock::now();
          if (now - last_reconcile >= kReconcilePeriod) {
            last_reconcile = now;
            maintain(windows, instance, rebuilt);
          }

          g_shade.store(!g_shade.load());
          bool pulse_failed = false;
          for (auto &entry : windows) {
            if (!entry.hwnd) {
              continue;
            }
            // 同步重绘：立刻把新的像素值提交给桌面合成器，产生一次真实脏区域。
            if (!InvalidateRect(entry.hwnd, nullptr, FALSE) || !UpdateWindow(entry.hwnd)) {
              pulse_failed = true;
            }
          }
          if (pulse_failed) {
            // 句柄失效时不在这里重建，交给 maintain 统一处理，避免两处竞态。
            for (auto &entry : windows) {
              if (entry.hwnd && !IsWindow(entry.hwnd)) {
                entry.hwnd = nullptr;
              }
            }
          }
          ++pulses_since_report;

          if (now - last_report >= kReportPeriod) {
            const auto elapsed = std::chrono::duration<double>(now - last_report).count();
            const double hz = elapsed > 0.0 ? static_cast<double>(pulses_since_report) / elapsed : 0.0;
            if (hz < kMinHealthyHz) {
              BOOST_LOG(warning) << "Frame keep-alive: only " << hz << " Hz over the last " << elapsed
                                 << "s on " << windows.size() << " monitor(s) — capture will starve";
            }
            else {
              BOOST_LOG(info) << "Frame keep-alive: " << hz << " Hz on " << windows.size() << " monitor(s)"
                              << (rebuilt ? " (rebuilt after display change)" : "");
            }
            rebuilt = false;
            last_report = now;
            pulses_since_report = 0;
          }

          if (timer) {
            WaitForSingleObject(timer, 100);
          }
          else {
            std::this_thread::sleep_for(std::chrono::milliseconds(kIntervalMs));
          }
        }

        if (timer) {
          CloseHandle(timer);
        }

        destroy_windows(windows);
      }

    cleanup:
      if (g_brush_a) {
        DeleteObject(g_brush_a);
        g_brush_a = nullptr;
      }
      if (g_brush_b) {
        DeleteObject(g_brush_b);
        g_brush_b = nullptr;
      }

      BOOST_LOG(info) << "Frame keep-alive stopped after "
                      << std::chrono::duration<double>(pulse_clock::now() - worker_start).count() << "s";

      // 允许下一次 start() 重新拉起（这是「失效必须重启 Sunshine」的根治点）。
      {
        std::lock_guard lock {g_state_mutex};
        g_worker_alive = false;
      }
    }
  }  // namespace

  void start() {
    std::lock_guard lock {g_state_mutex};
    if (g_worker_alive) {
      return;  // 健康，已经在跑
    }
    g_worker_alive = true;
    g_running.store(true);
    // detach：进程退出时不希望 std::thread 析构触发 terminate。
    std::thread {keepalive_worker}.detach();
  }

  void stop() {
    g_running.store(false);
  }
}  // namespace platf::frame_keepalive
