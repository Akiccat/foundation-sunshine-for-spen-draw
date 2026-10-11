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
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

#include "frame_keepalive.h"
#include "src/logging.h"

namespace platf::frame_keepalive {
  namespace {
    constexpr wchar_t kWindowClass[] = L"SunshineFrameKeepAlive";

    // 15ms ≈ 66Hz，留出余量保证不低於 60fps；再快只会白烧 CPU。
    constexpr int kIntervalMs = 15;

    // 两档只差 1/255 的暗色：DXGI 能看到差别，肉眼基本看不出。
    constexpr COLORREF kShadeA = RGB(0, 0, 0);
    constexpr COLORREF kShadeB = RGB(0, 0, 1);

    std::once_flag g_start_once;
    std::mutex g_window_mutex;
    std::vector<HWND> g_windows;
    std::atomic<bool> g_running {false};
    std::atomic<bool> g_shade {false};
    HBRUSH g_brush_a {nullptr};
    HBRUSH g_brush_b {nullptr};

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

    void keepalive_worker() {
      HINSTANCE instance = GetModuleHandleW(nullptr);

      WNDCLASSEXW wc {};
      wc.cbSize = sizeof(wc);
      wc.lpfnWndProc = keepalive_wnd_proc;
      wc.hInstance = instance;
      wc.lpszClassName = kWindowClass;
      if (!RegisterClassExW(&wc)) {
        BOOST_LOG(warning) << "Frame keep-alive: RegisterClassExW failed (" << GetLastError() << ")";
        return;
      }

      g_brush_a = CreateSolidBrush(kShadeA);
      g_brush_b = CreateSolidBrush(kShadeB);
      if (!g_brush_a || !g_brush_b) {
        BOOST_LOG(warning) << "Frame keep-alive: CreateSolidBrush failed (" << GetLastError() << ")";
        return;
      }

      std::vector<RECT> monitors;
      EnumDisplayMonitors(nullptr, nullptr, collect_monitor, reinterpret_cast<LPARAM>(&monitors));
      if (monitors.empty()) {
        // 理论上不该发生；兜底放到虚拟桌面原点，至少还有一个像素在工作。
        monitors.push_back(RECT {0, 0, 1, 1});
      }

      {
        std::lock_guard lock {g_window_mutex};
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
          g_windows.push_back(hwnd);
        }
      }

      if (g_windows.empty()) {
        BOOST_LOG(warning) << "Frame keep-alive: no window could be created, feature inactive";
        return;
      }

      BOOST_LOG(info) << "Frame keep-alive active: 1x1 pixel pulsing on " << g_windows.size()
                      << " monitor(s) at ~" << (1000 / kIntervalMs) << "Hz to keep the capture fed";

      while (g_running.load()) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
          TranslateMessage(&msg);
          DispatchMessageW(&msg);
        }

        {
          std::lock_guard lock {g_window_mutex};
          g_shade.store(!g_shade.load());
          for (HWND hwnd : g_windows) {
            InvalidateRect(hwnd, nullptr, FALSE);
            // 同步重绘：立刻把新的像素值提交给桌面合成器，产生一次真实脏区域。
            UpdateWindow(hwnd);
          }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(kIntervalMs));
      }

      {
        std::lock_guard lock {g_window_mutex};
        for (HWND hwnd : g_windows) {
          DestroyWindow(hwnd);
        }
        g_windows.clear();
      }

      if (g_brush_a) {
        DeleteObject(g_brush_a);
        g_brush_a = nullptr;
      }
      if (g_brush_b) {
        DeleteObject(g_brush_b);
        g_brush_b = nullptr;
      }
    }
  }  // namespace

  void start() {
    std::call_once(g_start_once, []() {
      g_running.store(true);
      std::thread {keepalive_worker}.detach();
    });
  }

  void stop() {
    g_running.store(false);
  }
}  // namespace platf::frame_keepalive
