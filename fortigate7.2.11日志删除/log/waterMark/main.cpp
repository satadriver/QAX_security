#include <windows.h>
#include <string>
#include <ctime>

// 窗口类名
const wchar_t* CLASS_NAME = L"ScreenWatermarkClass";

// 全局变量：透明色键（黑色）
const COLORREF TRANSPARENT_COLOR = RGB(0, 0, 0);

// 窗口过程函数
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // 1. 创建定时器，每1000毫秒（1秒）刷新一次窗口
        SetTimer(hwnd, 1, 3000, NULL);
        return 0;
    }

    case WM_TIMER: {
        // 2. 定时器触发时，强制窗口重绘（不擦除背景，由我们自己控制）
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_ERASEBKGND: {
        // 3. 阻止系统默认擦除背景（防止闪烁），我们自己在 WM_PAINT 中绘制
        return TRUE;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rect;
        GetClientRect(hwnd, &rect);

        // 1. 用透明色（黑色）填充背景
        HBRUSH hBrush = CreateSolidBrush(TRANSPARENT_COLOR);
        FillRect(hdc, &rect, hBrush);
        DeleteObject(hBrush);

        // 2. 获取当前时间字符串
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timeBuffer[128];
        swprintf_s(timeBuffer, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        // 3. 【核心升级】直接构造 LOGFONT，精确控制字体质量
        LOGFONT lf = {};
        lf.lfHeight = 56;                // 稍微放大一点更显精致
        lf.lfWeight = FW_BOLD;           // 粗体
        lf.lfQuality = CLEARTYPE_QUALITY; // ★★★ 开启 ClearType 抗锯齿，边缘平滑如丝
        lf.lfEscapement = -300;          // 倾斜 30 度
        lf.lfItalic = FALSE;
        lf.lfUnderline = FALSE;
        lf.lfStrikeOut = FALSE;
        wcscpy_s(lf.lfFaceName, L"Segoe UI"); // ★★★ 改用微软现代字体（比雅黑更精致）

        HFONT hFont = CreateFontIndirect(&lf);
        SelectObject(hdc, hFont);

        // 设置文字背景透明
        SetBkMode(hdc, TRANSPARENT);

        // 平铺参数
        int stepX = 320;
        int stepY = 240;

        // 4. ★★★ 绘制两层文字（阴影 + 主体），打造立体质感
        for (int x = 0; x < rect.right + stepX; x += stepX) {
            for (int y = 0; y < rect.bottom + stepY; y += stepY) {
                int offsetX = (y / stepY) % 2 == 0 ? 0 : (stepX / 2);

                // ---- 第一层：阴影（深红色，向右下偏移 2 像素） ----
                SetTextColor(hdc, RGB(80, 0, 0)); // 暗红色
                TextOutW(hdc, x + offsetX + 2, y + 2, timeBuffer, wcslen(timeBuffer));

                // ---- 第二层：主体（亮红色，带一点橙色调更柔和） ----
                SetTextColor(hdc, RGB(255, 60, 60)); // 亮红偏橙，不刺眼
                TextOutW(hdc, x + offsetX, y, timeBuffer, wcslen(timeBuffer));
            }
        }

        // 清理资源
        DeleteObject(hFont);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY: {
        KillTimer(hwnd, 1);  // 销毁定时器
        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // 1. 注册窗口类
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH); // 这里填黑色便于色键透明

    RegisterClass(&wc);

    // 2. 创建全屏窗口
    HWND hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        // WS_EX_LAYERED    : 分层窗口（实现透明）
        // WS_EX_TOPMOST    : 置顶，覆盖所有窗口
        // WS_EX_TRANSPARENT: 鼠标点击穿透，不影响操作
        // WS_EX_TOOLWINDOW : 不出现在任务栏和 Alt+Tab
        CLASS_NAME,
        L"Watermark",
        WS_POPUP,                                  // 无边框
        0, 0,                                      // X, Y
        GetSystemMetrics(SM_CXSCREEN),             // 宽度（全屏）
        GetSystemMetrics(SM_CYSCREEN),             // 高度（全屏）
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hwnd) {
        return 0;
    }

    // 3. 设置分层窗口属性：黑色变为完全透明，透明度为 255（不透明）
    // 参数含义：透明色键=黑色，透明度=255，同时启用色键和半透明属性
    SetLayeredWindowAttributes(hwnd, TRANSPARENT_COLOR, 255, LWA_ALPHA | LWA_COLORKEY);

    // 4. 显示窗口
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // 5. 消息循环
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}