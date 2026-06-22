#include <windows.h>
#include <string>
#include <ctime>
#include <gdiplus.h>

#pragma comment(lib, "gdiplus.lib")  // 链接 GDI+ 库

using namespace Gdiplus;

const wchar_t* CLASS_NAME = L"ScreenWatermarkClass";

// 窗口过程函数
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // 每秒刷新一次时间
        SetTimer(hwnd, 1, 1000, NULL);
        return 0;
    }
    case WM_TIMER: {
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_ERASEBKGND: {
        // 阻止系统擦除背景（避免闪烁）
        return TRUE;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rect;
        GetClientRect(hwnd, &rect);
        int width = rect.right;
        int height = rect.bottom;

        // 1. 获取屏幕 DC（用于最终合成）
        HDC hdcScreen = GetDC(hwnd);

        // 2. 创建 32 位内存位图（支持 Alpha 通道）
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height;  // 负值表示自上而下
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;      // 32位色深
        bmi.bmiHeader.biCompression = BI_RGB;

        VOID* pvBits = nullptr;
        HBITMAP hbm = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pvBits, nullptr, 0);
        HGDIOBJ hOld = SelectObject(hdcMem, hbm);

        // 3. 用 GDI+ 在内存位图上绘制
        Graphics graphics(hdcMem);

        // ★★★ 关键：先把整个位图清空为“完全透明”（Alpha = 0）
        graphics.Clear(Color(0, 0, 0, 0));

        // 开启抗锯齿，让字体边缘平滑
        graphics.SetTextRenderingHint(TextRenderingHintAntiAlias);

        // 4. 获取当前时间字符串
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timeBuffer[128];
        swprintf_s(timeBuffer, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

        // 5. 创建字体（Segoe UI 比雅黑更精致）
        Font font(L"Segoe UI", 19, FontStyleBold);

        // ★★★ 核心：设置文字透明度（Alpha 值）
        // 范围 0（完全透明）~ 255（完全不透明）
        // 这里设为 180，表示约 70% 不透明度，文字半透明显露背后窗口
        int alpha = 20;
        Color textColor(alpha, 1, 1, 1);  // Alpha, R, G, B

        // 阴影颜色（半透明黑色，增加立体感）
        Color shadowColor(30, 0, 0, 0);

        // 6. 平铺绘制（倾斜 30 度）
        int stepX = 240, stepY = 160;
        for (int x = 0; x < width + stepX; x += stepX) {
            for (int y = 0; y < height + stepY; y += stepY) {
                int offsetX = (y / stepY) % 2 == 0 ? 0 : (stepX / 2);

                // 先绘制阴影（向右下偏移 3 像素）
                //SolidBrush shadowBrush(shadowColor);
                //graphics.ResetTransform();  // 重置变换
                //graphics.TranslateTransform((REAL)(x + offsetX + 3), (REAL)(y + 3));
                //graphics.RotateTransform(-30.0f);  // 逆时针旋转30度（与第一版一致）
                //graphics.DrawString(timeBuffer, -1, &font, PointF(0, 0), &shadowBrush);



                // 再绘制主体文字（半透明红色）
                SolidBrush textBrush(textColor);
                graphics.ResetTransform();
                graphics.TranslateTransform((REAL)(x + offsetX), (REAL)y);
                graphics.RotateTransform(-30.0f);
                graphics.DrawString(timeBuffer, -1, &font, PointF(0, 0), &textBrush);

            }
        }
        graphics.ResetTransform();
        // 7. 使用 UpdateLayeredWindow 将内存位图合成到屏幕
        SIZE size = { width, height };
        POINT ptSrc = { 0, 0 };
        POINT ptDst = { 0, 0 };
        BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };

        UpdateLayeredWindow(hwnd, hdcScreen, &ptDst, &size, hdcMem, &ptSrc, 0, &bf, ULW_ALPHA);

        // 8. 清理资源
        ReleaseDC(hwnd, hdcScreen);
        SelectObject(hdcMem, hOld);
        DeleteObject(hbm);
        DeleteDC(hdcMem);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY: {
        KillTimer(hwnd, 1);
        PostQuitMessage(0);
        return 0;
    }
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // ★★★ 初始化 GDI+（必须先执行）
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // 注册窗口类
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);

    RegisterClass(&wc);

    // 创建全屏分层窗口
    HWND hwnd = CreateWindowEx(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        CLASS_NAME,
        L"Watermark",
        WS_POPUP,
        0, 0,
        GetSystemMetrics(SM_CXSCREEN),
        GetSystemMetrics(SM_CYSCREEN),
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hwnd) {
        GdiplusShutdown(gdiplusToken);
        return 0;
    }
    // 在 CreateWindowEx 之后，ShowWindow 之前
    if (!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
        //return 0;
        // 处理错误，可能是系统版本过低
    }
    // ★★★ 注意：这里不再调用 SetLayeredWindowAttributes，透明度完全由位图的 Alpha 通道控制
    // 窗口本身完全由 UpdateLayeredWindow 动态绘制

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // 消息循环
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 清理 GDI+
    GdiplusShutdown(gdiplusToken);
    return 0;
}