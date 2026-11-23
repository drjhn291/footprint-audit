#include "app/Application.hpp"
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    app::Application application(hInstance);
    int exitCode = application.Run();
    CoUninitialize();
    return exitCode;
}