cmake_minimum_required(VERSION 3.20)
project(footprint-audit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/utf-8)
endif()

add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

include(FetchContent)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.91.5
)

FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(imgui json)

file(GLOB_RECURSE APP_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

set(APP_RESOURCES "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/app.rc")
    list(APPEND APP_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/app.rc")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/assets/resources.rc")
    list(APPEND APP_RESOURCES "${CMAKE_CURRENT_SOURCE_DIR}/assets/resources.rc")
endif()

set(IMGUI_SOURCES
    "${imgui_SOURCE_DIR}/imgui.cpp"
    "${imgui_SOURCE_DIR}/imgui_demo.cpp"
    "${imgui_SOURCE_DIR}/imgui_draw.cpp"
    "${imgui_SOURCE_DIR}/imgui_tables.cpp"
    "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
)

add_executable(footprint-audit WIN32
    ${APP_SOURCES}
    ${IMGUI_SOURCES}
    ${APP_RESOURCES}
)

if(MSVC)
    target_compile_options(footprint-audit PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/FIwindows.h>)
endif()

target_include_directories(footprint-audit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/app"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/network"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ui"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/views"
    "${imgui_SOURCE_DIR}"
    "${imgui_SOURCE_DIR}/backends"
)

target_link_libraries(footprint-audit PRIVATE
    nlohmann_json::nlohmann_json
    d3d11
    dxgi
    d3dcompiler
    winhttp
    crypt32
    bcrypt
    shell32
    dwmapi
    windowscodecs
    ole32
    comdlg32
)