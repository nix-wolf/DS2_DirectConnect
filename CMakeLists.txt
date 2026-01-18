cmake_minimum_required(VERSION 3.30)
project(DS2_DirectConnect)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG        master
)
FetchContent_MakeAvailable(minhook)

include_directories(${minhook_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)

add_library(version SHARED library.cpp)

target_link_libraries(version
        PRIVATE
        minhook
        ole32.lib
        user32.lib
        kernel32.lib
        uuid.lib
)

if(MSVC)
    target_compile_options(version PRIVATE /W3 /MP)
endif()
