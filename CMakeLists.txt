cmake_minimum_required(VERSION 3.16)
project(netsim LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE NETSIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/device/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/link/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/engine/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/topo/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/netstack/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/app/*.cpp")

file(GLOB LUA_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua/*.c")
add_library(yanas_lua STATIC ${LUA_SOURCES})
target_include_directories(yanas_lua PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua")
target_compile_options(yanas_lua PRIVATE -w)

add_executable(netsim ${NETSIM_SOURCES}
    "${CMAKE_CURRENT_SOURCE_DIR}/script/LuaScript.cpp")
target_compile_options(netsim PRIVATE -Wall -Wextra -Werror)
target_include_directories(netsim PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua")
target_compile_definitions(netsim PRIVATE HAVE_LUA)
target_link_libraries(netsim PRIVATE yanas_lua)

if(UNIX)
    target_link_libraries(netsim PRIVATE m)
endif()
