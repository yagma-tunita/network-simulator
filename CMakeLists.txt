cmake_minimum_required(VERSION 3.16)
project(netsim LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror)

file(GLOB_RECURSE NETSIM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/device/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/link/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/engine/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/topo/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/app/*.cpp")

add_executable(netsim ${NETSIM_SOURCES})

include(FindPkgConfig)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LUA QUIET lua5.4)
endif()

if(LUA_FOUND)
    target_sources(netsim PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/script/LuaScript.cpp")
    target_include_directories(netsim PRIVATE ${LUA_INCLUDE_DIRS})
    target_link_directories(netsim PRIVATE ${LUA_LIBRARY_DIRS})
    target_link_libraries(netsim PRIVATE ${LUA_LIBRARIES})
    target_compile_definitions(netsim PRIVATE HAVE_LUA)
endif()
