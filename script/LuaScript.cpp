#include "LuaScript.hpp"
#include "../topo/CommandRunner.hpp"
#include "../engine/Engine.hpp"
#include "../topo/Topology.hpp"
#include <lua.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <exception>
#include <cstddef>

namespace
{
    constexpr std::streamoff kMaxScriptBytes = 4 * 1024 * 1024;
    constexpr long long kInstructionBudget = 50000000;
    long long g_luaBudget = 0;

    void LuaBudgetHook(lua_State *L, lua_Debug *)
    {
        g_luaBudget -= 1000;
        if(g_luaBudget <= 0)
            (void)luaL_error(L, "lua script exceeded the instruction budget");
    }

    void OpenSafeLibs(lua_State *L)
    {
        luaL_requiref(L, LUA_GNAME, luaopen_base, 1);        lua_pop(L, 1);
        luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);  lua_pop(L, 1);
        luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1); lua_pop(L, 1);
        luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);  lua_pop(L, 1);
        luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);  lua_pop(L, 1);
        luaL_requiref(L, LUA_COLIBNAME, luaopen_coroutine, 1); lua_pop(L, 1);

        const char *blocked[] = { "dofile", "loadfile", "load", "require" };
        for(const char *name : blocked)
        {
            lua_pushnil(L);
            lua_setglobal(L, name);
        }
    }

    struct LuaCtx
    {
        CommandContext *cmd;
    };

    int L_exec(lua_State *L)
    {
        auto *ctx = static_cast<LuaCtx *>(lua_touserdata(L, lua_upvalueindex(1)));
        const char *line = luaL_checkstring(L, 1);
        try
        {
            RunScriptLine(*ctx->cmd, line);
        }
        catch (const std::exception &e)
        {
            return luaL_error(L, "%s", e.what());
        }
        return 0;
    }

    int L_run(lua_State *L)
    {
        auto *ctx = static_cast<LuaCtx *>(lua_touserdata(L, lua_upvalueindex(1)));
        ctx->cmd->engine->Run();
        return 0;
    }

    int L_log(lua_State *L)
    {
        int n = lua_gettop(L);
        for (int i = 1; i <= n; i++)
        {
            std::size_t len = 0;
            const char *s = luaL_tolstring(L, i, &len);
            if (i > 1) std::cout << ' ';
            std::cout << s;
            lua_pop(L, 1);
        }
        std::cout << "\n";
        return 0;
    }
}

bool RunLuaFile(Engine &engine, Topology &topo, const std::string &path, std::string &err)
{
    CommandContext cmd;
    cmd.engine = &engine;
    cmd.topo = &topo;

    LuaCtx ctx;
    ctx.cmd = &cmd;

    lua_State *L = luaL_newstate();
    if (!L)
    {
        err = "cannot create lua state";
        return false;
    }
    OpenSafeLibs(L);
    g_luaBudget = kInstructionBudget;
    lua_sethook(L, LuaBudgetHook, LUA_MASKCOUNT, 1000);

    lua_pushlightuserdata(L, &ctx);
    lua_pushcclosure(L, L_exec, 1);
    lua_setglobal(L, "exec");

    lua_pushlightuserdata(L, &ctx);
    lua_pushcclosure(L, L_run, 1);
    lua_setglobal(L, "run");

    lua_pushcfunction(L, L_log);
    lua_setglobal(L, "log");

    lua_pushcfunction(L, L_log);
    lua_setglobal(L, "print");

    {
        std::ifstream probe(path, std::ios::binary | std::ios::ate);
        if(!probe)
        {
            err = "cannot open '" + path + "'";
            lua_close(L);
            return false;
        }
        std::streamoff size = probe.tellg();
        if(size < 0 || size > kMaxScriptBytes)
        {
            err = "lua script too large (limit 4 MiB)";
            lua_close(L);
            return false;
        }
    }

    if (luaL_loadfile(L, path.c_str()) != LUA_OK)
    {
        const char *m = lua_tostring(L, -1);
        err = m ? m : "load error";
        lua_close(L);
        return false;
    }

    if (lua_pcall(L, 0, 0, 0) != LUA_OK)
    {
        const char *m = lua_tostring(L, -1);
        err = m ? m : "runtime error";
        lua_close(L);
        return false;
    }

    lua_close(L);
    return true;
}
