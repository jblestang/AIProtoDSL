-- Standard Wireshark Lua Dissector Using Rust mlua
-- We must load the dynamic library natively using `package.loadlib`.
-- Wait, actually in Lua 5.4, simply `require("aiprotodsl")` works perfectly 
-- IF the module is in the LUA_CPATH, but giving the exact path is safer for testing.

-- Compute absolute path to the current script's directory
local script_dir = "/Users/jean-baptiste/RPP/AIProtoDSL"

local os_name = package.config:sub(1,1) == "\\" and "windows" or "unix"
local lib_path = ""
if os_name == "windows" then
    lib_path = script_dir .. "/target/debug/aiprotodsl.dll"
else
    local f = io.open(script_dir .. "/target/debug/libaiprotodsl.dylib", "r")
    if f then 
        f:close()
        lib_path = script_dir .. "/target/debug/libaiprotodsl.dylib"
    else
        lib_path = script_dir .. "/target/debug/libaiprotodsl.so"
    end
end

print("[Native Lua] Loading module from: " .. lib_path)
local load_func, err = package.loadlib(lib_path, "luaopen_aiprotodsl")

if not load_func then
    error("[Native Lua] Failed to load native library: " .. tostring(err))
end

-- Execute the initializer to get the `exports` table our Rust returned
local dsl_lib = load_func()

local dsl_file = script_dir .. "/examples/asterix_family.dsl"
print("[Native Lua] Loading DSL schema from: " .. dsl_file)
local protocol_userdata = dsl_lib.load_dsl(dsl_file)

if not protocol_userdata then
    error("[Native Lua] Failed to parse and load the DSL file in Rust!")
end

local my_proto = Proto("aiprotodsl", "AIProtoDSL Native Dissector")

function add_table_to_tree(tree, t, offset, buffer, is_array)
    for k, v in pairs(t) do
        if type(v) == "table" then
            if type(k) == "number" or is_array then
                local arr_tree = tree:add(my_proto, buffer(offset), "Item " .. tostring(k))
                add_table_to_tree(arr_tree, v, offset, buffer, k == "payloads")
            else
                local sub = tree:add(my_proto, buffer(offset), tostring(k))
                add_table_to_tree(sub, v, offset, buffer, k == "payloads")
            end
        else
            -- It's a primitive value
            -- For keys starting with __ (metadata), we might display them differently or skip
            if type(k) == "string" and string.sub(k, 1, 2) == "__" then
                if k == "__message_type" then
                    tree:add(my_proto, buffer(offset), "Message Type: " .. tostring(v))
                elseif k == "__error" then
                    tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Error: " .. tostring(v))
                end
                -- skip others like __len
            else
                local val_str = tostring(v)
                if type(v) == "number" then
                    val_str = string.format("%d (0x%X)", v, v)
                end
                tree:add(my_proto, buffer(offset), string.format("%s: %s", tostring(k), val_str))
            end
        end
    end
end

function my_proto.dissector(buffer, pinfo, tree)
    -- print(string.format("[Native Lua] Dissecting %d bytes on port %d", buffer:len(), pinfo.dst_port))
    pinfo.cols.protocol = "AIProtoDSL"
    local subtree = tree:add(my_proto, buffer(), "Dynamic Protocol Data")
    
    -- In standard Lua binding, `buffer:raw()` returns a standard Lua string
    -- which `mlua` can map over effortlessly to standard u8 slices.
    local ret_table = dsl_lib.dissect_packet(protocol_userdata, buffer:raw())
    
    if type(ret_table) == "table" then
        if ret_table.__error then
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Rust failed to dissect packet: " .. ret_table.__error)
        else
            add_table_to_tree(subtree, ret_table, 0, buffer, false)
        end
    else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Rust returned invalid type")
    end
end

-- Register as postdissector so we can catch it anywhere (default dissectors run first)
register_postdissector(my_proto)
