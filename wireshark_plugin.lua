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

local function add_table_to_tree(tree, tbl, offset, buffer, is_list_item)
    -- If it's a list item, we don't need to sort keys necessarily, but for tables we might
    local keys = {}
    for k in pairs(tbl) do
        if type(k) == "number" or (type(k) == "string" and k:sub(1, 2) ~= "__") then
            table.insert(keys, k)
        end
    end
    -- Sort keys for better readability (strings then numbers, or customizable)
    table.sort(keys, function(a, b)
        if type(a) == type(b) then return a < b end
        return type(a) == "string"
    end)

    for _, k in ipairs(keys) do
        local v = tbl[k]
        if type(v) == "table" then
            local subtree_name = tostring(k)
            if type(k) == "string" and tbl["__doc_" .. k] then
                subtree_name = tbl["__doc_" .. k] .. " (" .. k .. ")"
            elseif type(k) == "number" and is_list_item then
                subtree_name = "Item " .. tostring(k)
            end
            
            local subtree
            -- Use the actual length if the rust module provided it via `__len`
            if v.__len then
                subtree = tree:add(my_proto, buffer(offset, v.__len), subtree_name)
                offset = offset + v.__len
            else
                local field_offset = offset
                local field_len = 0
                if type(k) == "string" and tbl["__offset_" .. k] and tbl["__len_" .. k] then
                    field_offset = offset + tonumber(tbl["__offset_" .. k])
                    field_len = tonumber(tbl["__len_" .. k])
                end
                
                if field_len > 0 then
                    subtree = tree:add(my_proto, buffer(field_offset, field_len), subtree_name)
                else
                    subtree = tree:add(my_proto, buffer(offset), subtree_name)
                end
            end
            
            -- Pass true if this is a list containing only numeric keys
            local child_is_list = false
            if v[1] ~= nil then child_is_list = true end
            
            if v.__len then
                add_table_to_tree(subtree, v, offset - v.__len, buffer, child_is_list)
            else
                add_table_to_tree(subtree, v, offset, buffer, child_is_list)
            end
        else
            if type(k) == "string" and k:sub(1, 2) == "__" then
                -- Skip internal keys
            else
                local title = tostring(k)
                local val_str = tostring(v)
                
                if type(k) == "string" then
                    local doc_str = tbl["__doc_" .. k]
                    local q_str = tbl["__quantum_" .. k]
                    local enum_str = tbl["__enum_" .. k]
                    
                    if enum_str then
                        val_str = string.format("%s (%s)", enum_str, tostring(v))
                    elseif q_str then
                        -- Quantum is expressed as e.g. "1/256 NM" or "1 s"
                        -- We can use a simple pattern to extract float values
                        local num, den, unit = string.match(q_str, "(%d+)/(%d+)%s*(.*)")
                        if num and den then
                            local multiplier = tonumber(num) / tonumber(den)
                            local float_val = tonumber(v) * multiplier
                            val_str = string.format("%g %s (raw: %s)", float_val, unit or "", tostring(v))
                        else
                            local num2, unit2 = string.match(q_str, "(%d+%.?%d*)%s*(.*)")
                            if num2 then
                                local float_val = tonumber(v) * tonumber(num2)
                                val_str = string.format("%g %s (raw: %s)", float_val, unit2 or "", tostring(v))
                            else
                                val_str = string.format("%s [%s]", tostring(v), q_str)
                            end
                        end
                    elseif type(v) == "number" then
                        val_str = string.format("%s (0x%X)", tostring(v), v)
                    end
                    
                    if doc_str then
                        title = doc_str .. " (" .. k .. ")"
                    end
                end
                
                local field_offset = offset
                local field_len = 0
                
                if type(k) == "string" then
                    if tbl["__offset_" .. k] then field_offset = offset + tonumber(tbl["__offset_" .. k]) end
                    if tbl["__len_" .. k]    then field_len    = tonumber(tbl["__len_" .. k]) end
                end
                
                if field_len > 0 then
                    tree:add(my_proto, buffer(field_offset, field_len), string.format("%s: %s", title, val_str))
                else
                    tree:add(my_proto, buffer(field_offset), string.format("%s: %s", title, val_str))
                end
            end
        end
    end
end

local f_udp_payload = Field.new("udp.payload")

function my_proto.dissector(buffer, pinfo, tree)
    -- As a post-dissector, `buffer` is the full root frame. 
    -- We want only the UDP payload for ASTERIX.
    local udp_payload_info = f_udp_payload()
    if not udp_payload_info then return end -- Not a UDP packet or no payload
    
    local payload_tvb = udp_payload_info.range
    local len = payload_tvb:len()
    if len < 3 then return end
    
    -- Pass the raw UDP bytes to Rust
    local ret_table = dsl_lib.dissect_packet(protocol_userdata, payload_tvb:raw())
    
    if type(ret_table) == "table" and ret_table["Transport Header"] then
        -- Validate heuristic Transport
        local t_len = ret_table.__transport_len
        if t_len and t_len > 0 and t_len <= len then
            -- Override protocol column
            pinfo.cols.protocol = "AIProtoDSL"
            
            -- Add Tree directly attached to the UDP payload range
            local subtree = tree:add(my_proto, payload_tvb, "Dynamic Protocol Data (Cat " .. tostring(ret_table["Transport Header"].category) .. ")")
            
            if ret_table.__error then
                subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Rust failed to dissect: " .. ret_table.__error)
            else
                add_table_to_tree(subtree, ret_table, 0, payload_tvb, false)
            end
        end
    end
end

-- Safely and universally register as a post-dissector.
-- This ensures we don't fight with Wireshark's native Asterix dissector 
-- and we evaluate all UDP packets universally!
register_postdissector(my_proto)
