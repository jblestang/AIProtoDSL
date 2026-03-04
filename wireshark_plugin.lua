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

local proto_fields = {}
local fields_meta = protocol_userdata:get_all_fields()
local ftype_map = {
    uint8 = ProtoField.uint8,
    uint16 = ProtoField.uint16,
    uint32 = ProtoField.uint32,
    uint64 = ProtoField.uint64,
    int8 = ProtoField.int8,
    int16 = ProtoField.int16,
    int32 = ProtoField.int32,
    int64 = ProtoField.int64,
    bool = ProtoField.bool,
    float = ProtoField.float,
    double = ProtoField.double,
}

local registered_fields = {}
for _, f in ipairs(fields_meta) do
    local ftype_func = ftype_map[f.type] or ProtoField.uint64
    local abbr = "aip_v3." .. f.name
    local name = f.name
    
    local pf
    if f.type == "bool" then
        pf = ftype_func(abbr, name, nil, f.enum, nil, f.doc)
    elseif f.type == "float" or f.type == "double" then
        pf = ftype_func(abbr, name, nil, nil, nil, f.doc)
    else
        pf = ftype_func(abbr, name, base.DEC, f.enum, nil, f.doc)
    end
    
    -- Store constraints in a way that we can access them during dissection
    proto_fields[f.name] = {
        pf = pf,
        ranges = f.ranges
    }
    table.insert(registered_fields, pf)
end
my_proto.fields = registered_fields

local function is_empty_tree(tbl)
    if type(tbl) ~= "table" then return false end
    for k, v in pairs(tbl) do
        if type(k) == "number" or (type(k) == "string" and k:sub(1, 2) ~= "__") then
            if type(v) == "table" then
                if not is_empty_tree(v) then return false end
            else
                return false
            end
        end
    end
    return true
end

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
        
        -- Default: do not skip
        local skip = false
        if type(v) == "table" and is_empty_tree(v) then
            skip = true
        elseif type(v) == "string" and v == "" then
            skip = true
        end
        
        if not skip then
            if type(v) == "table" then
                local subtree_name = tostring(k)
                if type(k) == "string" and tbl["__doc_" .. k] then
                    subtree_name = k .. " (" .. tbl["__doc_" .. k] .. ")"
                elseif type(k) == "number" and is_list_item then
                    subtree_name = "Item " .. tostring(k)
                end
                
                local subtree
                -- Use the actual length if the rust module provided it via `__len`
                if v.__len then
                    subtree = tree:add(buffer(offset, v.__len), subtree_name)
                    offset = offset + v.__len
                else
                    local field_offset = offset
                    local field_len = 0
                    if type(k) == "string" and tbl["__offset_" .. k] and tbl["__len_" .. k] then
                        field_offset = tonumber(tbl["__offset_" .. k])
                        field_len = tonumber(tbl["__len_" .. k])
                    end
                    
                    if field_offset >= buffer:len() then
                        field_offset = buffer:len() - 1
                        field_len = 0
                    end
                    if field_offset + field_len > buffer:len() then
                        field_len = buffer:len() - field_offset
                    end
                    
                    if field_len > 0 then
                        subtree = tree:add(buffer(field_offset, field_len), subtree_name)
                    else
                        subtree = tree:add(buffer(field_offset, 1), subtree_name .. " [Truncated]")
                    end
                end
                
                if subtree and type(subtree) ~= "string" then
                    local new_offset = offset
                    if v.__len then new_offset = offset end
                    add_table_to_tree(subtree, v, new_offset, buffer, child_is_list)
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
                        
                        if doc_str and doc_str ~= "" then
                            doc_str = "(" .. doc_str .. ")"
                        else
                            doc_str = ""
                        end

                        if enum_str then
                            val_str = string.format("%s %s (%s)", enum_str, doc_str, tostring(v))
                        elseif q_str then
                            -- Parse fractions like "1/256 NM" or floats like "0.5 s"
                            local num, den, unit = string.match(q_str, "(%-?%d+%.?%d*)/(%-?%d+%.?%d*)%s*(.*)")
                            if num and den then
                                local multiplier = tonumber(num) / tonumber(den)
                                local float_val = tonumber(v) * multiplier
                                val_str = string.format("%g %s %s (%s)", float_val, unit or "", doc_str, tostring(v))
                            else
                                local num2, unit2 = string.match(q_str, "(%-?%d+%.?%d*)%s*(.*)")
                                if num2 then
                                    local float_val = tonumber(v) * tonumber(num2)
                                    val_str = string.format("%g %s %s (%s)", float_val, unit2 or "", doc_str, tostring(v))
                                else
                                    val_str = string.format("%s %s (%s)", tostring(v), doc_str, q_str)
                                end
                            end
                        elseif type(v) == "number" then
                            if doc_str ~= "" then
                                val_str = string.format("%s %s", tostring(v), doc_str)
                            else
                                val_str = tostring(v)
                            end
                        end
                        
                        if doc_str and doc_str ~= "" then
                            title = k .. " (" .. doc_str .. ")"
                        end
                    end
                    
                    local field_offset = offset
                    local field_len = 0
                    
                    if type(k) == "string" then
                        if tbl["__offset_" .. k] then field_offset = tonumber(tbl["__offset_" .. k]) end
                        if tbl["__len_" .. k]    then field_len    = tonumber(tbl["__len_" .. k]) end
                    end
                    
                    if field_offset >= buffer:len() then
                        field_offset = buffer:len() - 1
                        field_len = 0
                    end
                    if field_offset + field_len > buffer:len() then
                        field_len = buffer:len() - field_offset
                    end

                    local function check_ranges(val, ranges)
                        if not ranges or #ranges == 0 then return true end
                        local num = tonumber(val)
                        if not num then return true end
                        for _, r in ipairs(ranges) do
                            if num >= r.min and num <= r.max then
                                return true
                            end
                        end
                        return false
                    end

                    local function safe_add(t, f, b, v, s, field_key)
                        if type(t) ~= "userdata" then return nil end
                        local status, res = pcall(function()
                            if f then
                                return t:add(f, b, v, s)
                            else
                                return t:add(my_proto, b, s)
                            end
                        end)
                        if not status then
                            return nil
                        end

                        if res and field_key and proto_fields[field_key] then
                            local constraints = proto_fields[field_key].ranges
                            if constraints and #constraints > 0 then
                                if not check_ranges(v, constraints) then
                                    res:add_expert_info(PI_MALFORMED, PI_WARN, "Value " .. tostring(v) .. " is out of DSL range")
                                end
                            end
                        end
                        return res
                    end

                    if field_len > 0 then
                            if proto_fields[k] then
                                local val = v
                                if type(val) == "boolean" then val = val and 1 or 0 end
                                local label = string.format("%s: %s", proto_fields[k].pf.name, val_str)
                                safe_add(tree, proto_fields[k].pf, buffer(field_offset, field_len), val, label, k)
                            else
                                safe_add(tree, nil, buffer(field_offset, field_len), nil, string.format("%s: %s", title, val_str))
                            end
                        else
                            if buffer:len() > 0 then
                                if proto_fields[k] then
                                    local val = v
                                    if type(val) == "boolean" then val = val and 1 or 0 end
                                    local label = string.format("%s: %s [Truncated]", proto_fields[k].pf.name, val_str)
                                    safe_add(tree, proto_fields[k].pf, buffer(field_offset, 1), val, label, k)
                                else
                                    safe_add(tree, nil, buffer(field_offset, 1), nil, string.format("%s: %s [Truncated]", title, val_str))
                                end
                            else
                                safe_add(tree, nil, nil, nil, string.format("%s: %s [No Buffer Data]", title, val_str))
                            end
                        end
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
    local ret_tables = dsl_lib.dissect_packet(protocol_userdata, payload_tvb:raw())
    
    if type(ret_tables) == "table" then
        -- Iterate over array of transport blocks returned by Rust
        for i, ret_table in ipairs(ret_tables) do
            if type(ret_table) == "table" and ret_table["Transport Header"] then
                local t_len = ret_table.__block_len or ret_table.__transport_len
                local offset = ret_table["Transport Header"].__offset_Transport_Header or 0
                if type(offset) ~= "number" then offset = 0 end
                
                if t_len and t_len > 0 and (offset + t_len) <= len then
                    pinfo.cols.protocol = "AIProtoDSL"
                    
                    local block_tvb = payload_tvb:range(offset, t_len)
                    local subtree = tree:add(my_proto, block_tvb, "Dynamic Protocol Data (Cat " .. tostring(ret_table["Transport Header"].category) .. ")")
                    
                    if ret_table.__error then
                        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Rust failed to dissect block: " .. ret_table.__error)
                    else
                        add_table_to_tree(subtree, ret_table, offset, payload_tvb, false)
                    end
                end
            elseif type(ret_table) == "table" and ret_table.__error then
                tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Error parsing block " .. tostring(i) .. ": " .. ret_table.__error)
            end
        end
    end
end

-- Safely and universally register as a post-dissector.
-- This ensures we don't fight with Wireshark's native Asterix dissector 
-- and we evaluate all UDP packets universally!
register_postdissector(my_proto)
