"""Lua scripts for atomic Redis-based sliding window limit management (Milestone S07 / F3)."""

LUA_RESERVE = """
local amount = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local raw_cap = ARGV[3]
local res_id = ARGV[4]
local now = tonumber(ARGV[5])
local ttl = tonumber(ARGV[6])
local window_start = now - window

-- Helper: sum amounts from a ZSET where member is "amount:res_id"
local function sum_zset(zkey)
    local items = redis.call('ZRANGE', zkey, 0, -1)
    local total = 0
    for _, item in ipairs(items) do
        local sep = string.find(item, ":", 1, true)
        if sep then
            local amt_str = string.sub(item, 1, sep - 1)
            total = total + tonumber(amt_str)
        end
    end
    return total
end

-- Parse caps: either single integer or comma-separated per key
local caps = {}
if string.find(raw_cap, ",", 1, true) then
    for cap_str in string.gmatch(raw_cap, "([^,]+)") do
        table.insert(caps, tonumber(cap_str))
    end
else
    local default_cap = tonumber(raw_cap)
    for i = 1, #KEYS do
        caps[i] = default_cap
    end
end

-- Phase 1: Verify all scope keys have capacity
local usages = {}
local min_remaining = -1

for i, k in ipairs(KEYS) do
    local k_cap = caps[i]
    local committed_key = k .. ':c'
    local reserved_key = k .. ':r'

    -- Prune expired records
    redis.call('ZREMRANGEBYSCORE', committed_key, '-inf', window_start)
    redis.call('ZREMRANGEBYSCORE', reserved_key, '-inf', now)

    local used_c = sum_zset(committed_key)
    local used_r = sum_zset(reserved_key)
    local total_used = used_c + used_r

    if total_used + amount > k_cap then
        local remaining = k_cap - total_used
        if remaining < 0 then remaining = 0 end
        return {0, remaining, ""}
    end

    usages[i] = total_used
    local rem = k_cap - (total_used + amount)
    if min_remaining == -1 or rem < min_remaining then
        min_remaining = rem
    end
end

-- Phase 2: All scopes passed. Atomically create reservation across all scopes.
local expiry_time = now + ttl
local member = tostring(amount) .. ":" .. res_id

for _, k in ipairs(KEYS) do
    local reserved_key = k .. ':r'
    local committed_key = k .. ':c'
    redis.call('ZADD', reserved_key, expiry_time, member)
    redis.call('EXPIRE', reserved_key, window + ttl + 300)
    redis.call('EXPIRE', committed_key, window + 300)
end

-- Store reservation metadata record
local res_key = "limit:res:" .. res_id
redis.call('HSET', res_key,
    'amount', tostring(amount),
    'status', 'RESERVED',
    'created_at', tostring(now),
    'expires_at', tostring(expiry_time),
    'window', tostring(window),
    'scopes', table.concat(KEYS, ",")
)
redis.call('EXPIRE', res_key, ttl + 300)

return {1, min_remaining, res_id}
"""

LUA_COMMIT = """
local res_id = ARGV[1]
local now = tonumber(ARGV[2])
local res_key = "limit:res:" .. res_id

local status = redis.call('HGET', res_key, 'status')
if not status or status ~= 'RESERVED' then
    return {0, 'INVALID_STATUS'}
end

local expires_at = tonumber(redis.call('HGET', res_key, 'expires_at'))
if expires_at and now > expires_at then
    return {0, 'EXPIRED'}
end

local amount_str = redis.call('HGET', res_key, 'amount')
local scopes_str = redis.call('HGET', res_key, 'scopes')
local window_str = redis.call('HGET', res_key, 'window')
local window = tonumber(window_str) or 3600
local member = amount_str .. ":" .. res_id

for scope in string.gmatch(scopes_str, "([^,]+)") do
    local reserved_key = scope .. ':r'
    local committed_key = scope .. ':c'

    redis.call('ZREM', reserved_key, member)
    redis.call('ZADD', committed_key, now, member)
    redis.call('EXPIRE', committed_key, window + 300)
end

redis.call('HSET', res_key, 'status', 'COMMITTED', 'committed_at', tostring(now))
redis.call('EXPIRE', res_key, window + 300)

return {1, 'COMMITTED'}
"""

LUA_RELEASE = """
local res_id = ARGV[1]
local res_key = "limit:res:" .. res_id

local status = redis.call('HGET', res_key, 'status')
if not status or status ~= 'RESERVED' then
    return {0, 'INVALID_STATUS'}
end

local amount_str = redis.call('HGET', res_key, 'amount')
local scopes_str = redis.call('HGET', res_key, 'scopes')
local member = amount_str .. ":" .. res_id

for scope in string.gmatch(scopes_str, "([^,]+)") do
    local reserved_key = scope .. ':r'
    redis.call('ZREM', reserved_key, member)
end

redis.call('HSET', res_key, 'status', 'RELEASED')
redis.call('EXPIRE', res_key, 60)

return {1, 'RELEASED'}
"""

LUA_GET_USAGE = """
local k = KEYS[1]
local window = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local window_start = now - window

local function sum_zset(zkey)
    local items = redis.call('ZRANGE', zkey, 0, -1)
    local total = 0
    for _, item in ipairs(items) do
        local sep = string.find(item, ":", 1, true)
        if sep then
            local amt_str = string.sub(item, 1, sep - 1)
            total = total + tonumber(amt_str)
        end
    end
    return total
end

local committed_key = k .. ':c'
local reserved_key = k .. ':r'

redis.call('ZREMRANGEBYSCORE', committed_key, '-inf', window_start)
redis.call('ZREMRANGEBYSCORE', reserved_key, '-inf', now)

local used_c = sum_zset(committed_key)
local used_r = sum_zset(reserved_key)

return {used_c, used_r, used_c + used_r}
"""
