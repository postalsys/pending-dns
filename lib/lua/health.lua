local key = KEYS[1];

local max = tonumber(ARGV[1]) or 0;
local newScore = tonumber(ARGV[2]) or 0;

local list = redis.call("ZRANGEBYSCORE", key, '-inf', max, 'LIMIT', 0, 1);

if next(list) ~= nil then
    -- List is not empty, rotate and return
    local id = list[1];
    redis.call("ZADD", key, newScore, id);
    return id;
end

return nil;
