-- 测试 REPL 输出重定向
-- 在 REPL 中运行此脚本来验证 console->info 是否正确重定向

print("=== REPL Output Test ===")
print("")

-- 测试 1: 基本 print 输出
print("Test 1: Basic print output")
print("This should appear in REPL")
print("")

-- 测试 2: 调用会产生 console->info 的函数
print("Test 2: Calling functions with console->info")
print("Calling xdl.open...")
-- xdl.open("libc.so")  -- 这会产生 console->info 输出
print("")

-- 测试 3: 多行输出
print("Test 3: Multiple outputs")
for i = 1, 3 do
    print("Line " .. i)
end
print("")

-- 测试 4: 格式化输出
print("Test 4: Formatted output")
local addr = 0x7b8c9a0000
print(string.format("Address: 0x%x", addr))
print("")

print("=== Test Complete ===")
print("If you can see all messages above, REPL output is working correctly!")
