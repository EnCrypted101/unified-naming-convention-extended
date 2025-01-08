local passed, failed, unsupported = 0, 0, 0
local active = 0

local function getPath(path)
    local value = getfenv(0)
    while value ~= nil and path ~= "" do
        local name, next = string.match(path, "^([^.]+)%.?(.*)$")
        value = value[name]
        path = next
    end
    return value
end

local function runTest(category, name, testFunc, description)
    active = active + 1
    task.spawn(function()
        if not testFunc then
            print("🟡 " .. category .. "." .. name .. " (No test function provided)")
            unsupported = unsupported + 1
        elseif not getPath(category .. "." .. name) then
            print("🔴 " .. category .. "." .. name .. " (Not supported)")
            failed = failed + 1
        else
            print("🧪 Testing: " .. category .. "." .. name .. " -> " .. description)
            local ok, result = pcall(testFunc)
            if ok then
                print("🟢 " .. category .. "." .. name .. " -> Test Passed" .. (result and ": " .. tostring(result) or ""))
                passed = passed + 1
            else
                warn("🔴 " .. category .. "." .. name .. " -> Test Failed: " .. result)
                failed = failed + 1
            end
        end

        active = active - 1
    end)
end

print("----------------------------------------------------")
print("  UNCE Environment Check  ")
print("----------------------------------------------------\n")

runTest("get", "getregkeys", function()
    local keys = getregkeys("HKLM\\SOFTWARE\\Roblox")
    if type(keys) == "table" then
        print("  Returned table of registry keys.")
        return #keys
    else
        error("Failed to retrieve registry keys.")
    end
end, "Returns a table of all keys in a specified registry path.")

runTest("get", "getrawassembly", function()
    local function testFunc()
        return 123
    end
    local asm = getrawassembly(testFunc)
    if type(asm) == "string" and #asm > 0 then
        print("  Returned assembly code string.")
        print("  Assembly (first 50 chars): " .. string.sub(asm, 1, 50) .. "...")
        return true
    else
        error("Failed to retrieve assembly code.")
    end
end, "Returns the raw assembly code of a function.")

runTest("get", "getinstanceaddress", function()
    local player = game:GetService("Players").LocalPlayer
    local addr = getinstanceaddress(player)
    if type(addr) == "number" then
        print("  LocalPlayer address: 0x" .. string.format("%X", addr))
        return true
    else
        error("Failed to get instance address.")
    end
end, "Returns the memory address of an instance.")

runTest("get", "getthreads", function()
    local threads = getthreads()
    if type(threads) == "table" then
        print("  Found " .. #threads .. " threads.")
        return #threads
    else
        error("Failed to get threads.")
    end
end, "Returns a table containing all the thread objects in the executor.")

runTest("get", "getfunctionhash", function()
    local function testFunc()
        return 456
    end
    local hash = getfunctionhash(testFunc)
    if type(hash) == "string" and #hash > 0 then
        print("  Function hash: " .. hash)
        return true
    else
        error("Failed to get function hash.")
    end
end, "Returns a unique hash that identifies a function based on its bytecode.")

runTest("get", "getloadeddlls", function()
    local dlls = getloadeddlls()
    if type(dlls) == "table" then
        print("  Found " .. #dlls .. " loaded DLLs.")
        return #dlls
    else
        error("Failed to get loaded DLLs.")
    end
end, "Returns a table of all loaded DLLs in the Roblox process.")

runTest("get", "getmemorybreakpoints", function()
    local breakpoints = getmemorybreakpoints()
    if type(breakpoints) == "table" then
        print("  Found " .. #breakpoints .. " memory breakpoints.")
        return #breakpoints
    else
        error("Failed to get memory breakpoints.")
    end
end, "Returns a table of all active memory breakpoints.")

runTest("get", "getrawthreadcontext", function()
    local threads = getthreads()
    if threads and threads[1] then
        local context = getrawthreadcontext(threads[1])
        if type(context) == "table" then
            print("  Successfully got raw thread context.")
            return true
        else
            error("Failed to get raw thread context.")
        end
    else
        error("No threads found or failed to get threads.")
    end
end, "Returns the raw context of a thread as a table of register values.")

runTest("get", "getmemorypages", function()
    local startAddress = 0x00000000 
    local endAddress = 0x7FFFFFFF
    local pages = getmemorypages(startAddress, endAddress)
    if type(pages) == "table" then
        print("  Retrieved information about memory pages.")
        return true
    else
        error("Failed to retrieve memory pages information.")
    end
end, "Returns a table of all memory pages within a specified address range.")

runTest("get", "getfunctionrva", function()
    local function testFunc() return end
    local rva = getfunctionrva(testFunc)
    if type(rva) == "number" then
        print("  RVA of testFunc: 0x" .. string.format("%X", rva))
        return true
    else
        error("Failed to get function RVA.")
    end
end, "Returns the relative virtual address (RVA) of a function within its module.")

runTest("get", "getobjectfromhandle", function()
    local player = game:GetService("Players").LocalPlayer
    local handle = getinstancehandle(player)
    if handle then
        local object = getobjectfromhandle(handle)
        if object == player then
            print("  Successfully retrieved object from handle.")
            return true
        else
            error("Failed to retrieve object from handle or object mismatch.")
        end
    else
        print("  Could not obtain instance handle. Skipping test.")
        return false
    end
end, "Returns the object associated with a given handle.")

runTest("get", "getexportsbyordinal", function()
    local moduleName = "RobloxPlayerBeta.dll"
    local moduleBase = memgetbaseaddressbyname(moduleName)
    if moduleBase then
        local exports = getexportsbyordinal(moduleBase)
        if type(exports) == "table" then
            print("  Successfully retrieved exports by ordinal from " .. moduleName)
            return true
        else
            error("Failed to retrieve exports by ordinal.")
        end
    else
        error("Failed to get base address of " .. moduleName)
    end
end, "Returns a table of exported functions from a module (DLL), indexed by their ordinal numbers.")

runTest("set", "setthreadcontext", function()
    local threads = getthreads()
    if threads and threads[1] then
        print("  WARNING: Attempting to modify thread context. This may crash the game.")
        local originalContext = getrawthreadcontext(threads[1])
        if not originalContext then error("Could not get original thread context") end
        local success, result = pcall(function()
            setthreadcontext(threads[1], {["rip"] = 0x0}) 
        end)
        local restoreSuccess, restoreResult = pcall(function()
            setthreadcontext(threads[1], originalContext)
        end)
        if not restoreSuccess then
            print("  Failed to restore original thread context: " .. tostring(restoreResult))
        end
        if success then
            print("  Thread context modified (potentially unstable).")
        else
            print("  Failed to modify thread context: " .. tostring(result))
        end
        return success and restoreSuccess
    else
        error("No threads found.")
    end
end, "Modifies the context (registers, stack, etc.) of a specific thread. Extremely dangerous!")

runTest("set", "setrawassembly", function()
    local function testFunc()
        print("This should not be printed.")
    end
    local originalAsm = getrawassembly(testFunc)
    local asmSize = string.len(originalAsm)
    if asmSize > 0 then
        print("  WARNING: Attempting to overwrite function assembly. This may crash the game.")
        local nops = string.char(0x90):rep(asmSize)
        local success, result = pcall(function()
            setrawassembly(testFunc, nops)
        end)
        if success then
            print("  Function assembly overwritten (potentially unstable).")
            setrawassembly(testFunc, originalAsm)
            print("  Original assembly restored.")
            testFunc()
            return true
        else
            error("Failed to overwrite function assembly: " .. tostring(result))
        end
    else
        error("Could not get original assembly size.")
    end
end, "Overwrites the assembly code of a function with custom assembly code. Extremely dangerous!")

runTest("set", "setmemorybreakpoint", function()
    _G.testVar = 123
    local addr = getinstanceaddress(_G.testVar)
    if addr then
        local bpSet = setmemorybreakpoint(addr, "write", function()
            print("  Memory breakpoint triggered! _G.testVar was written to.")
            return true
        end)
        if bpSet then
            print("  Memory breakpoint set on address: 0x" .. string.format("%X", addr))
            _G.testVar = 456
            return true
        else
            error("Failed to set memory breakpoint.")
        end
    else
        error("Could not get address of _G.testVar")
    end
end, "Sets a memory breakpoint on a specific memory address.")

runTest("set", "clearmemorybreakpoints", function()
    clearmemorybreakpoints()
    print("  Cleared all memory breakpoints (if any were set).")
    return true
end, "Removes all active memory breakpoints.")

runTest("set", "terminateprocess", function()
    print("  WARNING: This test will terminate the Roblox process.")
    local terminate = terminateprocess()
    if not terminate then
        print("terminateprocess failed to execute.")
        return false
    end
    return true
end, "Terminates the Roblox process.")

runTest("set", "disablecrashreporting", function()
    disablecrashreporting()
    print("  Attempted to disable crash reporting.")
    return true
end, "Disables Roblox's crash reporting system.")

runTest("set", "setthreadcontextreg", function()
    local threads = getthreads()
    if threads and threads[1] then
        local regName = "rax"
        local originalContext = getrawthreadcontext(threads[1])
        local originalValue = originalContext[regName]
        local newValue = 12345
        setthreadcontextreg(threads[1], regName, newValue)
        local newContext = getrawthreadcontext(threads[1])
        local success = newContext[regName] == newValue
        setthreadcontextreg(threads[1], regName, originalValue)
        if success then
            print("  Successfully modified thread context register " .. regName .. ".")
            return true
        else
            error("Failed to modify thread context register.")
        end
    else
        error("No threads found or failed to get threads.")
    end
end, "Sets the value of a specific register in a thread's context. Extremely dangerous!")

runTest("set", "setmemorypageprotection", function()
    local addr = memallocvirtual(4096, "read,write")
    if type(addr) == "number" then
        local success, result = pcall(function()
            setmemorypageprotection(addr, 4096, "read,execute")
        end)
        if success then
            print("  Successfully modified protection flags of memory page.")
            memfreevirtual(addr)
            return true
        else
            error("Failed to modify protection flags: " .. tostring(result))
        end
    else
        error("Failed to allocate memory for protection test.")
    end
end, "Sets the protection flags of a specific memory page.")

runTest("set", "setfunctionrva", function()
    local function testFunc() return 123 end
    local originalRVA = getfunctionrva(testFunc)
    local newRVA = originalRVA + 4
    print("  WARNING: Attempting to modify function RVA. This may crash the game.")
    local success, result = pcall(function()
        setfunctionrva(testFunc, newRVA)
    end)
    if success then
        print("  Function RVA modified (potentially unstable).")
        setfunctionrva(testFunc, originalRVA)
        print("  Original function RVA restored.")
        return true
    else
        error("Failed to modify function RVA: " .. tostring(result))
    end
end, "Overwrites the relative virtual address (RVA) of a function within its module. Extremely dangerous!")

runTest("set", "unloadmodule", function()
    local moduleName = "ExampleModule.dll"
    print("  WARNING: Attempting to unload module " .. moduleName .. ". This may crash the game.")
    local success, result = pcall(function()
        unloadmodule(moduleName)
    end)
    if success then
        print("  Module " .. moduleName .. " unloaded (potentially unstable).")
        return true
    else
        error("Failed to unload module: " .. tostring(result))
    end
end, "Attempts to unload a specific module (DLL) from the Roblox process. Extremely dangerous!")

runTest("new", "newassemblyfunction", function()
    local asmCode = "\x55\x48\x89\xE5\xB8\x2A\x00\x00\x00\x5D\xC3"
    local newFunc = newassemblyfunction(asmCode)
    if type(newFunc) == "function" then
        local result = newFunc()
        print("  New assembly function created. Returned: " .. tostring(result))
        return result == 42
    else
        error("Failed to create assembly function.")
    end
end, "Creates a new function from raw assembly code.")

runTest("new", "newthreadex", function()
    local newThread = newthreadex(function()
        print("  Hello from new thread!")
        task.wait(1)
        print("  New thread exiting.")
    end, {stacksize = 1024 * 1024, priority = 2})

    if type(newThread) == "thread" then
        print("  New thread created with extended options.")
        return true
    else
        error("Failed to create new thread.")
    end
end, "Creates a new thread with extended options (stack size, initial state, priority).")

runTest("new", "newfiber", function()
    local fiber = newfiber(function()
        print("  Hello from fiber!")
        local value = coroutine.yield(1)
        print("  Fiber resumed with value:", value)
        return 2
    end)

    if type(fiber) == "thread" and coroutine.status(fiber) == "suspended" then
        print("  New fiber created.")
        local success, result = coroutine.resume(fiber)
        print("  Fiber yielded:", result)
        success, result = coroutine.resume(fiber, 42)
        print("  Fiber returned:", result)
        return true
    else
        error("Failed to create or resume fiber.")
    end
end, "Creates a new fiber for cooperative multitasking.")

runTest("new", "newexceptionhandler", function()
    local handlerSet = newexceptionhandler(function(exception)
        print("  Exception caught: " .. tostring(exception))
        return true
    end)

    if handlerSet then
        print("  Custom exception handler registered.")
        return true
    else
        error("Failed to register custom exception handler.")
    end
end, "Registers a custom exception handler.")

runTest("run", "runwithouthandlers", function()
    local function errorFunc()
        error("Intentional error for testing.")
    end

    local success, result = pcall(function()
        runwithouthandlers(errorFunc)
    end)

    if not success then
        print("  Successfully ran function without handlers and caught the error (game may have crashed).")
        return true
    else
        error("Function did not error as expected or error not caught.")
    end
end, "Executes a function without any exception handlers.")

runTest("run", "runinjectedcode", function()
    local injectedCode = [[
        __declspec(dllexport) int injectedFunction() {
            return 12345;
        }
    ]]
    local success, result = pcall(function()
        return runinjectedcode("injectedFunction")
    end)
    if success then
        print("runinjectedcode executed, result: ", result)
        return result == 12345
    end
    
    print("  runinjectedcode failed to execute injected function or could not inject code.")
    return false
end, "Executes code injected into the Roblox process from an external source.")

runTest("run", "runwithalteredpermissions", function()
    local function restrictedFunction()
        print("  This function should only be called with altered permissions.")
        return getregkeys("HKLM\\SOFTWARE\\Roblox")
    end

    print("  WARNING: Attempting to run function with altered permissions. This may have security implications.")
    local success, result = pcall(function()
        return runwithalteredpermissions(restrictedFunction)
    end)

    if success then
        print("  Function executed with altered permissions.")
        if type(result) == "table" then
            print("  Registry keys accessed.")
            return true
        else
            print("  Registry keys not accessed as expected.")
            return false
        end
    else
        error("Failed to run function with altered permissions: " .. tostring(result))
    end
end, "Executes a function with altered permissions. Extremely dangerous!")

runTest("run", "runataddresswithargs", function()
    local addr = memallocvirtual(1024, "read,write,execute")
    local machineCode = "\x55\x48\x89\xE5\xB8\x2A\x00\x00\x00\x5D\xC3"
    memwritebytes(addr, machineCode)
    print("  WARNING: Attempting to execute code at address with arguments. This is extremely dangerous.")
    local success, result = pcall(function()
        return runataddresswithargs(addr, 42, "hello")
    end)
    if success then
        print("  Code executed at address with arguments.")
        memfreevirtual(addr)
        return true
    else
        error("Failed to execute code at address with arguments: " .. tostring(result))
    end
end, "Executes arbitrary machine code at a specified memory address, passing custom arguments. Extremely dangerous!")

runTest("is", "isthreadsafe", function()
    local threadSafe = isthreadsafe(print)
    if threadSafe then
        print("  'print' function is reported as thread-safe.")
    else
        print("  'print' function is reported as not thread-safe.")
    end
    return threadSafe
end, "Checks if a given function is thread-safe.")

runTest("is", "isinstanceof", function()
    local part = Instance.new("Part")
    local isPart = isinstanceof(part, "Part")
    local isBasePart = isinstanceof(part, "BasePart")

    if isPart and isBasePart then
        print("  Instance checks successful.")
        return true
    else
        error("Instance check failed.")
    end
end, "Checks if an instance is of a specific class or inherits from a specific class.")

runTest("is", "isprocessprotected", function()
    local protected = isprocessprotected()
    if protected then
        print("  Roblox process has enhanced security measures enabled.")
    else
        print("  Roblox process does not have enhanced security measures enabled.")
    end
    return protected
end, "Checks if the Roblox process has enhanced security measures enabled.")

runTest("is", "isremotefunction", function()
    local function testFunc() end
    local remote = isremotefunction(testFunc)
    if remote then
        print("  Function is located in a remote process.")
    else
        print("  Function is not located in a remote process.")
    end
    return remote
end, "Checks if a function is located in a remote process.")

runTest("mem", "memallocvirtual", function()
    local addr = memallocvirtual(4096, "read,write")
    if type(addr) == "number" then
        print("  Allocated virtual memory at address: 0x" .. string.format("%X", addr))
        memfreevirtual(addr)
        print("  Freed allocated virtual memory.")
        return true
    else
        error("Failed to allocate virtual memory.")
    end
end, "Allocates a block of virtual memory with specified protection flags.")

runTest("mem", "memfreevirtual", function()
    local addr = memallocvirtual(4096, "read,write")
    if type(addr) == "number" then
        local freed = memfreevirtual(addr)
        if freed then
            print("  Freed virtual memory at address: 0x" .. string.format("%X", addr))
            return true
        else
            error("Failed to free virtual memory.")
        end
    else
        error("Failed to allocate virtual memory for freeing test.")
    end
end, "Frees a block of previously allocated virtual memory.")

runTest("mem", "memgetbaseaddressbyname", function()
    local addr = memgetbaseaddressbyname("RobloxPlayerBeta.dll")
    if type(addr) == "number" then
        print("  RobloxPlayerBeta.dll base address: 0x" .. string.format("%X", addr))
        return true
    else
        error("Failed to get base address by name.")
    end
end, "Returns the base address of a module given the module's name.")

runTest("mem", "memcopy", function()
    local src = "Hello, world!"
    local dst = memallocvirtual(string.len(src) + 1, "read,write")
    if type(dst) == "number" then
        memcopy(dst, src, string.len(src) + 1)
        local copied = memread(dst, "string", string.len(src) + 1)
        print("  Copied string: " .. tostring(copied))
        memfreevirtual(dst)
        return copied == src
    else
        error("Failed to allocate memory for memcopy test.")
    end
end, "Copies a block of memory from one address to another.")

runTest("mem", "memfill", function()
    local addr = memallocvirtual(16, "read,write")
    if type(addr) == "number" then
        memfill(addr, 0x41, 16)
        local filled = memread(addr, "string", 16)
        print("  Filled memory: " .. tostring(filled))
        memfreevirtual(addr)
        return filled == string.char(0x41):rep(16)
    else
        error("Failed to allocate memory for memfill test.")
    end
end, "Fills a block of memory with a specific byte value.")

runTest("mem", "memgetpatternsize", function()
    local pattern = "\x55\x8B\xEC\x83\xE4\xF8"
    local size = memgetpatternsize(pattern)
    if type(size) == "number" then
        print("  Pattern size: " .. size .. " bytes")
        return size
    else
        error("Failed to get pattern size.")
    end
end, "Returns the size (in bytes) of a given pattern used for pattern scanning.")

runTest("mem", "memvirtualalloc", function()
    local addr = 0x10000000
    local size = 4096
    local protection = "read,write,execute"
    local allocAddr = memvirtualalloc(addr, size, protection)
    if type(allocAddr) == "number" then
        print("  Allocated virtual memory at address: 0x" .. string.format("%X", allocAddr))
        memvirtualfree(allocAddr)
        print("  Freed allocated virtual memory.")
        return true
    else
        error("Failed to allocate virtual memory.")
    end
end, "Allocates a block of virtual memory at a specific address with specified protection flags.")

runTest("mem", "memvirtualfree", function()
    local addr = memvirtualalloc(0, 4096, "read,write")
    if type(addr) == "number" then
        local freed = memvirtualfree(addr)
        if freed then
            print("  Freed virtual memory at address: 0x" .. string.format("%X", addr))
            return true
        else
            error("Failed to free virtual memory.")
        end
    else
        error("Failed to allocate virtual memory for freeing test.")
    end
end, "Frees a block of virtual memory at a specific address.")

runTest("mem", "memreadbytes", function()
    local addr = memallocvirtual(16, "read,write")
    memfill(addr, 0x42, 16)
    local bytes = memreadbytes(addr, 16)
    if type(bytes) == "string" and #bytes == 16 then
        print("  Read bytes from memory: " .. string.format("%X ", string.byte(bytes, 1, 16)))
        memfreevirtual(addr)
        return true
    else
        error("Failed to read bytes from memory.")
    end
end, "Reads a specified number of raw bytes from a memory address and returns them as a string.")

runTest("mem", "memwritebytes", function()
    local addr = memallocvirtual(16, "read,write")
    local bytes = "\x41\x42\x43\x44\x45\x46"
    memwritebytes(addr, bytes)
    local readBytes = memreadbytes(addr, 6)
    if readBytes == bytes then
        print("  Successfully wrote bytes to memory.")
        memfreevirtual(addr)
        return true
    else
        error("Failed to write bytes to memory.")
    end
end, "Writes a sequence of raw bytes to a specific memory address.")

runTest("mem", "memgetprocessheap", function()
    local heapHandle = memgetprocessheap()
    if type(heapHandle) == "number" then
        print("  Process heap handle: 0x" .. string.format("%X", heapHandle))
        return true
    else
        error("Failed to get process heap handle.")
    end
end, "Returns a handle to the default heap of the Roblox process.")

runTest("mem", "memgetheapsegment", function()
    local heapHandle = memgetprocessheap()
    local segments = memgetheapsegment(heapHandle)
    if type(segments) == "table" then
        print("  Successfully retrieved heap segments.")
        return true
    else
        error("Failed to retrieve heap segments.")
    end
end, "Returns information about a specific segment within a heap.")

runTest("mem", "memcreateheap", function()
    local heapHandle = memcreateheap(4096, "read,write")
    if type(heapHandle) == "number" then
        print("  Created private heap with handle: 0x" .. string.format("%X", heapHandle))
        memdestroyheap(heapHandle)
        print("  Destroyed private heap.")
        return true
    else
        error("Failed to create private heap.")
    end
end, "Creates a new private heap within the Roblox process.")

runTest("mem", "memdestroyheap", function()
    local heapHandle = memcreateheap(4096, "read,write")
    if type(heapHandle) == "number" then
        local destroyed = memdestroyheap(heapHandle)
        if destroyed then
                        print("  Successfully destroyed private heap.")
            return true
        else
            error("Failed to destroy private heap.")
        end
    else
        error("Failed to create private heap for destruction test.")
    end
end, "Destroys a previously created private heap.")

runTest("dbg", "dbgsetvalue", function()
    local function debuggedFunction()
        local myVar = 10
        print("myVar (inside function):", myVar)
    end
    
    print("  Set a breakpoint on the print line in dbgsetvalue test function.")
    print("  Then, once hit continue execution")
    print("  Waiting for debugger to attach...")
    repeat task.wait() until type(dbgattach) == "function" and dbgattach()

    print("  Now, set a breakpoint using: dbgsetbreakpoint(debuggedFunction, *)")
    print("  Replace the * with the line number of the 'print' statement")
    
    local success, result = pcall(debuggedFunction)

    if not success then
        print("  Breakpoint hit. Attempting to change variable value using dbgsetvalue.")
        local changed = dbgsetvalue("myVar", 20)
        if changed then
            print("  Successfully changed variable value.")
            dbgcontinue()
            return true
        else
            error("Failed to change variable value.")
        end
    else
        print("  Breakpoint not hit.")
        error("dbgsetvalue test requires manual breakpoint.")
    end
end, "Sets the value of a variable or expression in the debugged context (requires debugger).")

runTest("dbg", "dbgenablebreakpoints", function()
    dbgenablebreakpoints(true)
    print("  Enabled all breakpoints.")
    dbgenablebreakpoints(false)
    print("  Disabled all breakpoints.")
    return true
end, "Enables or disables all breakpoints.")

runTest("dbg", "dbgdisassemble", function()
    local function testFunc()
        return 123
    end

    local assembly = dbgdisassemble(testFunc)
    if type(assembly) == "string" and #assembly > 0 then
        print("  Disassembled function. Assembly (first 50 chars): " .. string.sub(assembly, 1, 50) .. "...")
        return true
    else
        error("Failed to disassemble function.")
    end
end, "Disassembles a function or a block of memory.")

runTest("dbg", "dbgfindreferences", function()
    _G.myGlobalVar = "Test"
    local addr = getinstanceaddress(_G.myGlobalVar)

    if addr then
        local references = dbgfindreferences(addr)
        if type(references) == "table" then
            print("  Found " .. #references .. " references to _G.myGlobalVar.")
            return #references
        else
            error("Failed to find references.")
        end
    else
        error("Could not get address of _G.myGlobalVar.")
    end
end, "Finds all references to a specific memory address or function.")

runTest("dbg", "dbghookfunction", function()
    local function targetFunction(a, b)
        print("targetFunction called with:", a, b)
        return a + b
    end

    local hooked = dbghookfunction(targetFunction, function(...)
        print("  targetFunction hooked!")
        print("  Arguments:", ...)
        dbgbreak()
        return ...
    end)

    if hooked then
        print("  targetFunction hooked for debugging.")
        targetFunction(1, 2)
        return true
    else
        error("Failed to hook targetFunction.")
    end
end, "Hooks a function for debugging, pausing execution when called.")

runTest("dbg", "dbgunhookfunction", function()
    local function targetFunction(a, b)
        return a + b
    end
    
    local original = hookfunction(targetFunction, function(...)
        print("  targetFunction hooked!")
        return ...
    end)
    
    local unhooked = dbgunhookfunction(targetFunction)

    if unhooked then
        print("  targetFunction unhooked.")
        return true
    else
        error("Failed to unhook targetFunction.")
    end
end, "Removes a previously created debug hook.")

runTest("dbg", "dbgsetmemoryaccessfilter", function()
    local addr = memallocvirtual(4096, "read,write")
    local filterSet = dbgsetmemoryaccessfilter(addr, 4096, "write", function()
        print("  Memory access filter triggered at address: 0x" .. string.format("%X", addr))
        return true
    end)

    if filterSet then
        print("  Memory access filter set for address: 0x" .. string.format("%X", addr))
        memfill(addr, 0x42, 4096)
        memfreevirtual(addr)
        return true
    else
        error("Failed to set memory access filter.")
    end
end, "Sets a filter that will trigger the debugger when memory matching specific criteria is accessed.")

runTest("dbg", "dbgcontinuefrombreakpoint", function()
    local function debuggedFunction()
        local x = 10
        print("x:", x)
    end
    
    print("  Set a breakpoint on the print line in dbgcontinuefrombreakpoint test function using dbgsetbreakpoint.")
    print("  Then, once hit continue execution")
    print("  Waiting for debugger to attach...")
    repeat task.wait() until type(dbgattach) == "function" and dbgattach()

    print("  Now, set a breakpoint using: dbgsetbreakpoint(debuggedFunction, *)")
    print("  Replace the * with the line number of the 'print' statement")
    
    local success, result = pcall(debuggedFunction)

    if not success then
        print("  Breakpoint hit. Attempting to continue from breakpoint with modified context.")
        local registers = dbggetregisters()
        registers.rax = registers.rax + 5 
        dbgcontinuefrombreakpoint({registers = registers})
        return true
    else
        error("Breakpoint not hit.")
    end
end, "Continues execution from a breakpoint, optionally modifying the thread's context before continuing.")

runTest("dbg", "dbggetexceptionrecord", function()
    local record = dbggetexceptionrecord()
    if type(record) == "table" then
        print("  Successfully retrieved exception record.")
        return true
    else
        error("Failed to retrieve exception record or no exception occurred.")
    end
end, "Returns information about the last exception that occurred.")

runTest("dbg", "dbgsetexceptionhandler", function()
    local handlerSet = dbgsetexceptionhandler(function(exception)
        print("  Exception caught by custom handler: " .. tostring(exception))
        return true
    end, "all")

    if handlerSet then
        print("  Custom exception handler set for all exception types.")
        return true
    else
        error("Failed to set custom exception handler.")
    end
end, "Sets a custom exception handler that will be called when an exception occurs.")

runTest("dbg", "dbgsetstepexceptionfilter", function()
    print("  Setting a custom single-step exception filter...")
    local filterSet = dbgsetstepexceptionfilter(function()
        print("    Single-step exception triggered.")
        return true
    end)

    if filterSet then
        print("  Custom single-step exception filter set.")
        return true
    else
        error("Failed to set single-step exception filter.")
    end
end, "Sets a custom exception filter that will be called when a single-step exception occurs.")

runTest("dbg", "dbgsetprocesskillcallback", function()
    print("  Setting a process kill callback...")
    local callbackSet = dbgsetprocesskillcallback(function()
        print("    Roblox process is about to be terminated.")
    end)

    if callbackSet then
        print("  Process kill callback set.")
        return true
    else
        error("Failed to set process kill callback.")
    end
end, "Sets a callback function that will be executed when the Roblox process is about to be terminated.")

runTest("dbg", "dbgenablehardwarebreakpoints", function()
    print("  Enabling hardware breakpoints...")
    dbgenablehardwarebreakpoints(true)
    print("  Hardware breakpoints enabled.")

    print("  Disabling hardware breakpoints...")
    dbgenablehardwarebreakpoints(false)
    print("  Hardware breakpoints disabled.")

    return true
end, "Enables or disables hardware breakpoints.")

repeat task.wait() until active == 0

print("-----------------------------")
print("       UNCE Summary")
print("-----------------------------")
print("🟢 Passed: " .. passed)
print("🔴 Failed: " .. failed)
print("🟡 Unsupported: " .. unsupported)
