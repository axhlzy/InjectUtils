import socket

import lupa
from lupa import LuaRuntime
lua = LuaRuntime(unpack_returned_tuples=True)

s = socket.socket()
s.bind(('127.0.0.1',8023))
s.listen(5)
print("connecting...")

print(f"Using {lupa.LuaRuntime().lua_implementation} (compiled with {lupa.LUA_VERSION})")
      
while 1:
    sock,addr = s.accept()
    print(sock,addr)
    
    while 1:
        text = sock.recv(1024)
        if len(text.strip()) == 0:
            pass
        else:
            msg = text.decode()
            print("MSG:" + msg)
            lua.globals()._G.print = lambda *args: sock.send(((' '.join(map(str, args))) + '\n').encode())
            try:
                content = str(lua.eval(msg))
                print("CONTENT:" + content)
                sock.send(content.encode())
            except Exception as e:
                sock.send(str(e).encode())
        text = ""

    sock.close()