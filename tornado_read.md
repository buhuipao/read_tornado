### netutil.py:
简单的例子如下：
```python
server = TCPServer()
server.listen(8888)
IOLoop.instance().start()
```
listen的代码如下：
```
def listen(self, port, address=""):
    sockets = bind_sockets(port, address=address)
    self.add_sockets(sockets)
```
建立一个跑在ioloop之上的TCP服务, 通过add_accept_handler方法，把端口监听socket注册到ioloop读事件里去
```python

    def add_sockets(self, sockets):
        if self.io_loop is None:
            self.io_loop = IOLoop.instance()

        for sock in sockets:
            self._sockets[sock.fileno()] = sock
            add_accept_handler(sock, self._handle_connection,
                               io_loop=self.io_loop)
```
同时会有个callback传进去, callback就是tcp实例的_handle_connection方法
```python
def add_accept_handler(sock, callback, io_loop=None):
    if io_loop is None:
        io_loop = IOLoop.instance()

    def accept_handler(fd, events):
        while True:
            try:
                connection, address = sock.accept()
            except socket.error, e:
                if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    return
                raise
            callback(connection, address)
    io_loop.add_handler(sock.fileno(), accept_handler, IOLoop.READ)
```
这个callback里面包着继承TCPServer类之后自己实现的handle_stream方法, 达到异步读写的目的
handle_stream的参数：
1. 以监听Socket在接受连接之后生成的connection为参数的IOStream实例；
2. connection的地址
```python
def _handle_connection(self, connection, address):
    ...
    try:
        if self.ssl_options is not None:
            stream = SSLIOStream(connection, io_loop=self.io_loop)
        else:
            stream = IOStream(connection, io_loop=self.io_loop)
        self.handle_stream(stream, address)
    except Exception:
        logging.error("Error in connection callback", exc_info=True)
```
### process.py:
多进程的一些方法, 比如：cpu_count，fork_processes等

### httputil.py:
一些解析头部的方法

### httpserver.py:
HTTPServer类直接继承TCPServer类，直接复写实现他的handle_stream方法, handle_stream里面放入了请求的回调函数
```python
class HTTPServer(TCPServer):
    def __init__(self, request_callback, no_keep_alive=False, io_loop=None,
                 xheaders=False, ssl_options=None, **kwargs):
        self.request_callback = request_callback
        self.no_keep_alive = no_keep_alive
        self.xheaders = xheaders
        TCPServer.__init__(self, io_loop=io_loop, ssl_options=ssl_options,
                           **kwargs)

    def handle_stream(self, stream, address):
        HTTPConnection(stream, address, self.request_callback,
                       self.no_keep_alive, self.xheaders)
```
下面是一个简单例子：
```python
import httpserver
import ioloop

def handle_request(request):
   message = "You requested %s\n" % request.uri
   request.write("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (
                 len(message), message))
   request.finish()

http_server = httpserver.HTTPServer(handle_request)
http_server.listen(8888)
ioloop.IOLoop.instance().start()
```
