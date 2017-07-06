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
#### HTTPConnection类
如上例子，这个类拿到stream和request_callback函数之后实例化；实例首先会写入一个chunk到iostream里，并传入回调函数；接着完成请求处理
首先初始化：
```python
class HTTPConnection(object):
    def __init__(self, stream, address, request_callback, no_keep_alive=False,
                 xheaders=False):
        self.stream = stream
        self.address = address
        self.request_callback = request_callback
        self.no_keep_alive = no_keep_alive
        self.xheaders = xheaders
        self._request = None
        self._request_finished = False
        self._header_callback = stack_context.wrap(self._on_headers)
        # 先读取完整的头部，并传入self._on_headers回调函数
        self.stream.read_until(b("\r\n\r\n"), self._header_callback)
        self._write_callback = None
```
然后就是write和finish函数的逻辑:
```python

    def close(self):
        self.stream.close()
        self._header_callback = None

    def write(self, chunk, callback=None):
        assert self._request, "Request closed"
        if not self.stream.closed():
            self._write_callback = stack_context.wrap(callback)
            self.stream.write(chunk, self._on_write_complete)

    def finish(self):
        """Finishes the request."""
        """虽然之前的self.write函数会在写完chunk后执行一次self._finish_request
        但一般还是会在最后判断一次是否写完数据，再执行一次"""
        assert self._request, "Request closed"
        self._request_finished = True
        if not self.stream.writing():
            self._finish_request()

    def _on_write_complete(self):
        """先执行回调函数，然后判断是否io完成，没完成将会调用self._finish_request"""
        if self._write_callback is not None:
            callback = self._write_callback
            self._write_callback = None
            callback()
        if self._request_finished and not self.stream.writing():
            self._finish_request()
```
真正处理完成请求处理逻辑：
```python
    def _finish_request(self):
        ...

        self._request = None
        self._request_finished = False
        if disconnect:
            self.close()
            return
        # 此处读取htp头部, 并处理
        # 注意：self._header_callback = stack_context.wrap(self._on_headers)
        self.stream.read_until(b("\r\n\r\n"), self._header_callback)
```
先调用_on_headers, 再在_on_headers里面调用_on_request_body, 最后再执行用户定义的request_callback,
这个request_callback有两种形式：
* 一种是一个函数；
```python
def handle_request(request):
   message = "You requested %s\n" % request.uri
   request.write("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (
                 len(message), message))
   request.finish()
http_server = tornado.httpserver.HTTPServer(handle_request)
```

* 一种是实现了__call__的对象;
```python
application = tornado.web.Application([(r"/", MainHandler), ])
http_server = tornado.httpserver.HTTPServer(application)
```
两个分别解析头部和body的回调函数
```python
    def _on_headers(self, data):
        """解析头部，首先解析请求方法、URL、http协议版本
        然后用httputil解析头部字段"""
        try:
            data = native_str(data.decode('latin1'))
            eol = data.find("\r\n")
            start_line = data[:eol]
            try:
                # 得到请求方法，url，http协议版本
                method, uri, version = start_line.split(" ")
            ...
            headers = httputil.HTTPHeaders.parse(data[eol:])

            # 获取IP
            if getattr(self.stream.socket, 'family', socket.AF_INET) in (
                socket.AF_INET, socket.AF_INET6):
                remote_ip = self.address[0]
            else:
                remote_ip = '0.0.0.0'

            # 实例化一个请求
            self._request = HTTPRequest(
                connection=self, method=method, uri=uri, version=version,
                headers=headers, remote_ip=remote_ip)

            content_length = headers.get("Content-Length")
            if content_length:
                content_length = int(content_length)
                if content_length > self.stream.max_buffer_size:
                    raise _BadRequestException("Content-Length too long")
                if headers.get("Expect") == "100-continue":
                    self.stream.write(b("HTTP/1.1 100 (Continue)\r\n\r\n"))
                # 请求body的长度为参数，并传入回调函数_on_request_body
                self.stream.read_bytes(content_length, self._on_request_body)
                return

            self.request_callback(self._request)
            ...

    def _on_request_body(self, data):
        self._request.body = data
        if self._request.method in ("POST", "PATCH", "PUT"):
            httputil.parse_body_arguments(
                self._request.headers.get("Content-Type", ""), data,
                self._request.arguments, self._request.files)
        self.request_callback(self._request)
```
### web.py:
Application类的初始化的参数一般是一个列表，包括着一个个三元的元组（'pattern', 'handler', 'kwargs')
