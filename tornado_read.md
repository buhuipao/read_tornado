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
#### HTTPServer类:
直接继承TCPServer类，直接复写实现他的handle_stream方法, handle_stream里面放入了请求的回调函数
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

* 一种是实现了`__call__`的对象;
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
#### Application类:
初始化的参数一般是一个列表，包括着一个个三元的元组（'pattern', 'handler', 'kwargs')
* 'pattern': str类型，路由的path;
* 'handler': str类型类名字或者就是类, 路由的处理类;`handler = import_object(handler)`
* 'kwargs': dict类型，额外参数非必需，比如'name', 'path'
```python
def add_handlers(self, host_pattern, host_handlers):
    if not host_pattern.endswith("$"):
        host_pattern += "$"
    handlers = []
    if self.handlers and self.handlers[-1][0].pattern == '.*$':
        self.handlers.insert(-1, (re.compile(host_pattern), handlers))
    else:
        self.handlers.append((re.compile(host_pattern), handlers))
    for spec in host_handlers:
        if type(spec) is type(()):
            assert len(spec) in (2, 3)
            pattern = spec[0]
            handler = spec[1]
            if isinstance(handler, str):
                # 根据名字倒入自定义的处理器类
                handler = import_object(handler)
            if len(spec) == 3:
                kwargs = spec[2]
            else:
                kwargs = {}
            spec = URLSpec(pattern, handler, kwargs)
        handlers.append(spec)
        if spec.name:
            if spec.name in self.named_handlers:
                logging.warning(
                    "Multiple handlers named %s; replacing previous value",
                    spec.name)
            self.named_handlers[spec.name] = spec
```
如之前说的，application是一个类，想要作为一个reques_callback就必须实现`__call__`方法
```python
def __call__(self, request):
    transforms = [t(request) for t in self.transforms]
    handler = None
    args = []
    kwargs = {}
    # 如果没有匹配的主机名，就会返回None，就会执行下面的RedirectHandler, 重定向至默认主机处理
    handlers = self._get_host_handlers(request)
    if not handlers:
        handler = RedirectHandler(
            self, request, url="http://" + self.default_host + "/")
    else:
        for spec in handlers:
            # 匹配路由规则，如果咩有匹配到那么就会进行404错误处理
            match = spec.regex.match(request.path)
            if match:
                handler = spec.handler_class(self, request, **spec.kwargs)
                if spec.regex.groups:
                    def unquote(s):
                        if s is None:
                            return s
                        return escape.url_unescape(s, encoding=None)
                    if spec.regex.groupindex:
                        kwargs = dict(
                            (str(k), unquote(v))
                            for (k, v) in match.groupdict().iteritems())
                    else:
                        args = [unquote(s) for s in match.groups()]
                break
        if not handler:
            handler = ErrorHandler(self, request, status_code=404)
    # 以得到参数，执行handler
    handler._execute(transforms, *args, **kwargs)
    return handler
```
handler的执行逻辑如下:
```python
def _execute(self, transforms, *args, **kwargs):
    self._transforms = transforms
    try:
        # SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PATCH", "PUT", "OPTIONS")
        # 不支持方法就进行405错误处理
        if self.request.method not in self.SUPPORTED_METHODS:
            raise HTTPError(405)
        # 检查xsrf_cookie
        if self.request.method not in ("GET", "HEAD", "OPTIONS") and \
           self.application.settings.get("xsrf_cookies"):
            self.check_xsrf_cookie()
        # 处理前的中间件函数, 类似于falsk的before_request, 可以用来进行访问日志记录
        self.prepare()
        if not self._finished:
            args = [self.decode_argument(arg) for arg in args]
            kwargs = dict((k, self.decode_argument(v, name=k))
                          for (k, v) in kwargs.iteritems())
            # 真正执行代码在这，通过getattr得到自定义的处理类的方法执行函数, 然后执行之前得到的参数
            getattr(self, self.request.method.lower())(*args, **kwargs)
            if self._auto_finish and not self._finished:
                self.finish()
    except Exception, e:
        self._handle_request_exception(e)
```
#### RequestHandler类:
HTTP请求处理的一个极好的实例，值得细看，后看先挖坑, 先看tornado另一个谜一样的类：gen
### gen.py:

