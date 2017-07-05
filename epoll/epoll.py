# _*_ coding: utf-8 _*_

import socket
import select
import Queue


def test_epoll():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 55555))
    server.listen(10)
    print('服务监启动...')
    server.setblocking(0)
    timeout = 10
    epoll = select.epoll()
    # 监听的套接字肯定设置监视听读事件，即客户端连入
    # 接受连接之后新生成的套接对象也监视可读事件，因为需要等待客户端发来的数据然后读取
    # 然后将可读取的的套接字实例修改监视为可写，因为服务端需要写入数据进行回应
    # 获取套接字的消息队列内消息，直到套接字消息队列为空，则修改监视可读事件，然后循环
    # 同时还要处理客户断掉以及错误事件, 即注销此套接字实例的fd
    epoll.register(server.fileno(), select.EPOLLIN)
    msg_queue = {}
    fd_to_socket = {server.fileno(): server, }

    while True:
        print('等待连接...')
        events = epoll.poll(timeout)
        if not events:
            print('暂无活动连接，重新轮训...')
            continue

        print('发现%d个活动连接，开始处理...' % len(events))
        print('事件详情：')
        print(events)
        for fd, event in events:
            # 第一次fd肯定为server的fileno()
            sockt = fd_to_socket[fd]
            if sockt == server:
                conn, addr = server.accept()
                print('客户端%s:%d连入' % (addr[0], addr[1]))
                # 设置新生成的sockt为非阻塞
                conn.setblocking(0)
                epoll.register(conn.fileno(), select.EPOLLIN)
                fd_to_socket[conn.fileno()] = conn
                msg_queue[conn] = Queue.Queue()

            elif event & select.EPOLLIN:
                data = sockt.recv(1024)
                if data:
                    print('收到客户端的数据：%s' % data)
                    msg_queue[sockt].put(data)
                    # 修改此socket实例的epoll监听事件为可写(因为已经连上服务端，可用于写入即发送数据)
                    epoll.modify(fd, select.EPOLLOUT)
            elif event & select.EPOLLOUT:
                try:
                    msg = msg_queue[sockt].get_nowait()
                except Queue.Empty:
                    print('消息字典中连接客户端的socket的消息队列为空')
                    # 证明连接的socket无数据，则设置为sockt实例期待可读事件(等待客户端发送数据，触发epoll可读事件，然后读到自己的消息队列)
                    epoll.modify(fd, select.EPOLLIN)
                else:
                    sockt.send(msg)
            elif event & select.EPOLLHUP:
                print('客户端已经断掉...')
                epoll.unregister(fd)
                sockt.close()
                # 删除字典中这个套接字
                del fd_to_socket[fd]
            # event & select.EPOLLERR == True
            else:
                print('连接客户端的套接字出错...')
                epoll.unregister(fd)
                sockt.close()
                # 删除字典中这个套接字
                del fd_to_socket[fd]
    # 最后注销监听端口的socket, 销毁epoll，关闭监听套接字
    epoll.unregister(server.fileno())
    epoll.close()
    server.close()

if __name__ == '__main__':
    test_epoll()# _*_ coding: utf-8 _*_
