# _*_ coding: utf-8 _*_

import socket


def test_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = raw_input("Which server do you wan't to connect? ")
    client.connect((ip, 55555))

    while True:
    	data = raw_input('Please write message: ')
	if not data:
	    print("msg cant's be empty")
	    continue
        if data.lower() == 'exit':
            client.close()
            break
        client.sendall(data)
        echo_data = client.recv(1024)
        print('收到服务端的回信：%s' % echo_data)
    client.close()


if __name__ == '__main__':
    test_client()
