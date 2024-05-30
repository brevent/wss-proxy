import socket
import socks
import time

if __name__ == '__main__':
    for x in range(4):
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.set_proxy(socks.SOCKS5, "localhost", 1081)
        sock.settimeout(10)
        reqs = []
        for y in range(10):
            data = ("deadbeef_%d_%d_1" % (x, y))
            req = data.encode('utf8')
            sock.sendto(req, ("127.0.0.1", 1235))
            reqs.append(req)
        for y in range(10):
            data = ("deadbeef_%d_%d_2" % (x, y))
            req = data.encode('utf8')
            sock.sendto(req, ("127.0.0.1", 1235))
            time.sleep(.1)
            reqs.append(req)
        ress = []
        for req in reqs:
            (res, addr) = sock.recvfrom(65535)
            ress.append(res)
        if len(reqs) != len(ress):
            raise ValueError("length wrong")
        if set(reqs) != set(ress):
            raise ValueError("value wrong")
        print(b', '.join(reqs).decode('utf8'))
        print(b', '.join(ress).decode('utf8'))
        for y in range(1, 10):
            req = ('c' * 1024 * y).encode('utf8')
            try:
                sock.sendto(req, ('127.0.0.1', 1235))
            except OSError:
                print('length %d ko' % len(req))
                sock.close()
                break
            try:
                (res, addr) = sock.recvfrom(65535)
            except socket.timeout:
                print('length %d ko (timeout)' % len(req))
                raise
            print('length %d ok' % len(req))
            if req != res:
                raise ValueError()

