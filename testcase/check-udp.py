import sys
import socket
import socks
import time

if __name__ == '__main__':
    port = len(sys.argv) > 1 and int(sys.argv[1]) or 1081
    for x in range(len(sys.argv) > 2 and int(sys.argv[2]) or 1):
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.set_proxy(socks.SOCKS5, "localhost", port)
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
            z = '%s' % y
            req = ((z * 8688) + 'end of websocket').encode('utf8')
            try:
                sock.sendto(req, ('127.0.0.1', 1235))
            except OSError:
                print('%s, length %d ko' % (z, len(req)), file=sys.stderr)
                sock.close()
                break
            try:
                (res, addr) = sock.recvfrom(65535)
            except socket.timeout:
                print('%s, length %d ko (timeout)' % (z, len(req)), file=sys.stderr)
                raise
            print('%s, length %d ok' % (z, len(req)))
            if req != res:
                raise ValueError()
        for y in range(1, 9):
            req = ('c' * 1024 * y).encode('utf8')
            try:
                sock.sendto(req, ('127.0.0.1', 1235))
            except OSError:
                print('length %d ko' % len(req), file=sys.stderr)
                sock.close()
                break
            try:
                (res, addr) = sock.recvfrom(65535)
            except socket.timeout:
                print('length %d ko (timeout)' % len(req), file=sys.stderr)
                raise
            print('length %d ok' % len(req))
            if req != res:
                raise ValueError()
