import socket
import socks

if __name__ == '__main__':
    for x in range(4):
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.set_proxy(socks.SOCKS5, "localhost", 1081)
        for y in range(65):
            data = ("deadbeef_%d_%d" % (x, y))
            data += 'c'  * (1024 * y - len(data))
            req = data.encode('utf8')
            try:
                sock.sendto(req, ("127.0.0.1", 1235))
            except OSError:
                break
            (res, addr) = sock.recvfrom(65535)
            print("round %d_%d, length: %d" % (x, y, len(data)))
            if req != res:
                raise ValueError
