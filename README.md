# aiosocks
SOCKS proxy client for asyncio and aiohttp

# Requirement
python 3.5+

# Usage
### direct usage
```
import asyncio
from aiosocks import (
  Socks4Server, Socks5Server, Socks4Auth, Socks5Auth, create_connection
)

async def connect():
  socks5_serv = Socks5Server('127.0.0.1', 1080)
  socks4_serv = Socks4Server('127.0.0.1', 1080)
  
  socks5_auth = Socks5Auth('login', 'pwd')
  socks4_auth = Socks4Auth('ident')
  
  # socks5 connect
  transport, protocol = await create_connection(
      lambda: Protocol, proxy=socks5_serv, proxy_auth=socks5_auth, remote_resolve=True)
  
  # socks4 connect
  transport, protocol = await create_connection(
      lambda: Protocol, proxy=socks4_serv, proxy_auth=socks4_auth, remote_resolve=True)
      
  # socks4 without auth and local domain name resolving
  transport, protocol = await create_connection(
      lambda: Protocol, proxy=socks4_serv, proxy_auth=None, remote_resolve=False)


if __name__ == '__main__':
  loop = asyncio.get_event_loop()
  loop.run_until_complete(connect())
  loop.close()
```

### aiohttp usage
```
import asyncio
import aiohttp
from aiosocks import Socks5Server, Socks5Auth
from aiosocks.connector import SocksConnector

async def load_github_main():
  serv = Socks5Server('127.0.0.1', 1080)
  auth = Socks5Auth('proxyuser1', password='pwd')
  
  conn = SocksConnector(proxy=serv, proxy_auth=auth, remote_resolve=False)
  
  with aiohttp.ClientSession(connector=conn) as ses:
    async with session.get('http://github.com/') as resp:
      if resp.status == 200:
        return await resp.text()


if __name__ == '__main__':
  loop = asyncio.get_event_loop()
  loop.run_until_complete()
  loop.close()
```
