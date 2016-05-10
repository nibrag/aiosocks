SOCKS proxy client for asyncio and aiohttp
==========================================
.. image:: https://travis-ci.org/nibrag/aiosocks.svg?branch=master
  :target:  https://travis-ci.org/nibrag/aiosocks
  :align: right

.. image:: https://coveralls.io/repos/nibrag/aiosocks/badge.svg?branch=master&service=github
  :target:  https://coveralls.io/github/nibrag/aiosocks?branch=master
  :align: right

Features
--------
- SOCKS4, SOCKS4a and SOCKS5 version
- SocksConnector for aiohttp
- SOCKS "CONNECT" command

TODO
----
- UDP associate
- TCP port binding

Usage
-----
direct usage
^^^^^^^^^^^^

.. code-block:: python

  import asyncio
  from aiosocks import (
    Socks4Addr, Socks5Addr, Socks4Auth, Socks5Auth, create_connection
  )
  
  async def connect():
    socks5_addr = Socks5Addr('127.0.0.1', 1080)
    socks4_addr = Socks4Addr('127.0.0.1', 1080)
    
    socks5_auth = Socks5Auth('login', 'pwd')
    socks4_auth = Socks4Auth('ident')
  
    dst = ('github.com', 80)
    
    # socks5 connect
    transport, protocol = await create_connection(
        lambda: Protocol, proxy=socks5_addr, proxy_auth=socks5_auth, dst=dst)
    
    # socks4 connect
    transport, protocol = await create_connection(
        lambda: Protocol, proxy=socks4_addr, proxy_auth=socks4_auth, dst=dst)
        
    # socks4 without auth and local domain name resolving
    transport, protocol = await create_connection(
        lambda: Protocol, proxy=socks4_addr, proxy_auth=None, dst=dst, remote_resolve=False)
  
  
  if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(connect())
    loop.close()

aiohttp usage
^^^^^^^^^^^^^

.. code-block:: python

  import asyncio
  import aiohttp
  from aiosocks import Socks5Addr, Socks5Auth
  from aiosocks.connector import SocksConnector
  
  async def load_github_main():
    addr = Socks5Addr('127.0.0.1', 1080)
    auth = Socks5Auth('proxyuser1', password='pwd')
    
    conn = SocksConnector(proxy=addr, proxy_auth=auth, remote_resolve=False)
    
    with aiohttp.ClientSession(connector=conn) as ses:
      async with session.get('http://github.com/') as resp:
        if resp.status == 200:
          print(await resp.text())
  
  
  if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(load_github_main())
    loop.close()
