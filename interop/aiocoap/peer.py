"""OSCORE peer for the interop tests, using aiocoap.

server PORT CONTEXT: serve /hello, /echo and the observable /counter.
client URI CONTEXT: request URI/hello, URI/echo and three notifications of
URI/counter, printing one line per response.
"""

import asyncio
import sys

import aiocoap
import aiocoap.resource as resource
from aiocoap.credentials import CredentialsMap
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper

class Hello(resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(payload=b"Hello World!")

class Echo(resource.Resource):
    async def render_post(self, request):
        return aiocoap.Message(code=aiocoap.CHANGED, payload=request.payload)

class Counter(resource.ObservableResource):
    def __init__(self):
        super().__init__()
        self.count = 0

    def update_observation_count(self, count):
        if count and not hasattr(self, "task"):
            self.task = asyncio.get_running_loop().create_task(self.tick())

    async def tick(self):
        while True:
            await asyncio.sleep(0.05)
            self.count += 1
            self.updated_state()

    async def render_get(self, request):
        return aiocoap.Message(payload=str(self.count).encode())

def credentials(context, pattern):
    creds = CredentialsMap()
    creds.load_from_dict({pattern: {"oscore": {"contextfile": context}}})
    return creds

async def server(port, context):
    site = resource.Site()
    site.add_resource(["hello"], Hello())
    site.add_resource(["echo"], Echo())
    site.add_resource(["counter"], Counter())
    creds = credentials(context, ":peer")
    wrapped = OscoreSiteWrapper(site, creds)
    await aiocoap.Context.create_server_context(wrapped, bind=("127.0.0.1", int(port)), server_credentials=creds)
    print("ready", flush=True)
    await asyncio.get_running_loop().create_future()

async def client(uri, context):
    ctx = await aiocoap.Context.create_client_context()
    ctx.client_credentials = credentials(context, uri + "/*")
    r = await ctx.request(aiocoap.Message(code=aiocoap.GET, uri=uri + "/hello")).response
    print(r.code, r.payload.decode(), flush=True)
    r = await ctx.request(aiocoap.Message(code=aiocoap.POST, uri=uri + "/echo", payload=b"ping")).response
    print(r.code, r.payload.decode(), flush=True)
    req = ctx.request(aiocoap.Message(code=aiocoap.GET, uri=uri + "/counter", observe=0))
    r = await req.response
    print(r.code, r.payload.decode(), flush=True)
    n = 0
    async for r in req.observation:
        print(r.code, r.payload.decode(), flush=True)
        n += 1
        if n == 3:
            req.observation.cancel()
            break
    await ctx.shutdown()

if __name__ == "__main__":
    mode, arg, context = sys.argv[1:]
    asyncio.run(server(arg, context) if mode == "server" else client(arg, context))
