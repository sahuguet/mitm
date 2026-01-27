You need to add the mitm certificate to support proxying traffic to anthropic.com.

You need to have your MCP servers not running on localhost; use ngrok to make them appear remote.

```
% uv run python mcp_server.py
% ngrok http 8000
```
ngrok will give you a unique url.
Then configure the mcp server accordingly
```
% claude mcp add email-test --transport http --scope project http://mona-noncultured-edison.ngrok-free.dev/mcp
```

Now you can run Claude: you need to make sure you add
- the SSL certificate of mitmproxy, and
- the proxy info
```
% NODE_EXTRA_CA_CERTS=/Users/sahuguet/.mitmproxy/mitmproxy-ca-cert.pem
% HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 claude
```

Then you can capture the traffic.
```
% mitmdump -s mcp_proxy.py --set flow_detail=0
```

## Testing the policy
Now you can test the policy
```
% claude -p "use the email MCP tool, send a random message to arnaud@gmail.com."
% claude -p "use the email MCP tool, send a random message to arnaud@example.com."
```
