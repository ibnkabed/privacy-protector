# Screenshots

These three images are referenced from `README.md`.

| File | Shows | Referenced from |
|---|---|---|
| `dashboard.png` | The whole dashboard: summary cards, the engine strip, live activity, and the manual protection actions workspace | Directly under the three opening claims |
| `classification.png` | Activity rows with each hostname's classification, stage, record type, observation count, and confidence | `## User interface` |
| `self-test.png` | The engine strip after a self-test: transports, DoH providers, and classification counts | `## User interface` |

## They contain no private data, by construction

They were not captured from a real device. They come from a throwaway backend
started on temporary ports with an isolated runtime directory, seeded with
well-known public hostnames. Nothing in the frame is personal: the client is the
loopback address, the DNS port is a scratch port, and no Windows path, computer
name, local IP address, or real device hostname appears.

To reproduce them:

1. Start an isolated backend, so your own runtime data is never touched:

   ```powershell
   $env:PRIVACY_PROTECTOR_DATA_DIR = "$env:TEMP\pp-demo"
   python .\app.py --dns-host 127.0.0.1 --dns-port 53153 --web-host 127.0.0.1 --web-port 8790
   ```

2. Send DNS queries for a spread of public hostnames to `127.0.0.1:53153` so the
   activity table and the classification colors are populated.
3. Set a few exact-domain actions through `POST /api/policy`, and run
   `POST /api/dns/self-test`.
4. Open `http://127.0.0.1:8790/` at a viewport of about `1920x1180` and capture.

## If you ever replace them with a real capture

A capture of a live dashboard is a list of the services your own devices contact.
It can reveal your installed applications, your habits, and your network provider.

- Blur or crop every hostname, bundle identifier, and application name you are not
  willing to publish permanently.
- Remove any local IP address, computer name, or Windows user path from the frame,
  including the browser address bar and window title.
- Check the image at full size, not the thumbnail.

An image committed to a public repository stays in the git history even after a
later commit deletes it. Assume every screenshot you push is permanent.
