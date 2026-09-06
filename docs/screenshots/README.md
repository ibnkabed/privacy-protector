# Screenshots

Three images belong here. They are referenced from `README.md` as HTML comments
until the files exist, so the page never shows a broken image.

| File | What to capture | Referenced from |
|---|---|---|
| `dashboard.png` | The main dashboard with real activity: summary cards, the DNS engine strip, and a populated activity table | Directly under the three opening bullets |
| `classification.png` | One domain's V3 detail: its green/orange/red state, the reason, the evidence, and the confidence | `## User interface` |
| `self-test.png` | The DNS self-test result and the measured coverage state | `## User interface` |

## Sanitize before committing

A capture of this dashboard is a list of the services your own devices contact.
It can reveal your installed applications, your habits, and your network provider.

Before adding any image here:

- Prefer a run seeded with synthetic hostnames (`example.test`, `api.example.test`)
  over a capture of real traffic.
- If you use real traffic, blur or crop every hostname, bundle identifier, and
  application name you are not willing to publish permanently.
- Remove any local IP address, computer name, or Windows user path from the frame,
  including the browser address bar and window title.
- Check the image with the file open at full size, not the thumbnail.

An image committed to a public repository stays in the git history even after a
later commit deletes it. Assume every screenshot you push is permanent.

## Then update README.md

Replace each `<!-- SCREENSHOT: ... -->` comment in `README.md` with the markdown
image line written inside it.
