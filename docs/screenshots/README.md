# Screenshots

| File | Shows | Referenced from |
|---|---|---|
| `dashboard.png` | The PC view: each planet is a program, with one program's domains open | The top of `README.md` |
| `settings.png` | Settings: a switch for every protection and monitor, and the language | `## User interface` |

## They contain no private data, by construction

They come from a throwaway engine started on scratch ports with its own temporary data folder, seeded
with invented programs (`Chat.exe`, `Browser.exe`, ...) and `.example` domains. Phone and PC protection
were off, so the engine read nothing from the computer it ran on.

To reproduce them, write a few programs and domains into `<folder>\pc\domains.json`, then:

```powershell
$env:PRIVACY_PROTECTOR_DATA_DIR = "$env:TEMP\pp-demo"
python .\app.py --attached --no-tray --dns-port 53153 --web-port 8790
```

and open `http://127.0.0.1:8790/`.

A screenshot of a live dashboard lists the services your own devices contact. Never publish one without
removing every hostname, app name, address and Windows path you are not willing to make permanent: an image
pushed to a public repository stays in its history.
