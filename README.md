# OWASP-Lab-Manager

<img width="1494" height="935" alt="owasp-install" src="https://github.com/user-attachments/assets/9af23adb-14f4-45ca-9d31-781229dbd271" />

# OWASP Lab Manager

A simple menu-driven Python tool that spins up, monitors and tears down the well-known OWASP
vulnerable training apps using Docker. It doesn't ship any vulnerable code of its own — it just
automates pulling and running the official apps so you can get straight to practising.

> **Heads up:** everything this tool deploys is *intentionally* broken and insecure. Keep it on
> localhost or an isolated lab machine, never put it on a shared or public network, and only test
> things you own or have permission to test.

## What's inside

| File | What it's for |
|---|---|
| `owasp_lab_manager.py` | The tool itself — just Python 3.8+, no extra packages needed |
| `catalog.json` | The list of apps it knows about. Add your own without touching the code |
| `compose/juice-shop.yml`, `compose/webgoat.yml` | Compose files it ships for Juice Shop and WebGoat (bound to localhost) |
| `requirements.txt` | Dependency notes (spoiler: there aren't any pip packages) |
| `requirements-dev.txt`, `tests/test_basic.py` | Optional tests if you want to poke under the hood |

For crAPI, Security Shepherd and Mutillidae II, the tool just downloads or clones the **official
compose file straight from the project**, so you always get whatever the maintainers themselves
ship — nothing reinvented here.

## Apps you can spin up

| App | Tier | How it's deployed | Default ports | Open it at |
|---|---|---|---|---|
| OWASP Juice Shop | Official | bundled template (`bkimminich/juice-shop`) | 3000 | http://127.0.0.1:3000/ |
| OWASP WebGoat | Official | bundled template (`webgoat/webgoat`) | 8080 | http://127.0.0.1:8080/WebGoat |
| OWASP WebWolf | Official | ships inside the WebGoat image | 9090 | http://127.0.0.1:9090/WebWolf |
| OWASP crAPI | Official | official compose, downloaded fresh | 8888, 8025, 8443, 30080, 30443 | http://127.0.0.1:8888/ (mail: :8025) |
| OWASP Security Shepherd | Official | official repo, cloned | 8080 / 8443, DB 13306, Mongo 27018 | http://127.0.0.1:8080/ |
| OWASP Mutillidae II | Official project* | official repo, cloned | 80, 81, 82, 389, 443, 8888 | http://127.0.0.1/ |

\* Mutillidae II is an OWASP project, but its Docker setup lives in the maintainer's own GitHub
account rather than the OWASP org — worth knowing if you're being strict about provenance. crAPI
also pulls a few third-party images (Postgres, Mongo, Chroma, MailHog) as part of its own stack.
Anything you add yourself through the local catalog shows up tagged **COMMUNITY** so it's never
confused with the official apps.

A couple of apps share default ports — WebGoat and Shepherd both want 8080, crAPI and Mutillidae
both want 8888 — so run those one at a time, or just remap the movable ones from the menu. The
tool checks for clashes before it starts anything, so you'll know before it fails halfway through.

Not every OWASP lab app made the list — NodeGoat and DVSA, for example, aren't in here because I
haven't personally verified their current setup steps. You're welcome to add them yourself (see
below).

## What you'll need

* Linux (Kali or Ubuntu are the main targets, but any Debian-based distro should be fine), macOS,
  or Windows through WSL2 + Docker Desktop
* Python 3.8+, Docker, the Docker Compose v2 plugin, and `git` if you want Shepherd or Mutillidae
* About 10 GB of free disk space, and a bit more RAM if you're running crAPI (it's the heaviest one)

## Getting started

### Kali Linux / Ubuntu
```bash
sudo apt update && sudo apt install -y python3 git
cd owasp-lab-manager
python3 owasp_lab_manager.py
```
Head into **Environment & Docker** first — it checks everything for you and, if Docker isn't
installed yet, shows you the exact commands to fix it and asks before running anything. It will
never quietly install packages, touch your firewall, or drop you into the `docker` group on its
own (that group is effectively root, so that one's your call). Run the tool with `sudo`, or add
yourself to the group and log back in.

### Windows (via WSL2)
Install WSL2 with an Ubuntu distro, install Docker Desktop, and turn on WSL integration for that
distro. Then just open the Ubuntu shell and follow the steps above. Browse the `127.0.0.1` URLs
from Windows as normal — the tool itself doesn't run on native Windows Python.

### macOS
Install Docker Desktop, start it once, then run `python3 owasp_lab_manager.py`. If you're on
Apple Silicon, keep an eye out — some images are amd64-only and the tool will warn you if it spots
that.

### A few handy commands
```bash
python3 owasp_lab_manager.py                                   # just open the menu
python3 owasp_lab_manager.py --dry-run --run 5 --app crapi     # see what it *would* do, no changes
python3 owasp_lab_manager.py --run 5 --app juice-shop --accept-risk --yes   # fully scripted install
python3 owasp_lab_manager.py --run status_all                   # quick status check
LAB_HOME=/opt/lab python3 owasp_lab_manager.py                 # use a different data folder
```
`--bind` lets you change the address it publishes on (default is `127.0.0.1`), but anything other
than localhost makes you type `EXPOSE` first — on purpose, because that's genuinely not something
you want to do by accident. `--yes` will breeze through the normal prompts for you, but it will
never auto-agree to delete volumes, images, or downloaded files — those always ask.

## Getting around the menu

It's a clean, full-screen interface — clears the screen, shows a banner (`Author: www.tca.ac.tz`),
and groups everything into 8 sections instead of a huge flat list. `0` always takes you back or
exits.

| Section | What's in it |
|---|---|
| 1. Environment & Docker | System checks, Docker install help, port checks |
| 2. Application Catalog | Descriptions, docs links, ports, which apps are official vs community |
| 3. Install Applications | Install one app, or install a batch you've selected |
| 4. Start / Stop / Restart | Start, stop, restart, or stop everything at once |
| 5. Monitor & Diagnose | Status, URLs, container health, connectivity tests, logs |
| 6. Update Images | Pull newer images (asks before recreating anything) |
| 7. Remove & Cleanup | Remove one app, or wipe all lab containers and networks |
| 8. Help & Documentation | Usage notes, safety reminders, project links |

Colours respect `NO_COLOR` if you've got that set, and the screen only clears on a real terminal —
piping the output somewhere won't get weird escape codes mixed in.

### Scripting it

If you want to drive it from a script instead of clicking through the menu, `--run` takes either a
number or a name, and these stay stable even if the menu layout changes:

```
1 check_requirements   2 install_docker      3 list_catalog        4 install_selected
5 install_one          6 menu_start          7 menu_stop           8 menu_restart
9 status_all           10 show_urls          11 view_logs          12 container_health
13 update_images       14 check_ports        15 connectivity_tests 16 list_containers
17 stop_all            18 remove_app         19 remove_all         20 show_logs
21 help_text
```

## How it behaves, in plain terms

- Every app gets its own little Compose project (`owasplab-<id>`) with its own network, so
  cleanup only ever touches what this tool created — nothing else on your machine is at risk.
- Before starting anything, it checks for Docker, port conflicts, name clashes with existing
  containers, whether the image actually supports your CPU, and warns you if a port is about to
  be published more widely than you'd expect.
- It never silently overwrites a file you've edited by hand — it'll ask first and keep a `.bak`.
- Running install or start again doesn't duplicate anything; it just converges to the right state.
- Updating images (option 6) pulls newer layers but keeps your running containers on the old image
  until you say "go ahead and recreate" — and recreating does wipe in-container progress (like
  Juice Shop challenge progress), though named volumes are kept.
- Removing things keeps your data by default. Nothing gets deleted unless you explicitly say yes.
- URLs shown are the ones you can actually open in your browser. There's also a container-internal
  view for the curious, but that's not something you can browse to directly.
- Logs land as JSON lines under `~/.owasp_lab/logs/lab.log`, and state lives in
  `~/.owasp_lab/state.json`.
- Images default to the `latest` tag, and the digest that actually got pulled is recorded for you.
  If you want to pin a specific version, set something like
  `LAB_IMAGE_JUICE_SHOP=bkimminich/juice-shop:<tag>`, or point the catalog at a specific release.

## Adding your own app

Drop a `catalog.local.json` file into `~/.owasp_lab/` using the same shape as `catalog.json`
(`"method"` can be `template-compose`, `download-compose`, or `git-compose`). Anything without a
`"tier"` field just shows up as COMMUNITY. Bad entries get skipped with a warning instead of
crashing the whole tool.

## If something goes wrong

| What you're seeing | What to try |
|---|---|
| `permission denied` talking to Docker | Run with `sudo`, or add yourself to the `docker` group and log back in |
| A port's already taken | Check / Change Ports — stop whatever's using it, or remap (Juice Shop, WebGoat, Shepherd are movable; crAPI and Mutillidae aren't) |
| "Container name already exists" | Something else on your system is using a name this app needs (`www`, `database`, `secshep_*`, etc.) — rename or remove it |
| Image pull fails or gets rate-limited | Check your connection, try `docker login`, or retry — Mutillidae also offers a local build as a fallback |
| App seems stuck right after starting | Give it a minute — crAPI especially can take a while on first boot. Check Container Health, then the logs |
| Mutillidae says "database not found" | Totally normal on first visit — just use the rebuild link on that page |
| Weird errors on Apple Silicon | Some images don't ship arm64 builds — the tool will flag this during install |
| Anything else | Monitor & Diagnose → Troubleshooting Log shows exactly what ran and what came back |

## Cleaning up

1. Stop everything from **Start / Stop / Restart → Stop All**, or remove things properly from
   **Remove & Cleanup** (you'll need to type `DELETE` to confirm the big one).
2. If you actually want a full wipe — volumes, images, downloaded files and all — say yes when it
   asks. Otherwise your data sticks around.
3. For a totally clean slate, delete `~/.owasp_lab` (or wherever you pointed `LAB_HOME`) and this
   project folder. `docker images` / `docker image rm` will clear out any leftover images if you
   want the disk space back.

## Worth knowing before you dive in

- These apps are vulnerable on purpose, and some ship with default lab credentials out of the box.
  Don't reuse real passwords anywhere near them.
- Nothing runs privileged, nothing mounts your host filesystem, and nothing ever gets access to
  the Docker socket — I checked every compose file for this myself.
- Docker's own port publishing can bypass your host firewall rules, which is one more reason to
  just leave everything on localhost.
- crAPI, Shepherd and Mutillidae track their upstream `main`/`dev` branches, so what gets pulled
  can change over time. Pin a specific ref if you need things to stay exactly the same.
- A couple of Mutillidae's ports are under 1024 — Docker handles that binding for you, not this
  script.
- The apps with fixed ports (crAPI, Mutillidae) can't be remapped without editing their upstream
  compose file directly, which this tool deliberately won't do for you.

## Current status

I've run this end-to-end myself and it works — installs cleanly, starts up, shows the right URLs,
and tears back down without leaving a mess behind. If you hit something odd on your own machine,
Monitor & Diagnose → Troubleshooting Log is the first place to look, and it'll usually tell you
exactly what command ran and what it got back.

---

**Author:** www.tca.ac.tz
