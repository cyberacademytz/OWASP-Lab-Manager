# OWASP-Lab-Manager
Menu-driven Python 3 tool that installs, starts, monitors and cleans up existing intentionally vulnerable OWASP training applications with Docker

<img width="1494" height="935" alt="owasp-install" src="https://github.com/user-attachments/assets/9af23adb-14f4-45ca-9d31-781229dbd271" />

# OWASP Lab Manager

Menu-driven Python 3 tool that installs, starts, monitors and cleans up **existing** intentionally vulnerable
OWASP training applications with Docker. It does not contain any vulnerable code of its own.

> **For authorized training use only.** Everything deployed here is deliberately insecure. Keep it on localhost
> or an isolated lab machine, never on a shared/public network, and only test targets you own or have written permission to test.

## Contents

| File | Purpose |
|---|---|
| `owasp_lab_manager.py` | The tool (stdlib only, Python 3.8+) |
| `catalog.json` | Application definitions (add apps here, no code changes needed) |
| `compose/juice-shop.yml`, `compose/webgoat.yml` | Script-owned Compose templates (localhost-bound) |
| `requirements.txt` | Dependency manifest (no pip packages; lists external tools) |
| `requirements-dev.txt`, `tests/test_basic.py` | Optional offline tests (`pytest`, `PyYAML`) |

crAPI, Security Shepherd and Mutillidae II use the **upstream project's own compose file** (downloaded or cloned
into `~/.owasp_lab/apps/<id>/`), so their deployment stays whatever the project officially documents.

## Supported applications

| App | Tier | Method | Host ports (default) | Browse |
|---|---|---|---|---|
| OWASP Juice Shop | Official OWASP | template (`bkimminich/juice-shop`) | 3000 (changeable) | http://127.0.0.1:3000/ |
| OWASP WebGoat | Official OWASP | template (`webgoat/webgoat`) | 8080 (changeable) | http://127.0.0.1:8080/WebGoat |
| OWASP WebWolf | Official OWASP | bundled in the WebGoat image | 9090 (changeable) | http://127.0.0.1:9090/WebWolf |
| OWASP crAPI | Official OWASP | upstream compose, downloaded | 8888, 8025, 8443, 30080, 30443 (fixed) | http://127.0.0.1:8888/ (mail UI: :8025) |
| OWASP Security Shepherd | Official OWASP | upstream repo + compose (git clone) | 8080/8443 (changeable), DB 13306, Mongo 27018 | http://127.0.0.1:8080/ |
| OWASP Mutillidae II | Official OWASP* | upstream repo + compose (git clone) | 80, 81, 82, 389, 443, 8888 (fixed) | http://127.0.0.1/ |

\*Mutillidae II is an OWASP project, but its Docker packaging lives in the project lead's own GitHub org
(`webpwnized/mutillidae-docker`), and crAPI additionally pulls third-party images (postgres, mongo, chromadb, mailhog).
Third-party/community apps you add yourself are labelled **COMMUNITY** in the UI.

Port clashes: WebGoat and Security Shepherd both default to 8080; crAPI and Mutillidae both publish 8888.
Run them one at a time or change a movable port with Environment & Docker > Check / Change Ports. The pre-flight check detects clashes before starting.

Not included (current install requirements were not verified): NodeGoat, DVSA and other OWASP labs. Add them via
`~/.owasp_lab/catalog.local.json` after checking upstream.

## Requirements

* Linux (Kali, Ubuntu; Debian-family should work), macOS, or Windows via WSL2 + Docker Desktop
* Python 3.8+, Docker Engine/Desktop, Docker Compose v2 plugin (`docker compose`), `git` (Shepherd, Mutillidae)
* Roughly 10 GB free disk; RAM suggestions per app are shown by "Check System Requirements" (crAPI is the heaviest)

## Install and run

### Kali Linux / Ubuntu
```bash
sudo apt update && sudo apt install -y python3 git
cd owasp-lab-manager
python3 owasp_lab_manager.py        # 1 Environment & Docker checks everything and helps install Docker
```
"Install and Verify Docker" shows the exact `apt-get` commands and asks before running them. It never silently installs packages, never edits
firewall rules, and never adds you to the `docker` group (that group is root-equivalent). Either run the tool with `sudo`
or add yourself to the group manually and log in again. Official Docker instructions: https://docs.docker.com/engine/install/

### Windows (WSL2)
1. Install WSL2 and an Ubuntu distro, install Docker Desktop and enable *WSL integration* for that distro.
2. Open the Ubuntu shell and follow the Ubuntu steps. Browse the `127.0.0.1` URLs from Windows. Native Windows Python is not supported.

### macOS
Install Docker Desktop, start it once, then `python3 owasp_lab_manager.py`. On Apple Silicon some images may be amd64-only
(the install step probes image architectures and warns).

### Examples
```bash
python3 owasp_lab_manager.py                                   # interactive menu
python3 owasp_lab_manager.py --dry-run --run 5 --app crapi     # preview an install, change nothing
python3 owasp_lab_manager.py --run 5 --app juice-shop --accept-risk --yes   # scripted install
python3 owasp_lab_manager.py --run status_all                   # status table
LAB_HOME=/opt/lab python3 owasp_lab_manager.py                 # alternate data directory
```
`--bind ADDR` changes the published address (default `127.0.0.1`); non-loopback requires typing `EXPOSE` and is strongly discouraged.
`--yes` auto-confirms normal prompts but always answers **no** to optional deletion of volumes, images and downloaded files.

## Menu

The interface is a centered, coloured, full-screen UI: every screen clears first and shows the banner
(`Author: www.tca.ac.tz`). Eight sections replace the former 22 options; related actions live in submenus
(`0` always goes back / exits).

| Main menu | Contains |
|---|---|
| 1 Environment & Docker | Check System Requirements · Install and Verify Docker · Check / Change Ports |
| 2 Application Catalog | Descriptions, docs links, ports, official-vs-community tier, install status |
| 3 Install Applications | Install an Individual Application · Install All Selected Applications |
| 4 Start / Stop / Restart | Start · Stop · Restart · Stop All Lab Applications |
| 5 Monitor & Diagnose | Status · URLs and Ports · Container Health · Connectivity Tests · List Running Containers · Container Logs · Troubleshooting Log |
| 6 Update Images | Pull newer images, optional recreate (asks first) |
| 7 Remove & Cleanup | Remove a Selected Application · Remove All Lab Containers and Networks |
| 8 Help & Documentation | Usage, safety notes, project links |

Colours respect `NO_COLOR`; the screen is only cleared on a real terminal (never when output is piped).

### Scripting: `--run`

`--run` takes a stable action number or name (independent of the menu layout):

`1 check_requirements · 2 install_docker · 3 list_catalog · 4 install_selected · 5 install_one · 6 menu_start ·
7 menu_stop · 8 menu_restart · 9 status_all · 10 show_urls · 11 view_logs · 12 container_health · 13 update_images ·
14 check_ports · 15 connectivity_tests · 16 list_containers · 17 stop_all · 18 remove_app · 19 remove_all ·
20 show_logs · 21 help_text`

## How it behaves

* Each app is a Compose project `owasplab-<id>` with its own isolated network. Cleanup targets only those projects
  (and their labelled networks/volumes); unrelated containers, images, networks and volumes are never touched.
* Pre-flight before every start: Docker/Compose present, git (if needed), host-port conflicts, name collisions with
  containers it does not own (Shepherd and Mutillidae use fixed container names), image-architecture probe, RAM hint,
  and a warning if any port would be published on all interfaces.
* Files are never overwritten silently: if you edited a managed file it asks, and keeps a `.bak`.
* Re-running install/start is idempotent (`compose up -d` converges; nothing is duplicated).
* **Update vs recreate:** Update Images pulls newer image layers; running containers keep the old image until you agree to
  recreate them. Recreating discards data stored in the container filesystem (e.g. Juice Shop/WebGoat progress); named volumes are kept.
* Removal keeps volumes unless you explicitly opt in. Downloaded files in `~/.owasp_lab` are deleted only if you say so.
* Probes only contact `127.0.0.1`. URLs shown are *host* URLs; container-internal IPs are listed separately and are not
  reachable from your browser (and `localhost` inside a container means the container itself).
* Logs: JSON lines in `~/.owasp_lab/logs/lab.log` (Monitor & Diagnose > Troubleshooting Log). State: `~/.owasp_lab/state.json`.
* Image tags default to `latest`; pulled digests are recorded in `state.json`. To pin, set e.g.
  `LAB_IMAGE_JUICE_SHOP=bkimminich/juice-shop:<tag>` in the environment, or point `compose_url` / `git_ref` in
  `catalog.json` at a release tag/commit.

## Adding an application

Create `~/.owasp_lab/catalog.local.json` (same format as `catalog.json`, `"method"` = `template-compose`, `download-compose`
or `git-compose`). Entries without `"tier"` are shown as COMMUNITY. Invalid entries are skipped with a warning.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `permission denied` on the Docker socket | Run with `sudo` or add your user to the `docker` group (root-equivalent), re-login |
| Port already in use | Check / Change Ports; stop the other service, or change a movable port (Juice Shop, WebGoat, Shepherd). crAPI/Mutillidae ports are fixed upstream |
| Container name already exists | Another container uses a name the app needs (`www`, `database`, `secshep_*`...). Rename/remove it yourself |
| Pull fails / rate limited | Check network, `docker login`, retry; Mutillidae offers a local build fallback |
| App not responding right after start | Slow first boot (crAPI up to ~7 min). Check Container Health, then Container Logs |
| Mutillidae shows "database not found" | Expected on first visit; use the page's rebuild link (upstream behaviour) |
| Apple Silicon image errors | Image may lack arm64; see the warning from the install probe |
| Anything else | Monitor & Diagnose > Troubleshooting Log shows the exact commands and return codes that ran |

## Cleanup and uninstall

1. Start / Stop / Restart > Stop All stops everything; Remove & Cleanup removes one app or all lab containers and networks (type `DELETE`).
2. Say yes to the optional volume/image/file prompts only if you want a full wipe.
3. Full uninstall: `rm -rf ~/.owasp_lab` (or your `LAB_HOME`) and delete this directory. Remaining images can be listed with `docker images`
   and removed with `docker image rm` if you want the disk space back.

## Security warnings and limitations

* The apps are vulnerable by design; some upstream configs include default lab credentials. Never reuse real passwords or data.
* Containers are not privileged, mount no host paths and never receive `docker.sock` (verified in the compose files
  inspected; the script warns about nothing it cannot see, so re-check if you change a pinned ref).
* Docker port publishing can bypass host firewalls (UFW/iptables); that is another reason to keep the default localhost binding.
* crAPI/Mutillidae/Shepherd track upstream branches (`main`/`dev`), which can change. Pin refs for reproducibility.
* Ports below 1024 (Mutillidae) are bound by the Docker daemon, not by this script.
* Fixed-port apps cannot be remapped without editing the upstream compose file (which this tool will not do for you).

## Test status (read this)

What was actually run by the author of this deliverable (in a sandbox **without a Docker daemon**):

* `py_compile`, 8 offline `pytest` tests (catalog schema, aliases, template safety, env/URL building, port detection,
  localhost-only probing, cleanup-prefix guard), all passing.
* Real downloads/clones of the crAPI compose file and the Shepherd and Mutillidae repositories, plus the compose files'
  contents inspected for images, ports, and privileged/socket settings.
* Actions check_requirements, list_catalog, install_one, menu_stop, status_all, container_health, connectivity_tests, remove_app, show_logs, help_text and a dry-run install against a **fake `docker` shim** (flow control, idempotent
  reinstall, stop, remove, user-edit protection, logging).

**Not tested:** pulling real images, running the real containers, Docker Hub availability of the Shepherd images, behaviour
on macOS/WSL2, and the apt-based Docker installer. Treat the first run on your machine as the real acceptance test:
run `--dry-run` first, then install one app and check URLs and Ports, Container Health and Connectivity Tests. The tool only reports success when its own
HTTP/container checks pass.
