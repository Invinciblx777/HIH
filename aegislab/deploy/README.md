# Live deployment on a VM

`vm_setup.sh` installs rootless Podman, builds the sandbox image, runs the console as a systemd service and puts Caddy (HTTPS) in front.
Use Ubuntu 24.04. Open TCP 80 and 443 in the cloud firewall first. Then, on the VM:

    curl -fsSL https://raw.githubusercontent.com/Invinciblx777/HIH/deploy-vm/aegislab/deploy/vm_setup.sh | sudo bash

It prints `mode: live` and a single-use operator launch link. Visitors without that link get the read-only console;
only the operator session can create runs. Keep the link private.
