(() => {
  "use strict";

  const setupWireGuardQR = () => {
    const dialog = document.querySelector("#wireguard-qr-dialog");
    const image = document.querySelector("#wireguard-qr-image");
    const peerLabel = document.querySelector("#wireguard-qr-peer");
    const status = document.querySelector("#wireguard-qr-status");

    if (!dialog || !image || !peerLabel || !status) {
      return;
    }

    document.querySelectorAll("[data-qr-peer]").forEach((button) => {
      button.addEventListener("click", () => {
        const peer = button.dataset.qrPeer;
        if (!peer) {
          return;
        }

        peerLabel.textContent = peer;
        status.textContent = "Loading QR code...";
        status.hidden = false;
        image.hidden = true;
        image.alt = `WireGuard QR code for ${peer}`;
        image.src = `/wireguard/peer/qr?peer=${encodeURIComponent(peer)}`;
        dialog.showModal();
      });
    });

    image.addEventListener("load", () => {
      status.hidden = true;
      image.hidden = false;
    });

    image.addEventListener("error", () => {
      image.hidden = true;
      status.textContent = "The QR code could not be loaded.";
      status.hidden = false;
    });

    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) {
        dialog.close();
      }
    });

    dialog.addEventListener("close", () => {
      image.removeAttribute("src");
      image.alt = "";
      image.hidden = true;
      status.hidden = false;
    });
  };

  const setupWireGuardMode = () => {
    const dialog = document.querySelector("#wireguard-mode-dialog");
    const form = document.querySelector("#wireguard-mode-form");
    if (!dialog || !form) return;
    const peerLabel = document.querySelector("#wireguard-mode-peer");
    const targetLabel = document.querySelector("#wireguard-mode-target");
    const description = document.querySelector("#wireguard-mode-description");
    const peerInput = document.querySelector("#wireguard-mode-input-peer");
    const modeInput = document.querySelector("#wireguard-mode-input-mode");
    const confirm = document.querySelector("#wireguard-mode-confirm");
    const submit = document.querySelector("#wireguard-mode-submit");
    document.querySelectorAll("[data-mode-peer]").forEach((button) => {
      button.addEventListener("click", () => {
        const full = button.dataset.peerMode !== "full";
        peerLabel.textContent = button.dataset.modePeer;
        targetLabel.textContent = full ? "Full tunnel" : "Private network";
        description.textContent = full
          ? "Internet IPv4 traffic will use VPS-1's public IPv4 address. VPS-1 will enable IPv4 forwarding and NAT for the WireGuard subnet. IPv6 is not routed by this mode."
          : "Only traffic to the WireGuard subnet will use the VPN. Internet traffic will use the device's normal connection.";
        peerInput.value = button.dataset.modePeer;
        modeInput.value = full ? "full" : "private";
        confirm.checked = false;
        submit.disabled = false;
        submit.textContent = "Change mode";
        dialog.showModal();
      });
    });
    document.querySelector("#wireguard-mode-cancel").addEventListener("click", () => dialog.close());
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    dialog.addEventListener("close", () => {
      confirm.checked = false;
      peerInput.value = "";
      modeInput.value = "";
    });
    form.addEventListener("submit", () => {
      submit.disabled = true;
      submit.textContent = "Changing mode...";
    });
  };

  const setupUpdateNotification = () => {
    const banner = document.querySelector("#update-banner");
    const version = document.querySelector("#update-version");
    const dismiss = document.querySelector("#update-dismiss");
    const versionCheck = document.querySelector("#version-check");
    const versionCheckStatus = document.querySelector("#version-check-status");
    if (!banner || !version || !dismiss || !versionCheck || !versionCheckStatus) {
      return;
    }

    const storageKey = "rpctl-update-dismissed";
    const currentSession = banner.dataset.session || "session";
    const setCheckStatus = (message, state = "") => {
      versionCheckStatus.textContent = message;
      if (state) {
        versionCheckStatus.dataset.state = state;
      } else {
        delete versionCheckStatus.dataset.state;
      }
    };
    const refresh = async ({ showAfterCheck = false, force = false, announce = false } = {}) => {
      if (announce) {
        versionCheck.disabled = true;
        versionCheck.setAttribute("aria-busy", "true");
        setCheckStatus("Checking for updates...");
      }
      try {
        const endpoint = force ? "/system/update-status?refresh=1" : "/system/update-status";
        const response = await fetch(endpoint, {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const update = await response.json();
        if (!update.available || !update.latest) {
          banner.hidden = true;
          if (announce) {
            setCheckStatus(`${versionCheck.dataset.version} is up to date.`, "current");
          }
          return;
        }
        version.textContent = update.latest;
        if (announce) {
          setCheckStatus(`New version ${update.latest} is available.`, "available");
        }
        let dismissed = null;
        try {
          dismissed = JSON.parse(sessionStorage.getItem(storageKey));
        } catch (_) {
          dismissed = null;
        }
        const checkedAfterDismissal = dismissed && Date.parse(update.checked_at) > Date.parse(dismissed.at);
        if (showAfterCheck || !dismissed || dismissed.session !== currentSession || dismissed.version !== update.latest || checkedAfterDismissal) {
          try {
            sessionStorage.removeItem(storageKey);
          } catch (_) {
            // Browser storage is optional for the notification.
          }
          banner.hidden = false;
        }
      } catch (_) {
        if (announce) {
          setCheckStatus("Update check failed. Try again.", "error");
        }
        // Keep the dashboard usable when GitHub or the network is unavailable.
      } finally {
        if (announce) {
          versionCheck.disabled = false;
          versionCheck.removeAttribute("aria-busy");
        }
      }
    };

    dismiss.addEventListener("click", () => {
      try {
        sessionStorage.setItem(storageKey, JSON.stringify({ session: currentSession, version: version.textContent, at: new Date().toISOString() }));
      } catch (_) {
        // The close button still works when browser storage is unavailable.
      }
      banner.hidden = true;
    });

    versionCheck.addEventListener("click", () => {
      void refresh({ showAfterCheck: true, force: true, announce: true });
    });

    void refresh();
    window.setInterval(() => void refresh({ showAfterCheck: true, force: true }), 60 * 60 * 1000);
  };

  setupWireGuardQR();
  setupWireGuardMode();
  setupUpdateNotification();
})();
