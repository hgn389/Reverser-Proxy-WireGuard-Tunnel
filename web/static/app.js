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

  const setupUpdateNotification = () => {
    const banner = document.querySelector("#update-banner");
    const version = document.querySelector("#update-version");
    const dismiss = document.querySelector("#update-dismiss");
    if (!banner || !version || !dismiss) {
      return;
    }

    const storageKey = "rpctl-update-dismissed";
    const currentSession = banner.dataset.session || "session";
    const refresh = async (showAfterCheck) => {
      try {
        const response = await fetch("/system/update-status", {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        if (!response.ok) {
          return;
        }
        const update = await response.json();
        if (!update.available || !update.latest) {
          banner.hidden = true;
          return;
        }
        version.textContent = update.latest;
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
        // Keep the dashboard usable when GitHub or the network is unavailable.
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

    void refresh(false);
    window.setInterval(() => void refresh(true), 60 * 60 * 1000);
  };

  setupWireGuardQR();
  setupUpdateNotification();
})();
