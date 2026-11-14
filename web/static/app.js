(() => {
  "use strict";

  const vi = document.documentElement.lang === "vi";
  const text = (en, vietnamese) => vi ? vietnamese : en;
  document.querySelector("#language-switch")?.addEventListener("click", () => {
    document.cookie = `rpctl-language=${vi ? "en" : "vi"}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
    location.reload();
  });

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
        status.textContent = text("Loading QR code...", "Đang tải mã QR...");
        status.hidden = false;
        image.hidden = true;
        image.alt = text(`WireGuard QR code for ${peer}`, `Mã QR WireGuard cho ${peer}`);
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
      status.textContent = text("The QR code could not be loaded.", "Không tải được mã QR.");
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
        targetLabel.textContent = full ? text("Full tunnel", "Toàn bộ lưu lượng") : text("Private network", "Mạng riêng");
        description.textContent = full
          ? text("Internet IPv4 traffic will use VPS-1's public IPv4 address. VPS-1 will enable IPv4 forwarding and NAT for the WireGuard subnet. IPv6 is not routed by this mode.", "Lưu lượng Internet IPv4 sẽ dùng địa chỉ IPv4 công khai của VPS-1. VPS-1 bật chuyển tiếp IPv4 và NAT cho mạng WireGuard. Chế độ này không định tuyến IPv6.")
          : text("Only traffic to the WireGuard subnet will use the VPN. Internet traffic will use the device's normal connection.", "Chỉ lưu lượng đến mạng WireGuard đi qua VPN. Lưu lượng Internet dùng kết nối thông thường của thiết bị.");
        peerInput.value = button.dataset.modePeer;
        modeInput.value = full ? "full" : "private";
        confirm.checked = false;
        submit.disabled = false;
        submit.textContent = text("Change mode", "Đổi chế độ");
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
      submit.textContent = text("Changing mode...", "Đang đổi chế độ...");
    });
  };

  const setupUpdateNotification = () => {
    const banner = document.querySelector("#update-banner");
    const version = document.querySelector("#update-version");
    const dismiss = document.querySelector("#update-dismiss");
    const versionCheck = document.querySelector("#version-check");
    const versionCheckStatus = document.querySelector("#version-check-status");
    const latest = document.querySelector("#update-latest");
    const checked = document.querySelector("#update-checked");
    const install = document.querySelector("#update-install");
    const installForm = document.querySelector("#update-install-form");
    if (!banner || !version || !dismiss) {
      return;
    }

    const storageKey = "rpctl-update-dismissed";
    const currentSession = banner.dataset.session || "session";
    const setCheckStatus = (message, state = "") => {
      if (!versionCheckStatus) return;
      versionCheckStatus.textContent = message;
      if (state) {
        versionCheckStatus.dataset.state = state;
      } else {
        delete versionCheckStatus.dataset.state;
      }
    };
    const refresh = async ({ showAfterCheck = false, force = false, announce = false } = {}) => {
      if (installForm?.dataset.installing) return;
      if (install) install.disabled = true;
      if (announce && versionCheck) {
        versionCheck.disabled = true;
        versionCheck.setAttribute("aria-busy", "true");
        setCheckStatus(text("Checking for updates...", "Đang kiểm tra cập nhật..."));
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
        if (installForm?.dataset.installing) return;
        if (latest) latest.textContent = update.latest || text("Unknown", "Chưa xác định");
        if (checked) checked.textContent = update.checked_at ? new Date(update.checked_at).toLocaleString(vi ? "vi-VN" : "en-US") : text("Unknown", "Chưa xác định");
        if (install) install.disabled = !update.available || !update.latest;
        if (!update.available || !update.latest) {
          banner.hidden = true;
          if (announce || latest) {
            setCheckStatus(text(`${update.current || versionCheck?.dataset.version || "Installed version"} is up to date.`, `${update.current || versionCheck?.dataset.version || "Phiên bản đang cài"} đã là bản mới nhất.`), "current");
          }
          return;
        }
        version.textContent = update.latest;
        if (announce || latest) {
          setCheckStatus(text(`New version ${update.latest} is available.`, `Đã có phiên bản mới ${update.latest}.`), "available");
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
        if (announce || latest) {
          setCheckStatus(text("Update check failed. Try again.", "Kiểm tra cập nhật thất bại. Vui lòng thử lại."), "error");
        }
        if (latest) latest.textContent = text("Unavailable", "Không khả dụng");
        if (checked) checked.textContent = text("Check failed", "Kiểm tra thất bại");
        // Keep the dashboard usable when GitHub or the network is unavailable.
      } finally {
        if (announce && versionCheck) {
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

    if (versionCheck) versionCheck.addEventListener("click", () => {
      void refresh({ showAfterCheck: true, force: true, announce: true });
    });

    if (installForm) installForm.addEventListener("submit", (event) => {
      if (!install || install.disabled || !window.confirm(text("Install the latest verified release? The panel may restart briefly.", "Cài bản phát hành mới nhất đã xác minh? Bảng điều khiển có thể khởi động lại trong chốc lát."))) {
        event.preventDefault();
        return;
      }
      installForm.dataset.installing = "true";
      install.disabled = true;
      install.textContent = text("Installing update...", "Đang cài cập nhật...");
      if (versionCheck) versionCheck.disabled = true;
      setCheckStatus(text("Installing update. The panel may briefly disconnect; reconnect after it restarts.", "Đang cài cập nhật. Bảng điều khiển có thể mất kết nối ngắn; hãy kết nối lại sau khi khởi động xong."));
    });

    void refresh();
    window.setInterval(() => void refresh({ showAfterCheck: true, force: true }), 60 * 60 * 1000);
  };

  setupWireGuardQR();
  setupWireGuardMode();
  setupUpdateNotification();
})();
