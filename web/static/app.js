(() => {
  "use strict";

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
})();
