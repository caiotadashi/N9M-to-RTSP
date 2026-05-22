const form = document.querySelector("#configForm");
const startBtn = document.querySelector("#startBtn");
const stopBtn = document.querySelector("#stopBtn");
const runBadge = document.querySelector("#runBadge");
const statusText = document.querySelector("#statusText");
const sourceText = document.querySelector("#sourceText");
const channelsEl = document.querySelector("#channels");

const inputs = {
  host: document.querySelector("#hostInput"),
  port: document.querySelector("#portInput"),
  user: document.querySelector("#userInput"),
  password: document.querySelector("#passwordInput"),
  streamName: document.querySelector("#streamNameInput"),
};

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function loadConfig() {
  const config = await api("/api/config");
  inputs.host.value = config.host;
  inputs.port.value = config.port;
  inputs.user.value = config.user;
  inputs.password.value = config.password;
  inputs.streamName.value = config.streamName;
  document.querySelectorAll("[data-channel]").forEach((box) => {
    box.checked = Boolean(config.channels[Number(box.dataset.channel)]);
  });
}

async function saveConfig(event) {
  event.preventDefault();
  const channels = [...document.querySelectorAll("[data-channel]")].map((box) => box.checked);
  await api("/api/config", {
    method: "POST",
    body: JSON.stringify({
      host: inputs.host.value.trim(),
      port: Number(inputs.port.value),
      user: inputs.user.value.trim(),
      password: inputs.password.value,
      streamName: inputs.streamName.value.trim(),
      channels,
    }),
  });
  await refreshStatus();
}

async function refreshStatus() {
  const status = await api("/api/status");
  runBadge.textContent = status.running ? "Running" : "Idle";
  runBadge.classList.toggle("running", status.running);
  statusText.textContent = status.status;
  sourceText.textContent = status.source;
  startBtn.disabled = status.running;
  stopBtn.disabled = !status.running;
  renderChannels(status.channels, status.running);
}

function renderChannels(channels, running) {
  channelsEl.innerHTML = channels
    .map((channel) => {
      const active = running && channel.enabled && channel.frames > 0;
      return `
        <article class="channel-card">
          <div class="channel-title">
            <h2>Channel ${channel.channel}</h2>
            <span class="dot ${active ? "active" : ""}"></span>
          </div>
          <div class="stat-row"><span>Enabled</span><strong>${channel.enabled ? "Yes" : "No"}</strong></div>
          <div class="stat-row"><span>Frames</span><strong>${channel.frames}</strong></div>
          <div class="stat-row"><span>FPS</span><strong>${formatFps(channel.fps)}</strong></div>
          <div class="stat-row"><span>Bytes</span><strong>${formatBytes(channel.bytes)}</strong></div>
          <div class="stat-row"><span>Clients</span><strong>${channel.clients}</strong></div>
          <div class="rtsp-url">${channel.rtspUrl}</div>
        </article>
      `;
    })
    .join("");
}

function formatFps(fps) {
  return Number.isFinite(fps) && fps > 0 ? fps.toFixed(1) : "-";
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

form.addEventListener("submit", saveConfig);
startBtn.addEventListener("click", async () => {
  await api("/api/start", { method: "POST", body: "{}" });
  await refreshStatus();
});
stopBtn.addEventListener("click", async () => {
  await api("/api/stop", { method: "POST", body: "{}" });
  await refreshStatus();
});

loadConfig().then(refreshStatus);
setInterval(refreshStatus, 1500);
