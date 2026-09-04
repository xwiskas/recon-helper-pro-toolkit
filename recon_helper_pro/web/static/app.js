/* Recon Helper Pro dashboard.
 *
 * Two rules this file follows without exception:
 *   1. every value that came from a target is written with textContent, never
 *      innerHTML, so a hostile hostname or header can never become markup;
 *   2. every state-changing request carries the CSRF token from the meta tag.
 */
"use strict";

(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]');
  const CSRF = csrf ? csrf.getAttribute("content") : "";

  async function postJSON(url, body) {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(body || {}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || payload.error || "Request failed (" + response.status + ")");
    }
    return payload;
  }

  async function getJSON(url) {
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || payload.error || "Request failed (" + response.status + ")");
    }
    return payload;
  }

  const runner = document.getElementById("runner");
  if (!runner) return;

  const engagementId = runner.dataset.engagement;
  const targetInput = document.getElementById("target");
  const moduleSelect = document.getElementById("module");
  const modulePicker = document.getElementById("module-picker");
  const overrideWrap = document.getElementById("override-wrap");
  const overrideBox = document.getElementById("override");
  const notice = document.getElementById("scope-notice");
  const startButton = document.getElementById("start");
  const cancelButton = document.getElementById("cancel");
  const progress = document.getElementById("progress");
  const jobStatus = document.getElementById("job-status");
  const logList = document.getElementById("log");
  const resultsBody = document.querySelector("#results tbody");
  const doneLinks = document.getElementById("done-links");

  let currentJob = "";
  let cursor = 0;
  let timer = null;

  function selectedMode() {
    const checked = document.querySelector('input[name="mode"]:checked');
    return checked ? checked.value : "recipe";
  }

  function showNotice(text, kind) {
    notice.textContent = text;
    notice.className = "alert " + (kind || "info");
    notice.hidden = !text;
  }

  function log(line) {
    const item = document.createElement("li");
    item.textContent = line;
    logList.appendChild(item);
    logList.scrollTop = logList.scrollHeight;
  }

  function renderResults(results) {
    resultsBody.replaceChildren();
    results.forEach(function (entry) {
      const row = document.createElement("tr");
      const note = entry.skipped_reason || (entry.errors || []).join(" ") ||
        (entry.warnings || []).slice(0, 1).join(" ") || "";
      const cells = [
        entry.module || "",
        entry.mode || "",
        entry.status || "",
        entry.observations === undefined ? "-" : String(entry.observations),
        entry.findings === undefined ? "-" : String(entry.findings),
        entry.assets === undefined ? "-" : String(entry.assets),
        entry.requests === undefined ? "-" : String(entry.requests),
        note,
      ];
      cells.forEach(function (value, index) {
        const cell = document.createElement("td");
        if (index === 2) {
          const badge = document.createElement("span");
          badge.className = "status status-" + value;
          badge.textContent = value;
          cell.appendChild(badge);
        } else {
          cell.textContent = value;
          if (index === 0) cell.className = "mono";
          if (index === 7) cell.className = "small";
        }
        row.appendChild(cell);
      });
      resultsBody.appendChild(row);
    });
  }

  function setRunning(running) {
    startButton.disabled = running;
    cancelButton.hidden = !running;
    if (running) {
      progress.hidden = false;
      doneLinks.hidden = true;
    }
  }

  async function poll() {
    if (!currentJob) return;
    let snapshot;
    try {
      snapshot = await getJSON("/api/jobs/" + encodeURIComponent(currentJob) + "?cursor=" + cursor);
    } catch (error) {
      jobStatus.textContent = "Lost contact with the run: " + error.message;
      setRunning(false);
      return;
    }
    (snapshot.messages || []).forEach(log);
    cursor = snapshot.cursor || cursor;
    renderResults(snapshot.results || []);

    if (snapshot.finished) {
      window.clearInterval(timer);
      timer = null;
      setRunning(false);
      doneLinks.hidden = false;
      jobStatus.textContent = snapshot.error
        ? snapshot.status + " - " + snapshot.error
        : "Run " + snapshot.status + ". Stored data is on the engagement page.";
      currentJob = "";
    } else {
      jobStatus.textContent = "Running against " + snapshot.target + "...";
    }
  }

  function watch(jobId) {
    currentJob = jobId;
    cursor = 0;
    logList.replaceChildren();
    setRunning(true);
    poll();
    timer = window.setInterval(poll, 1200);
  }

  async function checkScope() {
    const target = targetInput.value.trim();
    if (!target) {
      showNotice("", "info");
      overrideWrap.hidden = true;
      return null;
    }
    // For the recipe, the certificate module is the first step that contacts the
    // target, so it is the right one to ask about.
    const moduleId = selectedMode() === "single" ? moduleSelect.value : "cert";
    let decision;
    try {
      decision = await getJSON(
        "/api/preflight?engagement_id=" + encodeURIComponent(engagementId) +
        "&module=" + encodeURIComponent(moduleId) +
        "&target=" + encodeURIComponent(target)
      );
    } catch (error) {
      showNotice(error.message, "error");
      overrideWrap.hidden = true;
      return null;
    }

    if (!decision.contacts_target) {
      showNotice("This module never contacts the target, so scope does not apply.", "ok");
      overrideWrap.hidden = true;
    } else if (decision.blocked) {
      showNotice(decision.reason + " This cannot be overridden.", "error");
      overrideWrap.hidden = true;
    } else if (decision.needs_override) {
      showNotice(
        decision.reason +
        " Running anyway sends requests to a destination outside your declared scope.",
        "warn"
      );
      overrideWrap.hidden = false;
    } else {
      showNotice(decision.reason, "ok");
      overrideWrap.hidden = true;
      overrideBox.checked = false;
    }
    return decision;
  }

  document.querySelectorAll('input[name="mode"]').forEach(function (radio) {
    radio.addEventListener("change", function () {
      modulePicker.hidden = selectedMode() !== "single";
      checkScope();
    });
  });
  moduleSelect.addEventListener("change", checkScope);
  targetInput.addEventListener("change", checkScope);
  targetInput.addEventListener("blur", checkScope);

  cancelButton.addEventListener("click", async function () {
    if (!currentJob) return;
    try {
      await postJSON("/api/jobs/" + encodeURIComponent(currentJob) + "/cancel", {});
      jobStatus.textContent = "Cancelling...";
    } catch (error) {
      jobStatus.textContent = "Could not cancel: " + error.message;
    }
  });

  startButton.addEventListener("click", async function () {
    const target = targetInput.value.trim();
    if (!target) {
      showNotice("Enter a target first.", "error");
      return;
    }
    const decision = await checkScope();
    if (decision && decision.blocked) return;
    if (decision && decision.needs_override && !overrideBox.checked) {
      showNotice(
        "That destination is out of scope. Tick the confirmation box if you are " +
        "authorized to contact it - the override is recorded in the activity log.",
        "warn"
      );
      return;
    }

    const override = !overrideWrap.hidden && overrideBox.checked;
    try {
      let response;
      if (selectedMode() === "single") {
        response = await postJSON("/api/engagements/" + engagementId + "/run", {
          module: moduleSelect.value,
          target: target,
          override: override,
        });
      } else {
        response = await postJSON("/api/engagements/" + engagementId + "/recipe", {
          target: target,
          override: override,
        });
      }
      watch(response.job_id);
    } catch (error) {
      showNotice(error.message, "error");
    }
  });

  if (runner.dataset.activeJob) {
    watch(runner.dataset.activeJob);
  }
})();
