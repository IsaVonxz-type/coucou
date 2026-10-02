import { Bridge, IS_TAURI, type ChatGPTStatus } from "../core/bridge";
import { h, clear } from "../views/dom";

export function chatgptSection(): HTMLElement {
  const dot = h("i", { class: "dot", "aria-hidden": "true" });
  const accountInfo = h("div", { class: "hint", role: "status", "aria-live": "polite" });
  const feedback = h("div", { role: "status", "aria-live": "polite" });
  const actions = h("div", { class: "row" });
  const picker = h("select", { "aria-label": "ChatGPT account registration" }) as HTMLSelectElement;
  const section = h("section", {},
    h("h2", {}, dot, h("span", { text: "ChatGPT" })),
    h("div", { class: "hint", text: "Connect your ChatGPT account through the official OAuth preview. This step saves your connection; chat support will follow." }),
    accountInfo,
    h("div", { class: "row" }, h("label", { text: "Account", for: "chatgpt-account" }), picker),
    actions,
    feedback,
  );
  picker.id = "chatgpt-account";
  let status: ChatGPTStatus = { pending: false, activeClientId: null, accounts: [], message: null };
  let busy = IS_TAURI;

  function showFeedback(text: string, error: boolean) {
    clear(feedback);
    feedback.append(h("div", { class: error ? "notice err" : "notice ok", text }));
  }

  async function run(operation: () => Promise<ChatGPTStatus>, signingIn = false) {
    busy = true;
    status.pending = signingIn;
    clear(feedback);
    draw();
    try {
      status = await operation();
      if (status.message) showFeedback(status.message, false);
    } catch (err) {
      showFeedback(String(err), true);
      try { status = await Bridge.chatgptStatus(); } catch { status.pending = false; }
    } finally {
      busy = false;
      draw();
    }
  }

  function draw() {
    const active = status.accounts.find((account) => account.clientId === status.activeClientId);
    const connected = active?.connected && active.planEnabled;
    dot.style.background = status.pending ? "#f5a524" : connected ? "#22c55e" : "#9398a1";
    accountInfo.textContent = status.pending
      ? "Finish sign-in in your browser. This attempt expires after five minutes."
      : busy
        ? "Updating ChatGPT connection..."
        : connected
          ? `Connected as ${active.email ?? "ChatGPT account"}. Credentials stay in the OS secure credential store.`
          : "No active ChatGPT session. Continue in your browser to connect.";
    clear(picker);
    if (!status.accounts.length) picker.append(h("option", { text: "No saved accounts", value: "" }));
    for (const [index, account] of status.accounts.entries()) {
      picker.append(h("option", {
        value: account.clientId,
        text: `${account.email ?? "ChatGPT account"} (${index + 1})${account.connected ? "" : " - signed out"}`,
      }));
    }
    picker.value = status.activeClientId ?? "";
    picker.disabled = busy || status.pending || !IS_TAURI || status.accounts.length < 2;
    clear(actions);
    const login = h("button", {
      class: "primary",
      text: connected ? "Reconnect with ChatGPT" : "Continue with ChatGPT",
      onclick: () => void run(() => Bridge.chatgptLogin(status.activeClientId), true),
    });
    login.disabled = busy || status.pending || !IS_TAURI;
    actions.append(login);
    if (status.accounts.length) {
      const add = h("button", { text: "Add account", onclick: () => void run(() => Bridge.chatgptLogin(null), true) });
      add.disabled = busy || status.pending || !IS_TAURI;
      actions.append(add);
    }
    if (active?.connected) {
      const refresh = h("button", { text: "Renew session", onclick: () => void run(() => Bridge.chatgptRefresh()) });
      const logout = h("button", { class: "danger", text: "Sign out", onclick: () => void run(() => Bridge.chatgptLogout()) });
      refresh.disabled = busy || status.pending;
      logout.disabled = busy || status.pending;
      actions.append(refresh, logout);
    }
    if (status.pending) {
      actions.append(h("button", { text: "Cancel sign-in", onclick: () => {
        void Bridge.chatgptCancel().catch((err) => showFeedback(String(err), true));
      } }));
    }
    if (!IS_TAURI) accountInfo.textContent = "ChatGPT sign-in is available in the desktop app.";
  }

  picker.addEventListener("change", () => {
    const id = picker.value;
    if (id) void run(() => Bridge.chatgptSelect(id));
  });
  draw();
  if (IS_TAURI) {
    void Bridge.chatgptStatus().then((value) => { status = value; })
      .catch((err) => showFeedback(String(err), true))
      .finally(() => { busy = false; draw(); });
  }
  return section;
}
