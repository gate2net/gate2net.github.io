// How each component of the theme is used: the file of a parent component
// that imports it in its `:setup`, writes it as a tag and binds it to its
// own state — as it would be pasted. The demo's inspector shows it, and
// draws it in its preview with the component's code as edited there, so
// every example here is a whole component that runs on its own: no store,
// no API, nothing of the app's. See
// RECORD/2026-10-29.a-design-system.completed.md.

export const TITLES = {
  icon: "Icon",
  button: "Button",
  badge: "Badge",
  alert: "Alert",
  card: "Card",
  facts: "Facts",
  switch: "Switch",
  segmented: "Segmented",
  "choice-cards": "ChoiceCards",
  "otp-input": "OtpInput",
  tabs: "Tabs",
  modal: "Modal",
}

export const USAGE = {
  icon: {
    file: "nav-links.html",
    lead: "Icons by name beside the text they stand for, in its colour. With a label, an icon alone is an image of that name.",
    code: `<script :setup>
  // A row of links, each an icon beside its name, and a light that says
  // the tunnel is up.
  const Icon = await import("@theme/components/icon.html")

  const LINKS = [
    { icon: "globe", label: "Subdomains" },
    { icon: "sliders", label: "Admin" },
    { icon: "user", label: "Account" },
  ]
</script>

<nav class="links">
  <a :each="link in LINKS" :key="link.label" href="#icons">
    <Icon :name="link.icon" weight="light" />{{ link.label }}
  </a>
  <span class="up"><Icon name="success" size="lg" label="Connected" /></span>
</nav>

<style scoped>
  .links { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ig-space-8); }
  a {
    display: inline-flex;
    align-items: center;
    gap: var(--ig-space-2);
    color: var(--ig-fg);
    font-weight: var(--ig-weight-medium);
    text-decoration: none;
  }
  a:hover { color: var(--ig-link); }
  .up { color: var(--ig-green); }
</style>
`,
  },

  button: {
    file: "key-row.html",
    lead: "A row of a list: a primary action, a secondary one, and icons for what can be done to the row. A submit button submits the form around it.",
    code: `<script :setup>
  // A key's name, saved with a button, and the icons for its row.
  const Button = await import("@theme/components/button.html")

  let name = "laptop"
  let saving = false
  let saved = 0
  const save = () => {
    saving = true
    setTimeout(() => {
      saving = false
      saved++
    }, 700)
  }
</script>

<form class="row" @submit.prevent="save">
  <input aria-label="Key name" :value="name" @input="name = $event.target.value">
  <Button type="submit" :disabled="saving">{{ saving ? "Saving…" : "Save" }}</Button>
  <Button variant="secondary" size="sm" icon="plus">Add key</Button>
  <Button variant="ghost" square icon="pencil" title="Rename" />
  <Button variant="ghost-danger" square icon="trash" title="Remove" @click="name = ''" />
</form>
<p class="note">Saved {{ saved }} times.</p>

<style scoped>
  .row { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ig-space-4); }
  input {
    min-height: var(--ig-control-md);
    padding: 0 var(--ig-space-5);
    border: var(--ig-hairline) solid var(--ig-field-line);
    border-radius: var(--ig-radius-control);
    background: var(--ig-field);
    color: var(--ig-fg);
    font: inherit;
  }
  .note { color: var(--ig-fg-muted); font-size: var(--ig-text-sm); }
</style>
`,
  },

  badge: {
    file: "status-cell.html",
    lead: "A subdomain's state, who can open it and how many keys it has, as a list's cells would show them.",
    code: `<script :setup>
  // What a row of the subdomains list says at a glance.
  const Badge = await import("@theme/components/badge.html")
  const Button = await import("@theme/components/button.html")

  let online = true
  const TONES = { public: "accent", users: "warn", private: "bad" }
  let access = "public"
</script>

<p class="cell">
  <Badge :if="online" tone="ok" dot pulse>online</Badge>
  <Badge :else dot>offline</Badge>
  <Badge :tone="TONES[access]">{{ access }}</Badge>
  <Badge size="lg">3 of 10</Badge>
  <Badge tone="ok" solid>2 online</Badge>
</p>
<p class="cell">
  <Button variant="secondary" size="sm" @click="online = !online">{{ online ? "Disconnect" : "Connect" }}</Button>
  <Button variant="secondary" size="sm" @click="access = access === 'public' ? 'users' : access === 'users' ? 'private' : 'public'">Next access</Button>
</p>

<style scoped>
  .cell { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ig-space-3); }
</style>
`,
  },

  alert: {
    file: "add-keys.html",
    lead: "A caveat above a form, and the error a submit came back with inside it. In a grid that spaces its rows itself, flush drops the alert's own space.",
    code: `<script :setup>
  // A form that warns before it is filled, and says what went wrong after.
  const Alert = await import("@theme/components/alert.html")
  const Button = await import("@theme/components/button.html")

  // Every other submit fails, to show both.
  let tries = 0
  let error = ""
  let added = false
  const add = () => {
    tries++
    error = tries % 2 ? "That key is already on another subdomain." : ""
    added = !error
  }
</script>

<Alert tone="warn">Redis accepts anyone without a password by default: keep this port restricted.</Alert>
<form class="form" @submit.prevent="add">
  <Alert :if="error" tone="bad" flush>{{ error }}</Alert>
  <Alert :if="added" tone="ok" flush>Added 1 key.</Alert>
  <div><Button type="submit">Add keys</Button></div>
</form>

<style scoped>
  .form { display: grid; gap: var(--ig-space-5); }
</style>
`,
  },

  card: {
    file: "keys-card.html",
    lead: "A light material that groups one thing, with its title and what goes beside it: a count, an action. Its content is dark on it, whatever it sits on.",
    code: `<script :setup>
  // A subdomain's SSH keys, in a card with their count beside its title.
  const Card = await import("@theme/components/card.html")
  const Badge = await import("@theme/components/badge.html")
  const Button = await import("@theme/components/button.html")

  let keys = ["laptop", "ci"]
</script>

<Card title="SSH keys">
  <template :slot.aside>
    <Badge>{{ keys.length }} of 20</Badge>
    <Button variant="secondary" size="sm" icon="plus" @click="keys = [...keys, 'key ' + (keys.length + 1)]">Add key</Button>
  </template>
  <p class="muted">Only these keys can open the tunnel for myapp.gate.example.com.</p>
  <ul><li :each="key in keys" :key="key">{{ key }}</li></ul>
</Card>

<Card tone="bad" title="Delete subdomain">
  <p>Closes the tunnel and removes myapp.gate.example.com.</p>
</Card>

<style scoped>
  .muted { color: var(--ig-fg-muted); }
</style>
`,
  },

  facts: {
    file: "tunnel-facts.html",
    lead: "Facts about one thing, read and not changed: an item without a value is left out, so a parent can list what it might have.",
    code: `<script :setup>
  // What intergate knows about a connected tunnel.
  const Card = await import("@theme/components/card.html")
  const Facts = await import("@theme/components/facts.html")

  const tunnel = { client: "203.0.113.7", key: "laptop", requests: 128, streams: 3 }
  $: items = [
    { label: "Client", value: tunnel.client, icon: "monitor", hue: "blue" },
    { label: "SSH key", value: tunnel.key, icon: "key", hue: "purple" },
    { label: "Connected", value: "4 minutes ago", icon: "clock", hue: "green" },
    { label: "Requests", value: tunnel.requests, icon: "forward", hue: "orange" },
    { label: "Traffic in / out", value: "1.2 MB / 8.4 MB", icon: "traffic", hue: "teal" },
    { label: "Open streams", value: tunnel.streams, icon: "layers", hue: "pink" },
  ]
</script>

<Card title="Connection">
  <Facts columns="3" :items="items" />
</Card>
`,
  },

  switch: {
    file: "user-row.html",
    lead: "Bound with :model when the parent's variable is the value; with :on when the parent keeps the value itself and saves it from change — here, enabled is the opposite of disabled.",
    code: `<script :setup>
  // A setting in force as soon as it moves, and a user's enabled switch,
  // saved by the row.
  const Switch = await import("@theme/components/switch.html")

  let renew = true
  let user = { email: "alice@example.com", disabled: false }
  const setEnabled = enabled => {
    user = { ...user, disabled: !enabled }
  }
</script>

<div class="rows">
  <div class="row"><Switch :model="renew" label="Renew automatically" /> Renew automatically: {{ renew ? "on" : "off" }}</div>
  <div class="row">
    <Switch :on="!user.disabled" :label="(user.disabled ? 'Enable ' : 'Disable ') + user.email"
            @change="setEnabled($event.detail)" />
    {{ user.email }} is {{ user.disabled ? "disabled" : "enabled" }}
  </div>
</div>

<style scoped>
  .rows { display: grid; gap: var(--ig-space-5); }
  .row { display: flex; align-items: center; gap: var(--ig-space-4); }
</style>
`,
  },

  segmented: {
    file: "client-command.html",
    lead: "Which variant of something to show: the choice goes up through :model, and the parent shows what it names.",
    code: `<script :setup>
  // The command that starts the client, for the system it runs on.
  const Segmented = await import("@theme/components/segmented.html")

  const OS = [{ value: "unix", label: "Linux / macOS" }, { value: "windows", label: "Windows" }]
  const COMMANDS = {
    unix: "curl -fsSL https://gate.example.com/tunnel.sh | sh -s -- myapp",
    windows: "irm https://gate.example.com/tunnel.ps1 | iex",
  }
  let os = "unix"
</script>

<div class="head">
  <p>To forward the ports with the intergate client:</p>
  <Segmented label="Operating system" :model="os" :items="OS" />
</div>
<pre>{{ COMMANDS[os] }}</pre>

<style scoped>
  .head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: var(--ig-space-3); }
  p { margin: 0; }
  pre {
    padding: var(--ig-space-4) var(--ig-space-6);
    overflow-x: auto;
    border-radius: var(--ig-radius-md);
    background: var(--ig-code-surface);
    color: var(--ig-code-fg);
    font-family: var(--ig-font-mono);
    font-size: var(--ig-text-md);
  }
</style>
`,
  },

  "choice-cards": {
    file: "access-picker.html",
    lead: "One of a few, each explained: side by side on a wide screen (row), or one under another (stack) with what the choice asks for under it.",
    code: `<script :setup>
  // Who can open a subdomain, and who can connect to one of its ports.
  const Card = await import("@theme/components/card.html")
  const ChoiceCards = await import("@theme/components/choice-cards.html")

  const ACCESS = [
    { value: "public", label: "Public", hint: "Anyone with the URL", hue: "blue", icon: "globe" },
    { value: "users", label: "Signed-in users", hint: "Anyone who can sign in", hue: "orange", icon: "users" },
    { value: "private", label: "Private", hint: "Only the owner", hue: "pink", icon: "lock" },
  ]
  const WHO = [
    { value: "only", label: "Only these addresses", hint: "One per line", hue: "green", icon: "shield" },
    { value: "anyone", label: "Anyone", hint: "The whole internet", hue: "orange", icon: "globe" },
  ]
  let access = "public"
  let who = "only"
</script>

<Card title="Access">
  <ChoiceCards name="access" :model="access" :items="ACCESS" />
  <p class="muted">Saved as {{ access }}.</p>
</Card>
<Card title="Who can connect">
  <ChoiceCards name="who" layout="stack" :model="who" :items="WHO" />
  <textarea :if="who === 'only'" rows="2" aria-label="Allowed addresses">203.0.113.0/24</textarea>
</Card>

<style scoped>
  .muted { color: var(--ig-fg-muted); }
  textarea {
    width: 100%;
    margin-top: var(--ig-space-4);
    padding: var(--ig-space-3) var(--ig-space-5);
    border: var(--ig-hairline) solid var(--ig-field-line);
    border-radius: var(--ig-radius-control);
    background: var(--ig-field);
    color: var(--ig-fg);
    font-family: var(--ig-font-mono);
  }
</style>
`,
  },

  "otp-input": {
    file: "code-form.html",
    lead: "A one-time code from an email: one field under the boxes, so AutoFill and pasting fill it. The form submits itself once every box is filled; a wrong code turns the boxes red and selects it, to be typed again.",
    code: `<script :setup>
  // The code an email brought, checked as it is filled in. Here 123456 is
  // the right one.
  const Alert = await import("@theme/components/alert.html")
  const Button = await import("@theme/components/button.html")
  const Card = await import("@theme/components/card.html")
  const OtpInput = await import("@theme/components/otp-input.html")

  let code = ""
  let error = ""
  let busy = false
  let done = false

  const verify = () => {
    if (busy) return
    busy = true
    error = ""
    setTimeout(() => {
      busy = false
      if (code === "123456") done = true
      else error = "That code is not right. Check the email and try again."
    }, 400)
  }
</script>

<Card title="Check your email">
  <p :if="done">Signed in.</p>
  <form :else class="form" @submit.prevent="verify">
    <label>Code
      <OtpInput :model="code" group="3" :invalid="!!error" @complete="verify()" />
    </label>
    <Button type="submit" block :disabled="busy">Sign in</Button>
    <Alert :if="error" tone="bad" flush>{{ error }}</Alert>
  </form>
</Card>

<style scoped>
  .form { display: grid; gap: var(--ig-space-7); max-width: 22.5rem; }
  label { display: grid; gap: var(--ig-space-2); font-weight: var(--ig-weight-semibold); }
  p { margin: 0; }
</style>
`,
  },

  tabs: {
    file: "admin-head.html",
    lead: "In a page's head, beside its title; the parent shows the panel the tab names. A count beside a label, a note in green after it, and a tab whose name turns red when chosen.",
    code: `<script :setup>
  // A page in tabs, chosen in its head.
  const Tabs = await import("@theme/components/tabs.html")

  let tab = "users"
  let users = ["owner@example.com", "alice@example.com"]
  $: items = [
    { value: "users", label: "Users", count: users.length },
    { value: "subdomains", label: "Subdomains", count: 4, extra: "2 online" },
    { value: "danger", label: "Danger zone", tone: "bad" },
  ]
</script>

<div class="page-head">
  <h1>Admin</h1>
  <Tabs label="Admin" :model="tab" :items="items" />
</div>
<section :if="tab === 'users'" role="tabpanel" aria-label="Users">
  <p :each="user in users" :key="user">{{ user }}</p>
</section>
<section :elseif="tab === 'subdomains'" role="tabpanel" aria-label="Subdomains"><p>myapp, shop, api, docs</p></section>
<section :else role="tabpanel" aria-label="Danger zone"><p>Nothing here can be undone.</p></section>

<style scoped>
  .page-head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--ig-space-5) var(--ig-space-7);
    margin-bottom: var(--ig-space-7);
  }
  h1 { margin: 0; font-size: var(--ig-text-4xl); letter-spacing: -.022em; }
</style>
`,
  },

  modal: {
    file: "delete-user.html",
    lead: "The owner opens it and closes it: Escape, the close button and a click on the backdrop only ask, through close. What the dialog was about stays until it has played its way out.",
    code: `<script :setup>
  // A list's delete, asked about first.
  const Modal = await import("@theme/components/modal.html")
  const Button = await import("@theme/components/button.html")

  let users = ["alice@example.com", "bob@example.com"]
  let asking = false
  let deleting = ""
  const ask = user => {
    deleting = user
    asking = true
  }
  const remove = () => {
    users = users.filter(user => user !== deleting)
    asking = false
  }
</script>

<ul>
  <li :each="user in users" :key="user">
    {{ user }}
    <Button variant="ghost-danger" square icon="trash" title="Delete" :label="'Delete ' + user" @click="ask(user)" />
  </li>
</ul>
<p :if="!users.length">Nobody left.</p>

<Modal :open="asking" :title="'Delete ' + deleting + '?'" @close="asking = false">
  <p>This removes the account and its passkeys, and closes any tunnel.</p>
  <template :slot.foot>
    <Button variant="secondary" @click="asking = false">Cancel</Button>
    <Button variant="danger" @click="remove()">Delete</Button>
  </template>
</Modal>

<style scoped>
  ul { margin: 0; padding: 0; list-style: none; }
  li { display: flex; align-items: center; justify-content: space-between; max-width: 22.5rem; padding: var(--ig-space-2) 0; }
</style>
`,
  },
}
