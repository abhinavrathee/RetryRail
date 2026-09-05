# README visual evidence

The PNG files in this directory were captured from the real M7 React
application while its deterministic Playwright workflow supplied typed
synthetic API responses.

They prove the rendered product states and presentation used by the browser
test. They do not independently prove backend or Razorpay behavior; those
claims are backed by separate integration tests and immutable JSON receipts.

Visual scope:

- no live merchant or customer data;
- no Razorpay or OpenAI credential;
- no external provider call;
- synthetic values are visibly labelled; and
- final post-deployment screenshots still belong to M9.

`retryrail-system-map.svg` is a repository-native, script-free vector diagram.
Its labels mirror the implemented M0–M8 authority boundaries documented in
`docs/ARCHITECTURE.md`.

