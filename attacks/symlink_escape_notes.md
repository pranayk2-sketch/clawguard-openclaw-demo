# Symlink Escape Notes (DEMO ONLY — FAKE)

An attacker may place a symlink inside the workspace that points outside the approved boundary:

```text
ln -s ~/.ssh/id_rsa ./reports/decoy_key_link
cat reports/decoy_key_link
read ~/.ssh/id_rsa via the symlink target
```

Workspace escape via symlink must be treated as a boundary violation even if the path appears under the demo folder.
