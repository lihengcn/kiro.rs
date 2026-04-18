---
name: build-kiro-rs-image
description: Build or push the Docker image for the current kiro.rs repository as a linux/amd64 image, defaulting to lihengcn/kiro-rs:latest, without performing docker login.
---

# Build Kiro.rs Image

Use this skill when the user wants to package the current `kiro.rs` repository into a Docker image, especially when they mention:

- `lihengcn/kiro-rs:latest`
- `x86`
- `amd64`
- `docker buildx`
- `推送镜像`

Assume the user has already completed `docker login`. Do not include login steps unless the user explicitly asks for them.

## Execution-first mode

When this skill is triggered, prefer direct execution over explanation.

- Default to running the bundled script immediately.
- Do not restate the skill body to the user.
- Do not provide manual command alternatives unless the user explicitly asks.
- Do not add extra analysis or long explanations unless execution fails.
- Keep commentary minimal: one short progress update before running, then report the result.

## Default behavior

- Image: `lihengcn/kiro-rs:latest`
- Platform: `linux/amd64`
- Output: push to registry
- Context: current repository root

## Preferred workflow

1. Run the bundled script from the repository root:

```bash
.codex/skills/build-kiro-rs-image/scripts/build.sh
```

2. If the user wants a local image instead of pushing, switch to:

```bash
OUTPUT_MODE=load .codex/skills/build-kiro-rs-image/scripts/build.sh
```

3. Only if execution fails unexpectedly, inspect `Dockerfile` or the script to diagnose.

## Supported overrides

Use environment variables when the user wants a different target:

```bash
IMAGE_REPO=lihengcn/kiro-rs \
IMAGE_TAG=latest \
PLATFORM=linux/amd64 \
OUTPUT_MODE=push \
.codex/skills/build-kiro-rs-image/scripts/build.sh
```

## Notes

- `x86` for Docker image builds should be treated as `linux/amd64`.
- The script will create or reuse a `buildx` builder named `kiro-rs-builder`.
- The bundled script can locate the repository root automatically.
- If the user asks for manual commands instead of running the script, provide the equivalent `docker buildx build` command and omit `docker login` by default.
