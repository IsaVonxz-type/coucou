# Coucou agent notes

- App roots: `NotchBuddy/` is the Swift 6 macOS app; `windows/` contains the Tauri 2 TypeScript/Rust app for Windows and Linux. Follow the platform-specific README when changing one.
- macOS: edit `NotchBuddy/project.yml`, never the generated `NotchBuddy/NotchBuddy.xcodeproj` by hand. Regenerate with `cd NotchBuddy && xcodegen`.
- macOS Debug build: `cd NotchBuddy && xcodegen && xcodebuild -scheme NotchBuddy -configuration Debug build`. CI Release build uses `xcodebuild -project NotchBuddy/NotchBuddy.xcodeproj -scheme NotchBuddy -configuration Release build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO`.
- Windows/Linux commands run from `windows/`: `npm ci`, `npm run tauri dev`, `npm run dev` (browser-only frontend), `npm run build`, and `npm run pack`. `predev`/`prebuild` build Rust `coucou-hook` first. Linux native builds need system packages listed in `windows/README.md`.
- Windows/Linux frontend is `windows/src/`; Tauri backend is `windows/src-tauri/`, split by OS under `src-tauri/src/platform/`; hook relay is `windows/hook/`. macOS app sources are `NotchBuddy/Sources/App/`.
- Visual changes should match `design/prototype/notch-buddy.html` and `design/captures/`; OS-specific setup and differences are documented in `windows/README.md`.
- Treat Claude Code integration as non-blocking: hooks must exit promptly when Coucou is unavailable. Never write `~/.claude/settings.json` or `%USERPROFILE%\.claude\settings.json` without a dated backup, merged diff, and explicit user confirmation; never approve a permission or send email without an explicit click.
- Keep secrets in macOS Keychain or Windows Credential Manager. No telemetry; network access is only for services the user configured.
- Preserve macOS bundle ID `fr.louisraille.NotchBuddy`; preferences and Keychain entries depend on it.
- Rust unit tests live in both workspace crates; run `cargo test --workspace --locked` from `windows/`. No npm test script or macOS test target is configured. Windows and Linux CI build and test on native hosted runners.
- See `CLAUDE.md` for additional macOS constraints and source references; its overview is macOS-focused, so use this file and `windows/README.md` for Windows work.
