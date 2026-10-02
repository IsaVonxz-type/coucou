# Coucou agent notes

- Two app roots: `NotchBuddy/` is the Swift 6 macOS app; `windows/` is the Tauri 2 app (TypeScript UI, Rust backend and hook relay). Follow the platform-specific README when changing one.
- macOS: edit `NotchBuddy/project.yml`, never the generated `NotchBuddy/NotchBuddy.xcodeproj` by hand. Regenerate with `cd NotchBuddy && xcodegen`.
- macOS Debug build: `cd NotchBuddy && xcodegen && xcodebuild -scheme NotchBuddy -configuration Debug build`. CI Release build uses `xcodebuild -project NotchBuddy/NotchBuddy.xcodeproj -scheme NotchBuddy -configuration Release build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO`.
- Windows commands run from `windows/`: `npm ci` for clean dependency install, `npm run tauri dev` for app development, `npm run dev` for the browser-only frontend, `npm run build` for TypeScript/Vite build, and `npm run pack` for the installer. `predev`/`prebuild` build the Rust `coucou-hook` first.
- Windows frontend is `windows/src/`; Rust app and hook are under `windows/src-tauri/` and `windows/hook/`. macOS app sources are `NotchBuddy/Sources/App/`.
- Visual changes should match `design/prototype/notch-buddy.html` and `design/captures/`; Windows-specific behavior and commands are documented in `windows/README.md`.
- Treat Claude Code integration as non-blocking: hooks must exit promptly when Coucou is unavailable. Never write `~/.claude/settings.json` or `%USERPROFILE%\.claude\settings.json` without a dated backup, merged diff, and explicit user confirmation; never approve a permission or send email without an explicit click.
- Keep secrets in macOS Keychain or Windows Credential Manager. No telemetry; network access is only for services the user configured.
- Preserve macOS bundle ID `fr.louisraille.NotchBuddy`; preferences and Keychain entries depend on it.
- Windows Rust unit tests live in both workspace crates; run `cargo test --workspace` from `windows/`. No npm test script or macOS test target is configured. macOS CI runs a Release build; Windows CI runs `npm ci` then `npm run pack`.
- See `CLAUDE.md` for additional macOS constraints and source references; its overview is macOS-focused, so use this file and `windows/README.md` for Windows work.
