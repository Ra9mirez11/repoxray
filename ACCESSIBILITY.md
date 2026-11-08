# Accessibility Statement

**RepoXray** (`https://repoxray.pages.dev` and `npx rxray`) is committed to ensuring security diagnostics are accessible to all developers, including users of assistive technologies, keyboard-only navigation, and terminal screen readers.

## Supported Environments & Measures

- **Semantic Web Structure:** The web scanner uses semantic landmarks (`<header>`, `<main>`, `<section>`, `<footer>`), explicit `aria-label` attributes on interactive inputs, and real `<button>` / `<input>` controls for full keyboard (`Tab` / `Enter` / `Space`) operability.
- **High-Contrast Typography:** Diagnostic severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) pair text labels with distinct borders and high-contrast foreground colors against dark obsidian surfaces rather than relying on color alone.
- **Zero Layout Shift (CLS):** Ambient backgrounds and Bento cards maintain stable geometry without motion-induced layout shifts.
- **CLI & Machine-Readable Output:** Developers using terminal screen readers or Braille displays can run `npx rxray .` or `npx rxray . --json` as a complete zero-GUI alternative to the web interface.

## Known Limitations

- Drag-and-drop directory intake requires pointer interaction; keyboard and assistive-technology users can use the **Select Local Project Folder** button, the **Scan Any GitHub URL** form, or the `npx rxray` CLI for identical scan coverage.

## Reporting Accessibility Barriers

If you encounter an accessibility barrier in either the Web UI or CLI output, please open an issue at <https://github.com/Ra9mirez11/repoxray/issues> with `[Accessibility]` in the title so we can prioritize a fix.
