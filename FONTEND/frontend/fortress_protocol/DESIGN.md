---
name: Fortress Protocol
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#c7c4d7'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#908fa0'
  outline-variant: '#464554'
  surface-tint: '#c0c1ff'
  primary: '#c0c1ff'
  on-primary: '#1000a9'
  primary-container: '#8083ff'
  on-primary-container: '#0d0096'
  inverse-primary: '#494bd6'
  secondary: '#b9c8de'
  on-secondary: '#233143'
  secondary-container: '#39485a'
  on-secondary-container: '#a7b6cc'
  tertiary: '#4edea3'
  on-tertiary: '#003824'
  tertiary-container: '#00885d'
  on-tertiary-container: '#000703'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e1e0ff'
  primary-fixed-dim: '#c0c1ff'
  on-primary-fixed: '#07006c'
  on-primary-fixed-variant: '#2f2ebe'
  secondary-fixed: '#d4e4fa'
  secondary-fixed-dim: '#b9c8de'
  on-secondary-fixed: '#0d1c2d'
  on-secondary-fixed-variant: '#39485a'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.02em
  label-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.04em
  mono-data:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  2xl: 48px
  3xl: 64px
  gutter: 24px
  margin: 32px
---

## Brand & Style
The brand personality centers on absolute reliability, technical precision, and unwavering security. This design system targets professionals and enterprises who require a "digital vault" experience where the UI itself acts as a visual guarantee of safety.

The design style is **Corporate / Modern** with a lean toward **Technical Minimalism**. It prioritizes clarity over decoration, using structured layouts and high-fidelity metaphors (keys, shields, locks) to communicate state. The emotional response should be one of calm confidence—reducing the anxiety associated with sensitive data handling through a stable, predictable, and highly legible interface.

## Colors
The palette is built on a foundation of "Deep Trust" tones. The primary color is a vibrant Indigo, used purposefully for action and highlights.

- **Dark Mode (Default):** Uses a palette of Charcoal (`#0F172A`) and Obsidian (`#020617`) to create a sense of depth and focus. High-contrast Slate borders provide structural definition without visual clutter.
- **Light Mode:** Shifts to a crisp White background with Slate (`#94A3B8`) and Light Gray (`#F8FAFC`) surfaces to maintain the professional, clinical aesthetic.
- **Status Indicators:** Success (Green), Error (Red), and Warning (Amber) are used strictly for functional feedback, ensuring that system status is immediately perceivable.

## Typography
The typography system utilizes **Inter** for its exceptional legibility and neutral, professional character across all standard UI elements. For technical metadata, encryption keys, and status labels, **Geist** is introduced to provide a subtle "developer-grade" precision.

- **Scale:** Large headlines are reserved for dashboard overviews and empty states. On mobile, `headline-lg` scales down to 24px.
- **Data Hierarchy:** Use `mono-data` for file paths, ID strings, and checksums to emphasize the technical integrity of the platform.
- **Weight:** Use Semibold (600) for interactive elements and Medium (500) for labels to maintain a clear visual hierarchy.

## Layout & Spacing
The layout follows a **Fixed-Fluid Hybrid** model. Navigation and sidebars are fixed-width to provide a stable frame, while the central workspace is fluid to accommodate dense data tables and file grids.

- **Grid:** Use a 12-column grid for desktop views with 24px gutters.
- **Rhythm:** An 8px base unit governs all padding and margins. 
- **Breakpoints:** 
  - **Mobile (<640px):** Single column, 16px side margins.
  - **Tablet (640px - 1024px):** 8-column grid, 24px margins.
  - **Desktop (>1024px):** 12-column grid, 32px margins, maximum content width of 1440px.

## Elevation & Depth
Depth is conveyed through **Tonal Layers** and **Subtle Outlines** rather than aggressive shadows. This reinforces the "Solid and Dependable" brand pillar.

- **Surface Levels:** The background is the lowest level. Cards and containers sit one level higher with a slightly lighter hex code and a 1px border.
- **Borders:** Every container must have a 1px solid border (`#1E293B` in dark mode). This creates a structural "vault-like" grid.
- **Shadows:** Use a single, highly-diffused shadow for floating elements like modals or dropdowns (e.g., `0px 10px 15px -3px rgba(0, 0, 0, 0.5)`). Avoid shadows on standard cards to keep the UI feeling grounded.

## Shapes
The shape language is **Soft (0.25rem)**. Elements are slightly rounded to feel modern and accessible, but remain close to right angles to maintain a serious, architectural feel.

- **Small elements:** Buttons and input fields use a `0.25rem` radius.
- **Large elements:** Cards and modals use a `0.5rem` (rounded-lg) radius.
- **Icons:** Icons should be enclosed in a squared-off container with a `0.25rem` radius when used as status indicators.

## Components
- **Buttons:** Primary buttons are solid Indigo with white text. Secondary buttons use a Ghost style (transparent background with a Slate border). All buttons have a subtle inner glow on hover to simulate a physical mechanical press.
- **Input Fields:** These are the core of the secure experience. They feature a dark background, a 1px border that glows Indigo on focus, and clear "Success" validation icons when data requirements are met.
- **Cards:** Cards are the primary container for files and keys. They use a subtle gradient from the top-left to signify light hitting a solid surface.
- **Status Chips:** Small, rectangular labels with low-opacity background tints and high-contrast text (e.g., "Encrypted", "Verified").
- **Activity Feed:** A vertical list using `mono-data` typography to show a real-time audit log of file access, emphasizing transparency and security.
- **Encryption Visualizer:** A unique component that shows a "progress" state during file uploads with shifting hex-code strings to visually represent the encryption process.