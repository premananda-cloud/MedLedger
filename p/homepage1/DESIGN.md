---
name: Ubiquitous Connect
colors:
  surface: '#f9f9f9'
  surface-dim: '#dadada'
  surface-bright: '#f9f9f9'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f3f3f4'
  surface-container: '#eeeeee'
  surface-container-high: '#e8e8e8'
  surface-container-highest: '#e2e2e2'
  on-surface: '#1a1c1c'
  on-surface-variant: '#3c4a3d'
  inverse-surface: '#2f3131'
  inverse-on-surface: '#f0f1f1'
  outline: '#6c7b6b'
  outline-variant: '#bbcbb9'
  surface-tint: '#E6FFDA'
  primary: '#006d2f'
  on-primary: '#ffffff'
  primary-container: '#25d366'
  on-primary-container: '#005523'
  inverse-primary: '#3de273'
  secondary: '#556067'
  on-secondary: '#ffffff'
  secondary-container: '#d9e4ec'
  on-secondary-container: '#5b666d'
  tertiary: '#625e56'
  on-tertiary: '#ffffff'
  tertiary-container: '#bdb7ae'
  on-tertiary-container: '#4c4841'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#66ff8e'
  primary-fixed-dim: '#3de273'
  on-primary-fixed: '#002109'
  on-primary-fixed-variant: '#005322'
  secondary-fixed: '#d9e4ec'
  secondary-fixed-dim: '#bdc8d0'
  on-secondary-fixed: '#131d23'
  on-secondary-fixed-variant: '#3e484f'
  tertiary-fixed: '#e8e2d8'
  tertiary-fixed-dim: '#ccc6bc'
  on-tertiary-fixed: '#1e1b16'
  on-tertiary-fixed-variant: '#4a463f'
  background: '#f9f9f9'
  on-background: '#1a1c1c'
  surface-variant: '#e2e2e2'
  dark-alt: '#202C33'
  border-light: '#E9EDEF'
typography:
  display-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
  headline-lg-mobile:
    fontFamily: Plus Jakarta Sans
    fontSize: 28px
    fontWeight: '700'
    lineHeight: 36px
  headline-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.01em
  label-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 14px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 4px
  xs: 8px
  sm: 16px
  md: 24px
  lg: 48px
  xl: 80px
  gutter: 20px
  margin-mobile: 16px
  margin-desktop: 64px
---

## Brand & Style

This design system is built on the principles of clarity, accessibility, and reliability. It evokes an approachable yet secure aesthetic, prioritizing high-legibility communication and effortless navigation. The brand personality is "Human & Global"—designed to feel familiar to billions while maintaining a crisp, modern edge that signals technological robustness.

The design style follows a **Modern Corporate** approach with subtle **Minimalist** influences. It utilizes generous whitespace to reduce cognitive load, a focused color palette to drive action, and soft, organic shapes to maintain a friendly, non-intimidating presence. Visual hierarchy is established through clear typographic scaling and intentional use of the signature green to highlight connectivity and status.

## Colors

The color palette is centered around the iconic WhatsApp Green, symbolizing growth and connectivity. 

- **Primary Green (#25D366):** Reserved for primary actions, success states, and brand recognition.
- **Deep Navy (#111B21):** Used for primary text and high-contrast backgrounds to ensure maximum readability and a sense of security.
- **Warm Sand (#FCF5EB):** An off-white neutral used for background sections to reduce eye strain and provide a softer visual transition than pure white.
- **Mint Tint (#E6FFDA):** Specifically used for message bubbles or highlighted containers to create a distinct secondary "on-surface" layer.

The default color mode is light, emphasizing transparency and cleanliness.

## Typography

This design system uses **Plus Jakarta Sans** as the core typeface across all levels. It mirrors the approachable, rounded, and highly legible characteristics of "WhatsApp Sans." 

Headlines use semi-bold and bold weights to provide structural grounding, while body text maintains a generous line height to ensure comfortable reading across long threads or documentation. Mobile-specific overrides for large display text prevent layout breakage on narrow viewports. Label styles are tighter and slightly more tracked out for utility-based UI elements like timestamps or metadata.

## Layout & Spacing

The layout philosophy follows a **Fluid Grid** model that prioritizes content flow. 

- **Desktop:** A 12-column grid with a maximum content width of 1280px. Gutters are fixed at 20px to maintain a compact, efficient feel.
- **Mobile:** A 4-column grid with 16px side margins. 

Spacing follows a 4px baseline rhythm. Padding within components should prioritize internal "breathing room" (usually 12px or 16px) to ensure touch targets are accessible. Content should reflow vertically on mobile, with horizontal scrolling reserved strictly for status stories or chip filters.

## Elevation & Depth

Depth is conveyed primarily through **Tonal Layers** rather than heavy shadows, keeping the UI flat and fast.

- **Level 0 (Floor):** Uses the Warm Sand (#FCF5EB) or Neutral White (#FFFFFF) for the base canvas.
- **Level 1 (Cards/Bubbles):** Uses the Mint Tint (#E6FFDA) or pure White with a 1px border (#E9EDEF) to define interactive zones.
- **Level 2 (Modals/Popovers):** Uses a very soft, ambient shadow (0px 4px 12px, 5% opacity Navy) to separate temporary overlays from the main content.

Outlines are preferred over shadows for input fields and list items to maintain the "clean and secure" brand promise.

## Shapes

The shape language is **Rounded**, reflecting a soft, friendly, and non-aggressive UI. 

- **Standard Buttons & Inputs:** Use the base 0.5rem (8px) radius.
- **Message Bubbles:** Use the `rounded-lg` (16px) radius to emphasize a chat-centric container style.
- **Search Bars & Badges:** Use the `rounded-xl` or full pill-shape to distinguish them from primary action containers.
- **Profile Icons:** Are always circular.

## Components

- **Buttons:** Primary buttons are solid Primary Green (#25D366) with Navy text or White text depending on contrast needs. Secondary buttons are outlined or use the Warm Sand background.
- **Chips:** Highly rounded (pill) with a light gray background, moving to Primary Green when selected.
- **Lists:** Clean, border-bottom separated rows (#E9EDEF) with ample 16px horizontal padding. Icons are typically 24x24px.
- **Checkboxes & Radios:** Use the Primary Green for the active state. The "Check" icon should be clean and thin.
- **Input Fields:** Flat styling with a 1px border. On focus, the border transitions to Primary Green with a subtle inset shadow to denote active engagement.
- **Cards:** Low elevation. Often used to group settings or features on a landing page, utilizing the Warm Sand background for the card body and White for the inner content.
- **Message Bubbles:** Tailored containers with asymmetrical rounding (e.g., sharper corner on the side of the sender) to denote directionality.