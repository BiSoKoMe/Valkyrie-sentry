---
name: Valkyrie Operator Console
description: A monochrome, instrument-grade console for local security decisions.
colors:
  void: "#000000"
  instrument: "#050505"
  raised-instrument: "#0a0a0a"
  primary-ink: "#f7f7f5"
  secondary-ink: "#b8b8b3"
  tertiary-ink: "#858581"
  faint-ink: "#585855"
  hairline: "rgba(255,255,255,.12)"
  strong-hairline: "rgba(255,255,255,.25)"
typography:
  headline:
    fontFamily: "Segoe UI Variable Text, Segoe UI, sans-serif"
    fontSize: "20px"
    fontWeight: 620
    lineHeight: 1.15
    letterSpacing: "-.025em"
  title:
    fontFamily: "Segoe UI Variable Text, Segoe UI, sans-serif"
    fontSize: "12.5px"
    fontWeight: 650
    lineHeight: 1.2
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Cascadia Mono, Consolas, monospace"
    fontSize: "9px"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: ".06em"
rounded:
  control: "2px"
  overlay: "3px"
spacing:
  xs: "6px"
  sm: "10px"
  md: "14px"
  lg: "18px"
  xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.primary-ink}"
    textColor: "{colors.void}"
    rounded: "{rounded.control}"
    padding: "9px 12px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.control}"
    padding: "9px 0"
  instrument-panel:
    backgroundColor: "{colors.instrument}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.control}"
    padding: "14px"
---

# Design System: Valkyrie Operator Console

## Overview

**Creative North Star: "The Incident Instrument"**

Valkyrie looks like calibrated security equipment, not a consumer dashboard and not a science-fiction prop. The interface is dense, quiet, and exact. One current decision is the primary object. Aggregate counters support that decision instead of competing with it.

The console is strictly monochrome. State is communicated with text, fill, border style, line continuity, and weight. It must remain credible when printed in grayscale and understandable without animation.

**Key Characteristics:**

- Pure black field with near-black instrument surfaces.
- Hairline structure instead of decorative containers.
- Compact interface type paired with monospace evidence labels.
- Explicit observed, inferred, missing, dry-run, and enforced states.
- Local and offline posture stated in the shell, not hidden in settings.

## Colors

The palette is neutral and functional. White is both the strongest text color and the only high-emphasis fill.

### Primary

- **Calibration White**: Used for selected states, primary text, focus, and the active causal stage.

### Neutral

- **Absolute Void**: The application field and deepest background.
- **Instrument Black**: Panels, ledgers, and controls separated from the field by hairlines.
- **Secondary Ink**: Explanatory copy and inactive navigation.
- **Tertiary Ink**: Labels, timestamps, and supporting metadata.
- **Structural Hairline**: Panel boundaries, row rules, and evidence joins.

### Named Rules

**The Monochrome Evidence Rule.** Never rely on hue to communicate severity, certainty, or action. Pair every state with words and structural treatment.

**The White Is Rare Rule.** Solid white fill is reserved for the selected causal stage and the primary action.

## Typography

**Display Font:** Segoe UI Variable Text with Segoe UI fallback
**Body Font:** Segoe UI Variable Text with Segoe UI fallback
**Label/Mono Font:** Cascadia Mono with Consolas fallback

**Character:** Interface text is compact and neutral. Evidence text is technical, tabular, and easy to copy. The application bundles no remote font dependency.

### Hierarchy

- **Headline** (620, 20px, 1.15): Protection posture and the strongest page statement.
- **Title** (650, 12.5px, 1.2): Panel names and investigation regions.
- **Body** (400, 13px, 1.45): Explanations and operator guidance.
- **Label** (400, 9px, .06em, uppercase): Evidence state, telemetry labels, and calibration metadata.

### Named Rules

**The Evidence Has a Different Voice Rule.** PIDs, domains, timestamps, hashes, states, and measurements use the monospace role. Explanations do not.

## Layout

The desktop shell uses a fixed navigation rail and a remaining-width content region. The top bar is persistent. The overview begins with protection posture, then compact telemetry, then the latest causal story and its authority inspector.

Spacing follows a compact 6, 10, 14, 18, and 24 pixel rhythm. At narrower desktop widths the six telemetry cells become two rows of three, the evidence inspector moves below the causal story, and the navigation rail collapses to icons. The application does not target phone-sized layouts.

## Elevation & Depth

The system is flat by default. Depth comes from tonal steps and hairline borders. Shadows are reserved for modal overlays and command surfaces that must sit above the application, never for routine panels.

### Named Rules

**The Ledger Before Shadow Rule.** Use a divider, inset, or tonal step before considering a shadow.

## Shapes

Controls and panels use restrained two-pixel corners. Overlays may use three-pixel corners. Evidence joins are straight lines. Missing evidence uses dashed borders, inferred evidence uses double borders, and observed evidence uses solid borders.

## Components

### Buttons

- **Shape:** Tight instrument rectangle (2px radius).
- **Primary:** White fill, black text, compact padding.
- **Hover / Focus:** Underline for text actions; a visible neutral outline for keyboard focus.
- **Ghost:** Transparent background with hairline separators when it belongs to an evidence panel.

### Chips

- **Style:** Transparent or near-black fill, one-pixel border, uppercase monospace label.
- **State:** Meaning is written in the chip. Dots or borders reinforce it but never replace the label.

### Cards / Containers

- **Corner Style:** Tight instrument corners (2px radius).
- **Background:** Near-black surface over the pure black field.
- **Shadow Strategy:** None at rest.
- **Border:** One-pixel neutral hairline.
- **Internal Padding:** Usually 12 to 14 pixels.

### Inputs / Fields

- **Style:** Near-black field, one-pixel border, two-pixel corner.
- **Focus:** Two-pixel neutral outline with offset.
- **Disabled:** Dimmed text with the reason kept visible.

### Navigation

The active row is white with black text. Inactive rows are unfilled. Section names use compact uppercase monospace labels. The rail collapses to icons at narrow desktop widths while counts remain visible.

### Causal Decision Story

Five ordered stages describe origin, actor, request, consequence, and verdict. The selected stage is white. Join lines indicate whether provenance is continuous. The inspector always distinguishes evidence present, evidence missing, and the authority boundary.

## Do's and Don'ts

### Do:

- **Do** make the current protection posture readable before any metric.
- **Do** show why Valkyrie acted and what evidence it lacked.
- **Do** keep controls square, compact, and usable by keyboard.
- **Do** preserve explicit local-only and authority-boundary language.

### Don't:

- **Don't** introduce gradients, glow, glass panels, or decorative cybersecurity imagery.
- **Don't** turn every metric into an isolated rounded card.
- **Don't** imply that inferred evidence was observed.
- **Don't** advertise AI as part of the runtime decision path.
- **Don't** use color as the only carrier of meaning.
