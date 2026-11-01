# G1 Docket — Project Rules

## UI DESIGN & THEMING RULES (STRICT ENFORCEMENT)

1. PALETTE & SURFACES (Light-First Institutional Theme):
   - Primary Background: Warm Alabaster / Slate-50 (`#F8FAFC`)
   - Elevated Surface / Cards: Pure White (`#FFFFFF`)
   - Primary Text: Deep Charcoal (`#0F172A`) — never use pure `#000000`
   - Secondary / Muted Text: Slate-600 (`#475569`)
   - Borders & Hairlines: `1px solid #E2E8F0`
   - Primary Accent: Single restrained brand color (e.g., `#1E293B` for primary actions, `#2563EB` for interactive links).

2. STRICT NEGATIVE CONSTRAINTS (BANNED PATTERNS):
   - NO dark-mode defaults, neon accents, or cyberpunk/crypto color schemes.
   - NO linear or radial color gradients on backgrounds, buttons, or text (`bg-gradient-*`, `bg-clip-text`, `linear-gradient`, `radial-gradient`).
   - NO glassmorphism (`backdrop-blur`, `backdrop-filter: blur(...)`), glowing drop shadows, or floating decorative blobs.
   - NO generic 3-column symmetrical "icon-in-a-colored-circle" feature cards.
   - NO hover-scale animations (`hover:scale-105`) or bounce transitions.

3. TYPOGRAPHY & HIERARCHY:
   - Left-align body copy and section headers by default. Reserve center-alignment strictly for short hero statements.
   - Headings: Tight letter-spacing (`tracking-tight` / `-0.025em`), semi-bold weight (`600`), high contrast against body size.
   - Body: Maximum line width of `65ch` for readability; `1.6` line-height.
   - Data / Metrics: Use `font-variant-numeric: tabular-nums` or a clean monospace font for numbers, timestamps, and specs.

4. SPATIAL ARCHITECTURE:
   - Separate sections using full-width 1px structural borders (`#E2E8F0`) or subtle background shifts (`#F8FAFC` to `#F1F5F9`) rather than floating boxes.
   - Use asymmetric layouts (e.g., 1/3 sticky section header on the left, 2/3 detailed content list on the right).
   - Keep border-radius tight and utilitarian (`4px` to `6px` / `rounded` or `rounded-md`), never pill-shaped (`rounded-full`) or overly bubbly (`rounded-2xl`).
