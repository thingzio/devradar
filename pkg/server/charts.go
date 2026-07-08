package server

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
)

// Server-rendered inline-SVG charts — no client JS/chart library, matching the
// "boring, self-contained" stance. Each helper returns safe template.HTML.

// severity fill colors (match the CSS --sev-* scale closely enough for SVG).
var svgSev = map[string]string{
	"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700",
	"low": "#0969da", "negligible": "#57606a", "unknown": "#8b949e",
}

// slice is one wedge of a donut chart.
type slice struct {
	Label string
	Value int
	Sev   string // severity key → color (via svgSev)
	Color string // explicit fill; wins over Sev when set (e.g. license palette)
}

// sliceFill resolves a slice's fill: an explicit Color wins, then the severity
// map, then the accent fallback.
func sliceFill(s slice) string {
	if s.Color != "" {
		return s.Color
	}
	if f := svgSev[s.Sev]; f != "" {
		return f
	}
	return "#4a9eff"
}

// donutChart renders a donut (ring) chart with a centered total and a legend to
// the right. Wedges are drawn clockwise from 12 o'clock in the order given.
// centerLabel is the caption under the big total (e.g. "findings").
func donutChart(slices []slice, centerLabel string, size int) template.HTML {
	total := 0
	for _, s := range slices {
		total += s.Value
	}
	if total == 0 {
		return template.HTML(`<p class="muted">No findings at or above your threshold.</p>`)
	}
	const (
		stroke  = 34  // ring thickness
		legendW = 150 // room for the legend column
		gap     = 24
	)
	r := float64(size)/2 - stroke/2
	cx, cy := float64(size)/2, float64(size)/2
	circ := 2 * math.Pi * r
	viewW := size + gap + legendW

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart donut" viewBox="0 0 %d %d" width="100%%" height="%d" role="img">`,
		viewW, size, size)
	// track ring (subtle background)
	fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="var(--surface-alt)" stroke-width="%d"></circle>`,
		cx, cy, r, stroke)
	// wedges: rotate the whole ring -90° so offsets start at 12 o'clock.
	offset := 0.0
	for _, s := range slices {
		if s.Value == 0 {
			continue
		}
		frac := float64(s.Value) / float64(total)
		dash := frac * circ
		fill := sliceFill(s)
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="%s" stroke-width="%d" `+
			`stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %.1f %.1f)">`+
			`<title>%s: %d (%.0f%%)</title></circle>`,
			cx, cy, r, fill, stroke, dash, circ-dash, -offset*circ, cx, cy,
			template.HTMLEscapeString(s.Label), s.Value, frac*100)
		offset += frac
	}
	// center total
	fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" class="donut-total">%d</text>`,
		cx, cy-2, total)
	fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" class="donut-sub">%s</text>`,
		cx, cy+16, template.HTMLEscapeString(centerLabel))
	// legend
	lx := size + gap
	ly := (size - len(slices)*22) / 2
	for i, s := range slices {
		y := ly + i*22
		fill := sliceFill(s)
		frac := 0.0
		if total > 0 {
			frac = float64(s.Value) / float64(total) * 100
		}
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="11" height="11" rx="2" fill="%s"></rect>`, lx, y, fill)
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="chart-lbl">%s</text>`,
			lx+18, y+10, template.HTMLEscapeString(fmt.Sprintf("%s  %d (%.0f%%)", s.Label, s.Value, frac)))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// hbar is one row of a horizontal bar chart.
type hbar struct {
	Label string
	Value int
	Sev   string // severity key → bar color; "" uses accent
	Sub   string // optional right-aligned subtext (e.g. "12 fixable")
}

// hbarChart renders a horizontal bar chart as inline SVG. Bars are scaled to the
// max value; labels sit to the left, values to the right. Rows are drawn in the
// order given (caller sorts).
func hbarChart(rows []hbar, width int) template.HTML {
	if len(rows) == 0 {
		return template.HTML(`<p class="muted">No data.</p>`)
	}
	const (
		rowH   = 26
		labelW = 150
		valW   = 90
		pad    = 4
	)
	maxV := 1
	for _, r := range rows {
		if r.Value > maxV {
			maxV = r.Value
		}
	}
	barMax := width - labelW - valW - pad*2
	if barMax < 40 {
		barMax = 40
	}
	h := len(rows)*rowH + pad*2
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %d %d" width="100%%" height="%d" role="img">`, width, h, h)
	for i, r := range rows {
		y := pad + i*rowH
		bw := r.Value * barMax / maxV
		if bw < 1 && r.Value > 0 {
			bw = 1
		}
		fill := svgSev[r.Sev]
		if fill == "" {
			fill = "#4a9eff"
		}
		// label (truncated by SVG clip via text-overflow isn't available; keep short)
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="chart-lbl" text-anchor="end">%s</text>`,
			labelW, y+rowH/2+4, template.HTMLEscapeString(trunc(r.Label, 22)))
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="2" fill="%s"></rect>`,
			labelW+pad, y+4, bw, rowH-10, fill)
		val := fmt.Sprintf("%d", r.Value)
		if r.Sub != "" {
			val += "  " + r.Sub
		}
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="chart-val">%s</text>`,
			labelW+pad+bw+6, y+rowH/2+4, template.HTMLEscapeString(val))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// remedRow is one severity's remediation split: how many findings have a fix
// available now (Fixable) out of the total (Total) at that severity.
type remedRow struct {
	Label   string
	Sev     string
	Fixable int
	Total   int
}

// remediationChart renders, per severity, a full-width track (total findings)
// with a solid overlay for the fixable-now subset — a "what can I act on today"
// view. The fixable overlay uses the severity color; the remaining (no-fix-yet)
// track is muted. A right-aligned "X of Y fixable" caption quantifies each row.
func remediationChart(rows []remedRow, width int) template.HTML {
	maxV := 1
	any := false
	for _, r := range rows {
		if r.Total > maxV {
			maxV = r.Total
		}
		if r.Total > 0 {
			any = true
		}
	}
	if !any {
		return template.HTML(`<p class="muted">No findings at or above your threshold.</p>`)
	}
	const (
		rowH   = 30
		labelW = 70
		valW   = 120
		pad    = 4
	)
	barMax := width - labelW - valW - pad*2
	if barMax < 40 {
		barMax = 40
	}
	h := len(rows)*rowH + pad*2
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %d %d" width="100%%" height="%d" role="img">`, width, h, h)
	for i, r := range rows {
		y := pad + i*rowH
		totalW := r.Total * barMax / maxV
		if totalW < 1 && r.Total > 0 {
			totalW = 1
		}
		fixW := 0
		if r.Total > 0 {
			fixW = r.Fixable * totalW / r.Total
		}
		fill := svgSev[r.Sev]
		if fill == "" {
			fill = "#4a9eff"
		}
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="chart-lbl" text-anchor="end">%s</text>`,
			labelW, y+rowH/2+4, template.HTMLEscapeString(r.Label))
		// full track (no-fix-yet portion, muted)
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="2" fill="var(--surface-alt)"></rect>`,
			labelW+pad, y+6, totalW, rowH-14)
		// fixable overlay (severity color)
		if fixW > 0 {
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="2" fill="%s"><title>%s: %d of %d fixable now</title></rect>`,
				labelW+pad, y+6, fixW, rowH-14, fill, template.HTMLEscapeString(r.Label), r.Fixable, r.Total)
		}
		caption := fmt.Sprintf("%d of %d fixable", r.Fixable, r.Total)
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="chart-val">%s</text>`,
			labelW+pad+totalW+6, y+rowH/2+4, template.HTMLEscapeString(caption))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// stackSeg is one severity segment of a stacked bar (a single scan/point).
type stackSeg struct {
	Sev string
	N   int
}

// stackPoint is one column in the stacked time-series (one scan/version).
type stackPoint struct {
	Label string
	Segs  []stackSeg // ordered crit→low
}

// stackedTimeSeries renders severity composition over time as stacked columns —
// the "vulnerabilities over versions" view. Columns left→right = oldest→newest.
func stackedTimeSeries(points []stackPoint, width int) template.HTML {
	if len(points) == 0 {
		return template.HTML(`<p class="muted">No scan history yet — the chart fills in as daily scans run.</p>`)
	}
	const (
		chartH = 160
		axisH  = 22
		gap    = 8
		padX   = 4
	)
	maxTotal := 1
	for _, p := range points {
		tot := 0
		for _, s := range p.Segs {
			tot += s.N
		}
		if tot > maxTotal {
			maxTotal = tot
		}
	}
	n := len(points)
	colW := (width - padX*2 - gap*(n-1)) / n
	if colW < 6 {
		colW = 6
	}
	h := chartH + axisH
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %d %d" width="100%%" height="%d" role="img">`, width, h, h)
	for i, p := range points {
		x := padX + i*(colW+gap)
		yTop := chartH
		for _, s := range p.Segs {
			if s.N == 0 {
				continue
			}
			segH := s.N * chartH / maxTotal
			if segH < 1 {
				segH = 1
			}
			yTop -= segH
			fill := svgSev[s.Sev]
			if fill == "" {
				fill = "#8b949e"
			}
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="%s"><title>%s: %d %s</title></rect>`,
				x, yTop, colW, segH, fill, template.HTMLEscapeString(p.Label), s.N, template.HTMLEscapeString(s.Sev))
		}
		// x label (rotated-free: short, centered)
		fmt.Fprintf(&b, `<text x="%d" y="%d" class="chart-xlbl" text-anchor="middle">%s</text>`,
			x+colW/2, chartH+14, template.HTMLEscapeString(trunc(p.Label, 10)))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ── License visualization ───────────────────────────────────────────────────

// svgCategory maps a license category to a fill. Copyleft strength reads as a
// warm→cool gradient (proprietary/strong = alarm, permissive = calm), matching
// how the severity palette signals risk.
var svgCategory = map[string]string{
	"proprietary":     "#8250df", // purple — most restrictive/non-OSS
	"strong-copyleft": "#cf222e", // red
	"weak-copyleft":   "#bc4c00", // amber
	"permissive":      "#1a7f37", // green — lowest obligation
	"unknown":         "#8b949e", // grey
}

// categoryFill resolves a category color, defaulting to the unknown grey.
func categoryFill(cat string) string {
	if f := svgCategory[cat]; f != "" {
		return f
	}
	return svgCategory["unknown"]
}

// licensePalette is a stable, colorblind-considerate set for license *families*
// (MIT, GPL, …) where there's no inherent ordering. Assigned by index so a given
// legend position is consistent within one render.
var licensePalette = []string{
	"#0969da", "#cf222e", "#bf8700", "#1a7f37", "#8250df",
	"#1b7c83", "#bc4c00", "#a475f9", "#953800", "#57606a",
}

// familyColor picks a deterministic palette color for a family label by hashing
// its position-independent name, so "GPL" is the same hue across pages.
func familyColor(name string) string {
	if name == "others" || name == "unknown" {
		return "#8b949e"
	}
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619
	}
	return licensePalette[int(h)%len(licensePalette)]
}

// treeCell is one rectangle in a treemap: a label, its weight (area ∝ weight),
// and a fill color.
type treeCell struct {
	Label string
	Value int
	Color string
}

// treemapChart renders a squarified treemap as inline SVG — packages (or license
// families) sized by count. It approximates the squarified algorithm with a
// slice-and-dice that alternates split direction to keep cells from becoming
// slivers, which is enough for a legible at-a-glance "what dominates" view (the
// disco package treemap). Cells are drawn largest-first; tiny cells drop their
// label but keep a <title> tooltip.
func treemapChart(cells []treeCell, width, height int) template.HTML {
	total := 0
	for _, c := range cells {
		total += c.Value
	}
	if total == 0 || len(cells) == 0 {
		return template.HTML(`<p class="muted">No package license data yet.</p>`)
	}
	// Largest first for a stable, readable layout.
	sorted := append([]treeCell(nil), cells...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart treemap" viewBox="0 0 %d %d" width="100%%" height="%d" role="img">`,
		width, height, height)
	layoutTreemap(&b, sorted, total, 0, 0, float64(width), float64(height))
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// layoutTreemap slice-and-dices cells into the rect (x,y,w,h), splitting along
// the longer axis at each step so cells stay close to square.
func layoutTreemap(b *strings.Builder, cells []treeCell, total int, x, y, w, h float64) {
	if len(cells) == 0 || total == 0 {
		return
	}
	if len(cells) == 1 {
		drawTreeCell(b, cells[0], x, y, w, h)
		return
	}
	// Split cells into two groups of roughly equal weight.
	half := total / 2
	acc, split := 0, 0
	for i, c := range cells {
		if acc+c.Value > half && i > 0 {
			break
		}
		acc += c.Value
		split = i + 1
	}
	if split >= len(cells) {
		split = len(cells) - 1
	}
	left, right := cells[:split], cells[split:]
	leftW := 0
	for _, c := range left {
		leftW += c.Value
	}
	frac := float64(leftW) / float64(total)
	if w >= h { // split vertically
		lw := w * frac
		layoutTreemap(b, left, leftW, x, y, lw, h)
		layoutTreemap(b, right, total-leftW, x+lw, y, w-lw, h)
	} else { // split horizontally
		lh := h * frac
		layoutTreemap(b, left, leftW, x, y, w, lh)
		layoutTreemap(b, right, total-leftW, x, y+lh, w, h-lh)
	}
}

// drawTreeCell emits one treemap rectangle with a border, a tooltip, and (if it
// is large enough) a label.
func drawTreeCell(b *strings.Builder, c treeCell, x, y, w, h float64) {
	fill := c.Color
	if fill == "" {
		fill = "#4a9eff"
	}
	fmt.Fprintf(b, `<g><rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" stroke="var(--surface)" stroke-width="1.5">`+
		`<title>%s: %d</title></rect>`,
		x, y, w, h, fill, template.HTMLEscapeString(c.Label), c.Value)
	// Only label cells with room for readable text.
	if w > 48 && h > 20 {
		maxChars := int(w / 8)
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" class="tree-lbl" fill="#fff">%s</text>`,
			x+5, y+15, template.HTMLEscapeString(trunc(c.Label, maxChars)))
	}
	b.WriteString(`</g>`)
}
