package server

import (
	"fmt"
	"html/template"
	"math"
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
	Sev   string // severity key → color
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
		fill := svgSev[s.Sev]
		if fill == "" {
			fill = "#4a9eff"
		}
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
		fill := svgSev[s.Sev]
		if fill == "" {
			fill = "#4a9eff"
		}
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
