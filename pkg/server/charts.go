package server

import (
	"fmt"
	"html/template"
	"strings"
)

// Server-rendered inline-SVG charts — no client JS/chart library, matching the
// "boring, self-contained" stance. Each helper returns safe template.HTML.

// severity fill colors (match the CSS --sev-* scale closely enough for SVG).
var svgSev = map[string]string{
	"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700",
	"low": "#0969da", "negligible": "#57606a", "unknown": "#8b949e",
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
