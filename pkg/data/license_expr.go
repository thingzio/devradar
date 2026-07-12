package data

import "strings"

// SPDX license-expression parser + evaluator.
//
// Replaces the earlier token-scan heuristic (flatten IDs, "OR anywhere ⇒
// permissive"), which could wrongly clear a policy violation for a mixed
// expression like "(MIT OR GPL-3.0) AND Proprietary": the mandatory, AND-ed
// denied operand was masked by the presence of an OR. That is unsafe for a
// compliance verdict. This is a real recursive-descent parser over the SPDX
// expression grammar with correct precedence and parentheses:
//
//	OR   lowest precedence   allowed if ANY operand allowed
//	AND                      allowed if ALL operands allowed
//	WITH highest precedence   binds a license to an exception (a single leaf)
//	( )  grouping
//
// Evaluation is over a boolean AST, so "(MIT OR GPL-3.0) AND Proprietary"
// correctly denies when Proprietary is denied, regardless of the OR. A WITH
// exception is preserved on its leaf ("gpl-2.0 WITH classpath-exception-2.0"), so
// a policy can deny/allow the exact license+exception pair rather than silently
// dropping the exception.

// exprNode is a node in a parsed SPDX expression AST.
type exprNode struct {
	op       string      // "or", "and", "leaf"
	children []*exprNode // for or/and
	license  string      // for leaf: the license ID (original case)
	excep    string      // for leaf: the WITH exception operand, if any (original case)
}

// exprParser is a recursive-descent parser over a token stream.
type exprParser struct {
	toks []string
	pos  int
}

// tokenizeExpr splits an SPDX expression into tokens: parentheses become their
// own tokens; whitespace separates the rest. Operators are recognized
// case-insensitively during parsing, not here.
func tokenizeExpr(expr string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range expr {
		switch r {
		case '(', ')':
			flush()
			toks = append(toks, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) next() string {
	t := p.peek()
	if t != "" {
		p.pos++
	}
	return t
}

func isKeyword(tok, kw string) bool { return strings.EqualFold(tok, kw) }

// parseOr := parseAnd ( "OR" parseAnd )*
func (p *exprParser) parseOr() *exprNode {
	left := p.parseAnd()
	if left == nil {
		return nil
	}
	nodes := []*exprNode{left}
	for isKeyword(p.peek(), "or") {
		p.next()
		right := p.parseAnd()
		if right == nil {
			break
		}
		nodes = append(nodes, right)
	}
	if len(nodes) == 1 {
		return nodes[0]
	}
	return &exprNode{op: "or", children: nodes}
}

// parseAnd := parseWith ( "AND" parseWith )*
func (p *exprParser) parseAnd() *exprNode {
	left := p.parseWith()
	if left == nil {
		return nil
	}
	nodes := []*exprNode{left}
	for isKeyword(p.peek(), "and") {
		p.next()
		right := p.parseWith()
		if right == nil {
			break
		}
		nodes = append(nodes, right)
	}
	if len(nodes) == 1 {
		return nodes[0]
	}
	return &exprNode{op: "and", children: nodes}
}

// parseWith := parsePrimary ( "WITH" IDENT )?
func (p *exprParser) parseWith() *exprNode {
	node := p.parsePrimary()
	if node == nil {
		return nil
	}
	if isKeyword(p.peek(), "with") {
		p.next()
		exc := p.next() // the exception operand
		if node.op == "leaf" {
			node.excep = exc
		}
	}
	return node
}

// parsePrimary := "(" parseOr ")" | IDENT
func (p *exprParser) parsePrimary() *exprNode {
	tok := p.peek()
	if tok == "" {
		return nil
	}
	if tok == "(" {
		p.next()
		inner := p.parseOr()
		if p.peek() == ")" {
			p.next()
		}
		return inner
	}
	if tok == ")" {
		return nil
	}
	// A stray operator where a primary was expected → skip it defensively.
	if isKeyword(tok, "or") || isKeyword(tok, "and") || isKeyword(tok, "with") {
		return nil
	}
	p.next()
	return &exprNode{op: "leaf", license: tok}
}

// parseLicenseExpression parses expr into an AST, or nil if it has no license.
func parseLicenseExpression(expr string) *exprNode {
	p := &exprParser{toks: tokenizeExpr(expr)}
	return p.parseOr()
}

// eval reports whether the subtree is allowed given the denied-key set. A leaf is
// allowed unless its key is denied; the key prefers the full "license WITH
// exception" pair (so a policy can target the pair) and falls back to the bare
// license. AND requires all children; OR requires any child.
func (n *exprNode) eval(denied map[string]struct{}, offending *[]string) bool {
	switch n.op {
	case "leaf":
		if n.excep != "" {
			pair := normalizeLicenseID(n.license) + " with " + strings.ToLower(strings.TrimSpace(n.excep))
			if _, bad := denied[pair]; bad {
				*offending = append(*offending, n.license+" WITH "+n.excep)
				return false
			}
		}
		if _, bad := denied[normalizeLicenseID(n.license)]; bad {
			*offending = append(*offending, n.license)
			return false
		}
		return true
	case "and":
		ok := true
		for _, c := range n.children {
			if !c.eval(denied, offending) {
				ok = false // keep evaluating so every offending leaf is reported
			}
		}
		return ok
	case "or":
		// Allowed if any child is allowed. Collect offending from failing children
		// only for the all-denied case; if any child passes, the OR is satisfied and
		// the offending list contributed by the failing branch is irrelevant.
		var branchOffending []string
		anyAllowed := false
		for _, c := range n.children {
			var childOff []string
			if c.eval(denied, &childOff) {
				anyAllowed = true
			} else {
				branchOffending = append(branchOffending, childOff...)
			}
		}
		if anyAllowed {
			return true
		}
		*offending = append(*offending, branchOffending...)
		return false
	}
	return true
}
