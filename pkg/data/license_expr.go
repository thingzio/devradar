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

// exprParser is a recursive-descent parser over a token stream. `malformed` is
// set whenever the input violates the SPDX expression grammar — a missing
// operand (e.g. "MIT OR", "GPL WITH"), an unbalanced parenthesis (e.g. "(GPL"),
// or unconsumed trailing tokens (e.g. "MIT garbage"). A malformed expression must
// NOT be turned into a partial policy verdict; the caller treats it as an unknown
// license (a data-quality signal) instead.
type exprParser struct {
	toks      []string
	pos       int
	malformed bool
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
			p.malformed = true // "… OR" with no right operand
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
			p.malformed = true // "… AND" with no right operand
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
		if exc == "" || isKeyword(exc, "or") || isKeyword(exc, "and") || exc == "(" || exc == ")" {
			p.malformed = true // "… WITH" with no (valid) exception operand
		} else if node.op == "leaf" {
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
		if inner == nil {
			p.malformed = true // "()" or "(" with no expression
		}
		if p.peek() == ")" {
			p.next()
		} else {
			p.malformed = true // unbalanced: missing ")"
		}
		return inner
	}
	if tok == ")" {
		p.malformed = true // stray ")"
		return nil
	}
	// A stray operator where a primary was expected is a grammar error.
	if isKeyword(tok, "or") || isKeyword(tok, "and") || isKeyword(tok, "with") {
		p.malformed = true
		return nil
	}
	p.next()
	return &exprNode{op: "leaf", license: tok}
}

// parseLicenseExpression parses expr into an AST, or nil if it has no license.
func parseLicenseExpression(expr string) *exprNode {
	root, _ := parseLicenseExpressionChecked(expr)
	return root
}

// parseLicenseExpressionChecked parses expr into an AST and reports whether it was
// well-formed. malformed is true for a missing operand, an unbalanced/stray
// parenthesis, or unconsumed trailing tokens (e.g. "MIT garbage"). A well-formed
// empty input (no tokens) yields (nil, false) — vacuous, not malformed.
func parseLicenseExpressionChecked(expr string) (root *exprNode, malformed bool) {
	p := &exprParser{toks: tokenizeExpr(expr)}
	root = p.parseOr()
	// Trailing tokens the grammar never consumed → malformed (e.g. "MIT garbage",
	// "MIT )"). An all-empty token stream that produced no root is simply vacuous.
	if p.pos < len(p.toks) {
		p.malformed = true
	}
	if root == nil && len(p.toks) > 0 {
		p.malformed = true // had tokens but produced no license (e.g. "AND", "()")
	}
	return root, p.malformed
}

// deniedLeaf decides whether a single license leaf is denied by the policy. It
// receives the raw license ID and the WITH exception operand ("" if none), so the
// policy can honor a pair-specific rule (e.g. deny GPL-2.0 in general but ALLOW
// "GPL-2.0 WITH Classpath-exception-2.0"). Returns denied + the display string to
// surface as the offending token.
type deniedLeaf func(license, excep string) (denied bool, display string)

// eval reports whether the subtree is allowed under the leaf predicate. AND
// requires all children allowed; OR requires any child allowed.
func (n *exprNode) eval(isDenied deniedLeaf, offending *[]string) bool {
	switch n.op {
	case "leaf":
		if denied, display := isDenied(n.license, n.excep); denied {
			*offending = append(*offending, display)
			return false
		}
		return true
	case "and":
		ok := true
		for _, c := range n.children {
			if !c.eval(isDenied, offending) {
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
			if c.eval(isDenied, &childOff) {
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
