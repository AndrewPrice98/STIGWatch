// A small syntax highlighter for the generated remediation files (YAML and PowerShell).
//
// It tokenises text into plain data: an array of lines, each an array of { type, text } tokens.
// The page renders every token as a React <span> with a text child, so file content that came
// from collector-supplied strings can never become markup. No HTML string is ever built, and no
// external library is used. The tokens are for reading, not parsing: a mistake only changes a
// colour, never the text, and concatenating the tokens always gives back the original line.

const rule = (type, re) => ({ type, re: new RegExp(re.source, 'y') })

const PS_KEYWORDS = [
  'begin', 'break', 'catch', 'continue', 'do', 'else', 'elseif', 'end', 'exit', 'finally', 'for',
  'foreach', 'function', 'if', 'in', 'param', 'process', 'return', 'switch', 'throw', 'trap', 'try',
  'until', 'while',
].join('|')

const PS_RULES = [
  rule('comment', /#.*/),
  rule('string', /'(?:[^']|'')*'/),
  rule('string', /"(?:[^"`]|`.)*"/),
  rule('variable', /\$(?:\{[^}]*\}|[A-Za-z_][\w:]*|[$?^_])/),
  rule('param', /-[A-Za-z][\w]*/),
  rule('cmdlet', /\b[A-Z][A-Za-z]*-[A-Z][A-Za-z0-9]*\b/),
  rule('keyword', new RegExp(`\\b(?:${PS_KEYWORDS})\\b`, 'i')),
  rule('number', /\b\d+(?:\.\d+)?\b/),
  rule('punct', /[{}()[\];,|=+*/<>!@]+/),
]

const YAML_VALUE_RULES = [
  rule('string', /"(?:[^"\\]|\\.)*"/),
  rule('string', /'(?:[^']|'')*'/),
  rule('template', /\{\{.*?\}\}/),
  rule('keyword', /\b(?:true|false|null|yes|no)\b/),
  rule('number', /\b\d+(?:\.\d+)?\b/),
  rule('punct', /[[\]{},|>&*!-]+(?=\s|$)/),
]

function push(tokens, type, text) {
  if (!text) return
  const last = tokens[tokens.length - 1]
  if (last && last.type === type) last.text += text
  else tokens.push({ type, text })
}

function scan(line, rules, tokens, start = 0) {
  let i = start
  while (i < line.length) {
    let hit = null
    for (const r of rules) {
      r.re.lastIndex = i
      const m = r.re.exec(line)
      if (m && m[0]) { hit = { type: r.type, text: m[0] }; break }
    }
    if (hit) { push(tokens, hit.type, hit.text); i += hit.text.length } else { push(tokens, 'plain', line[i]); i += 1 }
  }
}

function powershell(lines) {
  let mode = null // 'block' inside <# #>, "'" or '"' inside a here-string
  return lines.map((line) => {
    const tokens = []
    if (mode === 'block') {
      const end = line.indexOf('#>')
      if (end === -1) { push(tokens, 'comment', line); return tokens }
      push(tokens, 'comment', line.slice(0, end + 2))
      mode = null
      scan(line, PS_RULES, tokens, end + 2)
      return tokens
    }
    if (mode === "'" || mode === '"') {
      if (line.startsWith(`${mode}@`)) { push(tokens, 'string', line.slice(0, 2)); mode = null; scan(line, PS_RULES, tokens, 2) } else push(tokens, 'string', line)
      return tokens
    }
    const open = line.indexOf('<#')
    const hash = line.indexOf('#')
    if (open !== -1 && hash === open + 1) {
      scan(line.slice(0, open), PS_RULES, tokens)
      const end = line.indexOf('#>', open + 2)
      if (end === -1) { push(tokens, 'comment', line.slice(open)); mode = 'block' } else {
        push(tokens, 'comment', line.slice(open, end + 2))
        scan(line, PS_RULES, tokens, end + 2)
      }
      return tokens
    }
    const here = /@(['"])\s*$/.exec(line)
    if (here) { scan(line.slice(0, here.index), PS_RULES, tokens); push(tokens, 'string', here[0]); mode = here[1]; return tokens }
    scan(line, PS_RULES, tokens)
    return tokens
  })
}

function yaml(lines) {
  let blockIndent = -1 // indentation of the line that opened a | or > block scalar
  return lines.map((line) => {
    const tokens = []
    const indent = line.match(/^\s*/)[0].length
    if (blockIndent >= 0) {
      if (!line.trim() || indent > blockIndent) { push(tokens, 'string', line); return tokens }
      blockIndent = -1
    }
    if (/^\s*#/.test(line) || /^---\s*$/.test(line)) { push(tokens, /^---/.test(line) ? 'punct' : 'comment', line); return tokens }
    const key = /^(\s*(?:-\s+)*)((?:"[^"]*"|'[^']*'|[^\s:#'"{}[\],&*!|>][^:#]*?))(\s*:)(?=\s|$)/.exec(line)
    let at = 0
    if (key) {
      push(tokens, 'punct', key[1])
      push(tokens, 'key', key[2])
      push(tokens, 'punct', key[3])
      at = key[0].length
    }
    // A trailing comment starts at a "#" preceded by whitespace, outside quotes (good enough for display).
    let body = line.slice(at)
    let comment = ''
    const c = /(^|\s)#(?!\{)/.exec(body)
    if (c && !/["'][^"']*$/.test(body.slice(0, c.index))) { comment = body.slice(c.index + c[1].length); body = body.slice(0, c.index + c[1].length) }
    const value = []
    scan(body, YAML_VALUE_RULES, value)
    // Jinja templates inside a quoted string get their own colour.
    for (const t of value) {
      if (t.type !== 'string') { push(tokens, t.type, t.text); continue }
      t.text.split(/(\{\{.*?\}\})/).forEach((part, i) => push(tokens, i % 2 ? 'template' : 'string', part))
    }
    if (comment) push(tokens, 'comment', comment)
    if (/(?:^|\s)[|>][+-]?\d*\s*$/.test(line.replace(/\s+#.*$/, ''))) blockIndent = indent
    return tokens
  })
}

/** Tokenise `text` for `lang` ('yaml' | 'powershell'); other languages come back unhighlighted. */
export function highlight(text, lang) {
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n')
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  if (lang === 'powershell') return powershell(lines)
  if (lang === 'yaml') return yaml(lines)
  return lines.map((l) => (l ? [{ type: 'plain', text: l }] : []))
}
