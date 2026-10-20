#!/usr/bin/env python3
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# This file is part of foxtrot.
#
# foxtrot is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# foxtrot is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

# Make the section 3 man pages from the public headers: one page, foxtrot_NAME(3),
# for each include/foxtrot/NAME.h, from the comment that opens it (the
# description), the comments before the declarations, and the declarations
# themselves.  The headers are the reference; this keeps the pages from
# saying anything else.  Also writes man.am, the list of pages for automake.
#
# Usage: python3 gen-man.py    (from doc/; writes man/foxtrot_*.3 and man.am)
#
# The pages are checked in, so that building the library needs no python.

import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
INC = os.path.join(HERE, '..', 'include', 'foxtrot')
OUT = os.path.join(HERE, 'man')
VERSION = None
DATE = '2026'

for line in open(os.path.join(HERE, '..', 'configure.ac')):
    m = re.search(r'AC_INIT\(\[foxtrot\], \[([^\]]+)\]', line)
    if m:
        VERSION = m.group(1)
if VERSION is None:
    sys.exit('no version in configure.ac')


def roff(text):
    """Escape TEXT for roff: backslashes, hyphens, and leading dots."""
    text = text.replace('\\', '\\e').replace('-', '\\-')
    return text


def line_safe(l):
    return '\\&' + l if l[:1] in ('.', "'") else l


# ---- Scanning a header into items ----

class Item:
    def __init__(self, kind, text, comment=None, name=None):
        self.kind = kind          # 'func', 'type', 'macro', 'heading', 'prose'
        self.text = text          # the declaration, or the prose
        self.comment = comment    # the comment before a declaration
        self.name = name
        self.adjacent = False     # Right after the one before, no blank line.


def comment_text(raw):
    """The words of a /* */ comment, with the comment marks and the indent
    of its continuation lines taken off."""
    body = raw[2:-2]
    lines = body.split('\n')
    out = [lines[0].strip()]
    rest = lines[1:]
    # The continuation lines are indented by the same amount (3, as the
    # first line's text is after "/* ").
    indent = None
    for l in rest:
        if l.strip():
            n = len(l) - len(l.lstrip(' '))
            indent = n if indent is None else min(indent, n)
    for l in rest:
        out.append(l[indent:] if indent and l.strip() else l.strip() if not l.strip() else l)
    # Trailing blank lines.
    while out and not out[-1].strip():
        out.pop()
    return '\n'.join(out)


def scan(path):
    src = open(path).read()
    items = []
    pending = None
    last_end = None
    first = True
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in ' \t\n':
            i += 1
            continue
        if src.startswith('/*', i):
            j = src.index('*/', i) + 2
            raw = src[i:j]
            i = j
            if first:               # The licence.
                first = False
                continue
            text = comment_text(raw)
            head = text.split('\n')[0]
            if re.match(r'^(----|====)', head):
                title = re.sub(r'[-=\s]+$', '', re.sub(r'^[-=\s]+', '', head))
                items.append(Item('heading', title))
                body = '\n'.join(text.split('\n')[1:]).strip('\n')
                if body.strip():
                    items.append(Item('prose', body))
                pending = None
            else:
                if pending is not None:
                    items.append(Item('prose', pending))
                pending = text
            continue
        if c == '#':
            # A preprocessor line, with its continuations.
            j = i
            while True:
                e = src.find('\n', j)
                if e < 0:
                    e = n
                if src[j:e].endswith('\\'):
                    j = e + 1
                    continue
                break
            line = src[i:e]
            i = e
            m = re.match(r'#\s*define\s+(\w+)', line)
            if m and not m.group(1).startswith('FOXTROT_') and not m.group(1).endswith('_H'):
                items.append(Item('macro', ' '.join(line.replace('\\\n', ' ').split()),
                                  pending, m.group(1)))
                pending = None
            elif re.match(r'#\s*ifdef\s+__cplusplus', line):
                # Skip to the matching #endif.
                depth = 1
                while depth and i < n:
                    e = src.find('\n', i + 1)
                    e = n if e < 0 else e
                    seg = src[i:e]
                    if re.match(r'\s*#\s*if', seg):
                        depth += 1
                    elif re.match(r'\s*#\s*endif', seg):
                        depth -= 1
                    i = e
            continue
        # A declaration, to the ; at depth 0.
        j = i
        depth = 0
        while j < n:
            ch = src[j]
            if src.startswith('/*', j):
                j = src.index('*/', j) + 2
                continue
            if ch == '"':
                j = src.index('"', j + 1) + 1
                continue
            if ch in '({[':
                depth += 1
            elif ch in ')}]':
                depth -= 1
            elif ch == ';' and depth == 0:
                break
            j += 1
        decl = src[i:j + 1]
        start = i
        i = j + 1
        text = decl.strip()
        if re.match(r'(typedef\s+)?(struct|enum|union)\b[^;(]*\{', text) or \
           re.match(r'typedef\b', text):
            m = re.search(r'(\w+)\s*;$', text)
            tag = re.match(r'(?:typedef\s+)?(?:struct|enum|union)\s+(\w+)', text)
            name = m.group(1) if m else (tag.group(1) if tag else None)
            items.append(Item('type', text, pending, name))
        elif '(' in text:
            m = re.search(r'(\w+)\s*\(', text)
            items.append(Item('func', text, pending, m.group(1)))
        else:
            items.append(Item('type', text, pending, None))
        # Declared with no blank line and no comment since the last one?
        if pending is None and last_end is not None and len(items) > 1 \
           and items[-2].kind == items[-1].kind \
           and '\n\n' not in src[last_end:start] and '/*' not in src[last_end:start]:
            items[-1].adjacent = True
        last_end = i
        pending = None
    if pending is not None:
        items.append(Item('prose', pending))
    return items


# ---- Rendering comment text ----

def flow(text, out):
    """TEXT, which is prose with lists and tables in it, as roff."""
    paras = re.split(r'\n\s*\n', text.strip('\n'))
    for p in paras:
        lines = p.split('\n')
        base = min((len(l) - len(l.lstrip(' ')) for l in lines if l.strip()), default=0)
        stripped = [l[base:] for l in lines]
        first = stripped[0]
        if re.match(r'^\s*(-|o|\*)\s+\S', first) and len(first) - len(first.lstrip()) < 6:
            # A list.
            items, cur = [], []
            for l in stripped:
                if re.match(r'^\s*(-|o|\*)\s+', l):
                    if cur:
                        items.append(cur)
                    cur = [re.sub(r'^\s*(-|o|\*)\s+', '', l)]
                else:
                    cur.append(l.strip())
            if cur:
                items.append(cur)
            for it in items:
                out.append('.IP \\(bu 3')
                out.append(line_safe(roff(' '.join(it))))
            continue
        if any(l.startswith('  ') for l in stripped[1:] if l.strip()) or \
           (len(stripped) > 1 and first.startswith('  ')) or first.startswith('    '):
            # Indented lines or aligned columns: as they are.
            out.append('.PP')
            out.append('.nf')
            out.append('.RS')
            for l in stripped:
                out.append(line_safe(roff(l)))
            out.append('.RE')
            out.append('.fi')
            continue
        out.append('.PP')
        out.append(line_safe(roff(' '.join(l.strip() for l in stripped))))


def short_name(text):
    """A short phrase for the NAME line: the opening of the description."""
    para = re.split(r'\n\s*\n', text.strip())[0]
    para = ' '.join(l.strip() for l in para.split('\n'))
    m = re.search(r'(.{12,}?)(\s\(|, |: | for | in the | that | which |\.\s|\.$|;)', para)
    s = m.group(1) if m else para
    s = s.rstrip('.:;, ')
    if len(s) > 70:
        s = s[:70].rsplit(' ', 1)[0]
    return s


def decl_lines(text):
    """A declaration on one line."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return ' '.join(text.split())


def proto_wrapped(f, width=78):
    """A prototype for the SYNOPSIS, broken after commas to fit."""
    d = decl_lines(f.text)
    if len(d) <= width:
        lines = [d]
    else:
        # Break after a comma in the parameters, continuing under them.
        head, _, rest = d.partition('(')
        parts = [x.strip() for x in rest.rsplit(')', 1)[0].split(',')]
        tail = ')' + rest.rsplit(')', 1)[1]
        lines, cur = [], head + '('
        indent = ' ' * 8
        for k, part in enumerate(parts):
            piece = part + (',' if k + 1 < len(parts) else '')
            if len(cur) + len(piece) + 1 > width and cur.strip() and not cur.endswith('('):
                lines.append(cur.rstrip())
                cur = indent
            cur += (' ' if not cur.endswith(('(', ' ')) else '') + piece
        lines.append(cur + tail)
    out = []
    for l in lines:
        l = line_safe(roff(l))
        out.append(l)
    out[0] = out[0].replace(roff(f.name), '\\fB' + roff(f.name) + '\\fP', 1)
    return out


def proto(f):
    d = line_safe(roff(decl_lines(f.text)))
    return d.replace(roff(f.name), '\\fB' + roff(f.name) + '\\fP', 1)


def flow_under_tag(text, out):
    """A comment as the body of a .TP entry."""
    sub = []
    flow(text, sub)
    if sub and sub[0] == '.PP':
        sub = sub[1:]
    out.extend(sub)


def render(name, items):
    out = []
    page = 'foxtrot_' + name
    body = list(items)
    desc = None
    if body and body[0].kind == 'prose':
        desc = body[0].text
        body = body[1:]
    elif body and body[0].comment:
        desc = body[0].comment
        body[0].comment = None
    funcs = [b for b in body if b.kind == 'func']
    types = [b for b in body if (b.kind == 'type' and b.name) or b.kind == 'macro']
    names = [page] + [f.name for f in funcs]
    out.append('.\\" Generated by gen-man.py from include/foxtrot/%s.h; do not edit.' % name)
    out.append('.TH %s 3 "%s" "foxtrot %s" "Foxtrot Library Reference"' %
               (page.upper(), DATE, VERSION))
    out.append('.SH NAME')
    # man-db builds its index from this line; every function is listed so
    # that "man gf_key_generate" finds the page.
    out.append(roff(', '.join(names)) + ' \\- ' + roff(short_name(desc) if desc else 'foxtrot ' + name))
    out.append('.SH SYNOPSIS')
    out.append('.nf')
    out.append('.B #include <foxtrot/%s.h>' % name)
    if funcs:
        out.append('.sp')
        for f in funcs:
            out.extend(proto_wrapped(f))
    out.append('.fi')
    out.append('.SH DESCRIPTION')
    if desc:
        flow(desc, out)
    else:
        out.append('.PP')
        out.append('See the header.')
    if types:
        out.append('.SH "TYPES AND CONSTANTS"')
        for it in types:
            out.append('.PP')
            out.append('.nf')
            for l in it.text.split('\n'):
                out.append(line_safe(roff(l.rstrip())))
            out.append('.fi')
            if it.comment:
                out.append('.RS')
                flow_under_tag(it.comment, out)
                out.append('.RE')
    if funcs:
        out.append('.SH FUNCTIONS')
        i = 0
        while i < len(body):
            it = body[i]
            i += 1
            if it.kind == 'heading':
                out.append('.SS "%s"' % roff(it.text))
            elif it.kind == 'prose':
                flow(it.text, out)
            elif it.kind == 'func':
                # Declarations that sit together share their description.
                group = [it]
                while i < len(body) and body[i].kind == 'func' and body[i].adjacent \
                      and not body[i].comment:
                    group.append(body[i])
                    i += 1
                out.append('.TP')
                out.append('\n.br\n'.join(proto(g) for g in group))
                comment = next((g.comment for g in group if g.comment), None)
                if comment:
                    flow_under_tag(comment, out)
    out.append('.SH "SEE ALSO"')
    out.append('foxtrot(7)')
    out.append('.PP')
    out.append('The full manual: \\fBinfo foxtrot\\fP.')
    out.append('.SH COPYRIGHT')
    out.append('Copyright \\(co 2026 Chris Burdess.  License GPLv3+: GNU GPL version 3 or later')
    out.append('<https://www.gnu.org/licenses/gpl.html>.')
    out.append('This is free software: you are free to change and redistribute it.')
    out.append('There is NO WARRANTY, to the extent permitted by law.')
    return '\n'.join(out) + '\n', names


def main():
    check = '--check' in sys.argv[1:]
    headers = sorted(f[:-2] for f in os.listdir(INC) if f.endswith('.h'))
    written, stale = [], []
    os.makedirs(OUT, exist_ok=True)
    for h in headers:
        items = scan(os.path.join(INC, h + '.h'))
        text, names = render(h, items)
        path = os.path.join(OUT, 'foxtrot_%s.3' % h)
        if check:
            if not os.path.exists(path) or open(path).read() != text:
                stale.append(path)
        else:
            open(path, 'w').write(text)
        written.append('man/foxtrot_%s.3' % h)
    am = '## Generated by gen-man.py; do not edit.\nman3_MANS = \\\n  %s\nman7_MANS = foxtrot.7\n' % \
        ' \\\n  '.join(written)
    am_path = os.path.join(HERE, 'man.am')
    if check:
        if not os.path.exists(am_path) or open(am_path).read() != am:
            stale.append(am_path)
        if stale:
            print('out of date (run python3 doc/gen-man.py): ' + ' '.join(
                os.path.basename(x) for x in stale))
            sys.exit(1)
        print('man pages are up to date')
        return
    open(am_path, 'w').write(am)
    print('%d pages' % len(written))


main()
