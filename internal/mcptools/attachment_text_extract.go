package mcptools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ledongthuc/pdf"
	"golang.org/x/sys/unix"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// Attachment text extraction for mail_attachment_text. Pure Go, no
// cgo, no external binaries: DOCX and XLSX are parsed straight from
// their zip/XML parts; PDF goes through github.com/ledongthuc/pdf (a
// BSD-3-Clause fork of rsc.io/pdf with no dependencies). Every
// extractor is defensive — the input is attacker-supplied — and stops
// early once it has more text than the caller can use.

// Extraction limits. Attachments are already capped at
// max_attachment_bytes before they're decrypted; these bound the
// expansion (zip bombs, pathological PDFs). The parsers additionally
// run in a resource-limited child process (extractTextIsolated below),
// so a parser bug that loops or balloons kills only the child.
const (
	extractMaxZipEntryBytes = 64 << 20 // per decompressed XML part
	extractMaxZipEntries    = 10000
	extractPDFTimeBudget    = 20 * time.Second
	extractMaxSheets        = 200

	// PDF page tree walk (pdfPageList): a self-referential /Kids
	// (2 0 obj << /Type /Pages /Kids [2 0 R] >>) made the library's
	// Page(i) descend forever.
	extractPDFMaxTreeDepth = 64
	extractPDFMaxTreeNodes = 100000

	// XLSX amplification: one shared string can be referenced from
	// every cell, so output is budgeted per cell append, not per row.
	extractMaxSharedStrings     = 1 << 20
	extractMaxSharedStringBytes = 32 << 10
	extractMaxCellsPerRow       = 1000
)

// extractOutputBudget is the byte budget an extractor may produce for
// a rune limit: limit*4 bytes always holds at least limit runes, so a
// cut at the budget still fills the caller's window.
func extractOutputBudget(limit int) int {
	if limit <= 0 {
		limit = maxReadMaxChars
	}
	return limit*4 + 1024
}

// errUnsupportedFormat is returned for types we can't extract text from.
var errUnsupportedFormat = errors.New("unsupported attachment type for text extraction")

// detectFormat classifies an attachment by magic bytes, then MIME
// type, then filename extension. Returns "" when unsupported.
func detectFormat(mimeType, filename string, content []byte) string {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(mimeType, ";", 2)[0]))
	ext := strings.ToLower(path.Ext(filename))

	if bytes.HasPrefix(content, []byte("%PDF-")) {
		return "pdf"
	}
	if bytes.HasPrefix(content, []byte("PK\x03\x04")) {
		switch {
		case ext == ".docx" || strings.Contains(mt, "wordprocessingml"):
			return "docx"
		case ext == ".xlsx" || strings.Contains(mt, "spreadsheetml"):
			return "xlsx"
		}
		// Sniff the zip for the part that identifies it.
		if zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content))); err == nil {
			for _, f := range zr.File {
				switch f.Name {
				case "word/document.xml":
					return "docx"
				case "xl/workbook.xml":
					return "xlsx"
				}
			}
		}
		return ""
	}
	switch {
	case mt == "application/pdf" || ext == ".pdf":
		return "pdf"
	case mt == "text/html" || mt == "application/xhtml+xml" || ext == ".html" || ext == ".htm":
		return "html"
	case mt == "text/csv" || ext == ".csv":
		return "csv"
	case strings.HasPrefix(mt, "text/"),
		mt == "application/json", mt == "application/xml",
		ext == ".txt", ext == ".md", ext == ".json", ext == ".xml", ext == ".log", ext == ".tsv":
		return "text"
	}
	return ""
}

// extractText dispatches on format, in this process. limit is a rune
// budget: extractors may stop once they have produced more than limit
// runes (the caller truncates precisely and reports truncated). Tool
// handlers use extractTextIsolated, which runs the document parsers
// out of process.
func extractText(format string, content []byte, limit int) (string, error) {
	switch format {
	case "pdf":
		return extractPDF(content, limit)
	case "docx":
		return extractDOCXLimit(content, limit)
	case "xlsx":
		return extractXLSX(content, limit)
	case "html":
		return sanitize.Text(string(content)), nil
	case "csv", "text":
		return cleanPlainText(content), nil
	}
	return "", errUnsupportedFormat
}

// cleanPlainText makes arbitrary text bytes safe to hand to the
// model: invalid UTF-8 replaced, BOM dropped, control characters other
// than \n and \t removed (terminal escapes, zero-width tricks).
func cleanPlainText(b []byte) string {
	s := strings.ToValidUTF8(string(b), "\uFFFD")
	s = strings.TrimPrefix(s, "\uFEFF")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r == '\r':
			return '\n'
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			return -1
		case r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			// Zero-width and bidi controls.
			return -1
		}
		return r
	}, s)
}

// extractPDF pulls plain text page by page, stopping once limit runes
// are collected or the time budget runs out. The parser is fed
// untrusted bytes, so any panic is recovered into an error.
func extractPDF(content []byte, limit int) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = "", fmt.Errorf("pdf parse failed: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return "", fmt.Errorf("pdf open: %w", err)
	}
	deadline := time.Now().Add(extractPDFTimeBudget)
	pages, err := pdfPageList(r)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := len(pages)
	for i := 1; i <= n; i++ {
		if time.Now().After(deadline) {
			b.WriteString(fmt.Sprintf("\n[extraction stopped after %d of %d pages: time budget]\n", i-1, n))
			break
		}
		text, perr := pages[i-1].GetPlainText(nil)
		if perr != nil {
			b.WriteString(fmt.Sprintf("\n[page %d: text could not be extracted]\n", i))
			continue
		}
		if n > 1 {
			b.WriteString(fmt.Sprintf("\n--- page %d ---\n", i))
		}
		b.WriteString(text)
		if limit > 0 && utf8.RuneCountInString(b.String()) > limit {
			break
		}
	}
	s := cleanPlainText([]byte(b.String()))
	if strings.TrimSpace(s) == "" {
		return "", errors.New("pdf contains no extractable text (likely a scanned image; OCR is not supported)")
	}
	return strings.TrimSpace(s), nil
}

// pdfPageList walks the page tree once, depth-first in document order,
// and returns the leaf pages. Unlike the library's Page(i) (which
// re-descends from the root for every page, trusting /Count) it is
// bounded: a /Kids cycle or an absurdly deep or wide tree is an error
// rather than an endless loop.
func pdfPageList(r *pdf.Reader) ([]pdf.Page, error) {
	var (
		pages []pdf.Page
		nodes int
	)
	var walk func(v pdf.Value, depth int) error
	walk = func(v pdf.Value, depth int) error {
		nodes++
		if nodes > extractPDFMaxTreeNodes {
			return fmt.Errorf("pdf page tree has more than %d nodes; refusing", extractPDFMaxTreeNodes)
		}
		switch v.Key("Type").Name() {
		case "Page":
			pages = append(pages, pdf.Page{V: v})
		case "Pages":
			if depth >= extractPDFMaxTreeDepth {
				return errors.New("pdf page tree is cyclic or nested too deeply; refusing")
			}
			kids := v.Key("Kids")
			for i := 0; i < kids.Len(); i++ {
				if err := walk(kids.Index(i), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(r.Trailer().Key("Root").Key("Pages"), 0); err != nil {
		return nil, err
	}
	return pages, nil
}

// openZip opens content as a zip archive with an entry-count bound.
func openZip(content []byte) (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	if len(zr.File) > extractMaxZipEntries {
		return nil, fmt.Errorf("zip has %d entries; refusing (limit %d)", len(zr.File), extractMaxZipEntries)
	}
	return zr, nil
}

// readZipPart returns the decompressed bytes of one part, bounded by
// extractMaxZipEntryBytes (zip-bomb defense: the bound applies to the
// actual decompressed stream, not the header's claimed size).
func readZipPart(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, extractMaxZipEntryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if len(b) > extractMaxZipEntryBytes {
			return nil, fmt.Errorf("%s decompresses past %d bytes; refusing", name, extractMaxZipEntryBytes)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s not found", name)
}

// newXMLDecoder returns a decoder that tolerates the charsets Office
// declares (always UTF-8 in practice) without fetching anything.
func newXMLDecoder(b []byte) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	return d
}

// extractDOCX walks word/document.xml: text runs (w:t), tabs, breaks,
// and paragraph ends. Tables come out cell-per-tab, row-per-line.
func extractDOCX(content []byte) (string, error) {
	return extractDOCXLimit(content, 0)
}

// extractDOCXLimit is extractDOCX that stops once the output passes
// extractOutputBudget(limit).
func extractDOCXLimit(content []byte, limit int) (string, error) {
	zr, err := openZip(content)
	if err != nil {
		return "", err
	}
	doc, err := readZipPart(zr, "word/document.xml")
	if err != nil {
		return "", err
	}
	budget := extractOutputBudget(limit)
	var b strings.Builder
	d := newXMLDecoder(doc)
	inText := false
	for b.Len() <= budget {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("parse document.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "t":
				inText = true
			case "tab":
				b.WriteByte('\t')
			case "br", "cr":
				b.WriteByte('\n')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inText = false
			case "p":
				b.WriteByte('\n')
			case "tc":
				b.WriteByte('\t')
			}
		case xml.CharData:
			if inText {
				b.Write(t)
			}
		}
	}
	return strings.TrimSpace(cleanPlainText([]byte(b.String()))), nil
}

// extractXLSX renders every sheet as tab-separated rows under a
// "## Sheet: <name>" heading, resolving shared strings and inline
// strings. Formulas are not evaluated; the cached value (<v>) is used.
func extractXLSX(content []byte, limit int) (string, error) {
	zr, err := openZip(content)
	if err != nil {
		return "", err
	}
	shared, err := xlsxSharedStrings(zr)
	if err != nil {
		return "", err
	}
	sheets, err := xlsxSheets(zr)
	if err != nil {
		return "", err
	}
	budget := extractOutputBudget(limit)
	var b strings.Builder
	for i, sh := range sheets {
		if i >= extractMaxSheets {
			b.WriteString(fmt.Sprintf("\n[%d more sheets omitted]\n", len(sheets)-i))
			break
		}
		data, err := readZipPart(zr, sh.part)
		if err != nil {
			b.WriteString(fmt.Sprintf("## Sheet: %s\n[unreadable: %v]\n\n", sh.name, err))
			continue
		}
		b.WriteString("## Sheet: " + clipRunes(sh.name, 200) + "\n")
		if err := xlsxWriteSheet(&b, data, shared, budget); err != nil {
			b.WriteString(fmt.Sprintf("[parse error: %v]\n", err))
		}
		b.WriteString("\n")
		if b.Len() >= budget {
			break
		}
	}
	return strings.TrimSpace(cleanPlainText([]byte(b.String()))), nil
}

// xlsxSharedStrings reads xl/sharedStrings.xml (absent in workbooks
// with no string cells). Each <si> may hold one <t> or several rich-
// text runs (<r><t>); they are concatenated. Phonetic runs (<rPh>) are
// skipped.
func xlsxSharedStrings(zr *zip.Reader) ([]string, error) {
	data, err := readZipPart(zr, "xl/sharedStrings.xml")
	if err != nil {
		return nil, nil // no shared strings
	}
	var out []string
	var cur strings.Builder
	d := newXMLDecoder(data)
	inSI, inT, inRPh := false, false, false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse sharedStrings.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "si":
				inSI = true
				cur.Reset()
			case "t":
				inT = true
			case "rPh":
				inRPh = true
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "si":
				inSI = false
				if len(out) >= extractMaxSharedStrings {
					// Later indexes stay unresolved (rendered as the
					// raw index) rather than growing without bound.
					return out, nil
				}
				out = append(out, cur.String())
			case "t":
				inT = false
			case "rPh":
				inRPh = false
			}
		case xml.CharData:
			if inSI && inT && !inRPh {
				// Cap each string: one 8 MiB string referenced from
				// every cell was a 1.5 GiB allocation.
				if room := extractMaxSharedStringBytes - cur.Len(); room > 0 {
					if len(t) > room {
						t = t[:room]
					}
					cur.Write(t)
				}
			}
		}
	}
	return out, nil
}

type xlsxSheet struct {
	name string
	part string // zip path, e.g. xl/worksheets/sheet1.xml
}

// xlsxSheets returns sheets in workbook order, resolving each sheet's
// r:id through xl/_rels/workbook.xml.rels. Falls back to the
// worksheets present in the zip when the workbook can't be resolved.
func xlsxSheets(zr *zip.Reader) ([]xlsxSheet, error) {
	rels := map[string]string{}
	if data, err := readZipPart(zr, "xl/_rels/workbook.xml.rels"); err == nil {
		var doc struct {
			Rels []struct {
				ID     string `xml:"Id,attr"`
				Target string `xml:"Target,attr"`
			} `xml:"Relationship"`
		}
		if err := newXMLDecoder(data).Decode(&doc); err == nil {
			for _, r := range doc.Rels {
				target := r.Target
				if strings.HasPrefix(target, "/") {
					target = strings.TrimPrefix(target, "/")
				} else {
					target = path.Join("xl", target)
				}
				rels[r.ID] = path.Clean(target)
			}
		}
	}
	var sheets []xlsxSheet
	if data, err := readZipPart(zr, "xl/workbook.xml"); err == nil {
		var wb struct {
			Sheets []struct {
				Name  string     `xml:"name,attr"`
				Attrs []xml.Attr `xml:",any,attr"`
			} `xml:"sheets>sheet"`
		}
		if err := newXMLDecoder(data).Decode(&wb); err == nil {
			for _, s := range wb.Sheets {
				var rid string
				for _, a := range s.Attrs {
					if a.Name.Local == "id" {
						rid = a.Value
					}
				}
				if part, ok := rels[rid]; ok {
					sheets = append(sheets, xlsxSheet{name: s.Name, part: part})
				}
			}
		}
	}
	if len(sheets) > 0 {
		return sheets, nil
	}
	// Fallback: every xl/worksheets/sheetN.xml in numeric order.
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/") && strings.HasSuffix(f.Name, ".xml") &&
			!strings.Contains(strings.TrimPrefix(f.Name, "xl/worksheets/"), "/") {
			name := strings.TrimSuffix(path.Base(f.Name), ".xml")
			sheets = append(sheets, xlsxSheet{name: name, part: f.Name})
		}
	}
	if len(sheets) == 0 {
		return nil, errors.New("xlsx has no worksheets")
	}
	sort.Slice(sheets, func(i, j int) bool {
		return sheetNum(sheets[i].name) < sheetNum(sheets[j].name)
	})
	return sheets, nil
}

func sheetNum(name string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(name, "sheet"))
	if err != nil {
		return 1 << 30
	}
	return n
}

// xlsxWriteSheet streams one worksheet's cells as TSV rows. Column
// gaps are preserved using the cell reference (A1, C1 → "a\t\tc").
// budget is the size b may reach: it is charged per cell as the cell is
// added (a row of 60 references to one large shared string must not be
// joined first and measured after), rows are capped at
// extractMaxCellsPerRow cells whether or not cells carry r=, and the
// sheet stops once the budget is spent.
func xlsxWriteSheet(b *strings.Builder, data []byte, shared []string, budget int) error {
	d := newXMLDecoder(data)
	var (
		row      []string
		rowBytes int
		cellType string
		cellCol  int
		inV      bool
		inIsT    bool
		val      strings.Builder
		inCell   bool
		full     bool
	)
	flushRow := func() {
		defer func() { rowBytes = 0 }()
		// Trim trailing empties.
		end := len(row)
		for end > 0 && row[end-1] == "" {
			end--
		}
		if end > 0 {
			b.WriteString(strings.Join(row[:end], "\t"))
			b.WriteByte('\n')
		}
		row = row[:0]
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "row":
				row = row[:0]
			case "c":
				inCell = true
				cellType = ""
				cellCol = len(row)
				val.Reset()
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "t":
						cellType = a.Value
					case "r":
						if c, ok := colIndex(a.Value); ok {
							cellCol = c
						}
					}
				}
			case "v":
				inV = true
			case "t":
				if inCell {
					inIsT = true
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "v":
				inV = false
			case "t":
				inIsT = false
			case "c":
				inCell = false
				text := val.String()
				switch cellType {
				case "s":
					if idx, err := strconv.Atoi(strings.TrimSpace(text)); err == nil && idx >= 0 && idx < len(shared) {
						text = shared[idx]
					}
				case "b":
					if text == "1" {
						text = "TRUE"
					} else if text == "0" {
						text = "FALSE"
					}
				}
				// Cap absurd column indexes (a crafted r="XFD1048576"
				// would otherwise allocate a 16k-wide row per cell),
				// and the row width itself (cells without r= append).
				if cellCol >= extractMaxCellsPerRow {
					cellCol = len(row)
				}
				if cellCol >= extractMaxCellsPerRow {
					continue // row full: drop the cell
				}
				// Charge the budget before keeping the cell; the gap
				// tabs count too.
				cost := len(text) + 1
				if cellCol > len(row) {
					cost += cellCol - len(row)
				}
				if room := budget - b.Len() - rowBytes; cost > room {
					full = true
					if room <= 1 {
						continue
					}
					text = text[:room-1]
					cost = room
				}
				rowBytes += cost
				for len(row) < cellCol {
					row = append(row, "")
				}
				text = cellReplacer.Replace(text)
				if cellCol < len(row) {
					row[cellCol] = text
				} else {
					row = append(row, text)
				}
			case "row":
				flushRow()
				if full || b.Len() >= budget {
					return nil
				}
			}
		case xml.CharData:
			if inCell && (inV || inIsT) {
				if room := extractMaxSharedStringBytes - val.Len(); room > 0 {
					if len(t) > room {
						t = t[:room]
					}
					val.Write(t)
				}
			}
		}
	}
	flushRow()
	return nil
}

// --- out-of-process extraction (SECURITY H5) ----------------------
//
// The PDF / DOCX / XLSX parsers chew on attacker-supplied bytes, and a
// budget checked between pages can't stop a parser that never returns
// (a 300-byte PDF with a self-referential page tree spun forever inside
// the library). So the daemon re-executes its own binary with a hidden
// subcommand, feeds the document on stdin and reads the text from
// stdout:
//
//	<self> __extract-text <pdf|docx|xlsx> <max_chars>
//
// The child gets an empty environment (GOMAXPROCS aside) and only
// stdin/stdout/stderr, sets its own rlimits before reading the input
// (CPU 20 s, no file writes, no core files, 16 descriptors, data
// segment where the OS enforces it), caps its Go heap and runs a
// watchdog that exits past extractChildMaxMemory (darwin doesn't
// enforce RLIMIT_DATA / RLIMIT_AS, so the watchdog is the real memory
// bound there). The parent kills it after extractSandboxTimeout and
// caps what it reads back. The child never touches the session, the
// Keychain or the store: the dispatch runs before anything in main.
//
// A binary that didn't install the dispatch (MaybeRunExtractTextChild)
// falls back to in-process extraction under a goroutine timeout. That
// returns to the caller on time but cannot stop the parser: a hostile
// document can leave a goroutine spinning until the process exits.

// ExtractTextSubcommand is the hidden argv[1] that turns a binary into
// the extraction child.
const ExtractTextSubcommand = "__extract-text"

const (
	extractInProcessTimeout = 20 * time.Second
	extractChildMaxInput    = 256 << 20
	extractChildMaxMemory   = 1 << 30
	extractChildGoMemLimit  = 512 << 20
	extractChildStderrMax   = 2048
)

// extractSandboxEnabled is set when this binary can serve as the
// extraction child (MaybeRunExtractTextChild ran in main / TestMain).
var extractSandboxEnabled atomic.Bool

// Swapped in tests.
var (
	// extractExecutable locates the binary to re-execute.
	extractExecutable = os.Executable
	// extractSandboxTimeout bounds the child's wall-clock time.
	extractSandboxTimeout = 30 * time.Second
	// extractChildEnv is the child's whole environment: nothing from
	// ours (no tokens, no paths), just a small thread count.
	extractChildEnv = []string{"GOMAXPROCS=2"}
	// extractTextFn is the extractor the child and the in-process
	// fallback run.
	extractTextFn = extractText
	// extractChildCPUSeconds is the child's RLIMIT_CPU (soft; hard is +1).
	extractChildCPUSeconds uint64 = 20
)

// MaybeRunExtractTextChild must be called first thing in a binary that
// can host mail_attachment_text: when argv[1] is ExtractTextSubcommand
// it runs the extraction child and exits; otherwise it records that
// this binary supports the subcommand and returns.
func MaybeRunExtractTextChild() {
	if len(os.Args) >= 2 && os.Args[1] == ExtractTextSubcommand {
		os.Exit(runExtractTextChild(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	extractSandboxEnabled.Store(true)
}

// sandboxedFormat reports whether format's parser runs out of process.
func sandboxedFormat(format string) bool {
	switch format {
	case "pdf", "docx", "xlsx":
		return true
	}
	return false
}

// extractTextIsolated is the tool-facing extractor: it returns the
// text (at most limit runes) and the extracted length before that cut.
// PDF / DOCX / XLSX run in the sandboxed child when available.
func extractTextIsolated(ctx context.Context, format string, content []byte, limit int) (string, int, error) {
	if !sandboxedFormat(format) {
		text, err := extractText(format, content, limit)
		return text, utf8.RuneCountInString(text), err
	}
	if extractSandboxEnabled.Load() {
		return extractTextSubprocess(ctx, format, content, limit)
	}
	return extractTextInProcessGuarded(ctx, format, content, limit, extractInProcessTimeout)
}

// extractTextInProcessGuarded runs extractText on a goroutine and gives
// up after timeout. The goroutine is NOT stopped (Go can't); see the
// residual-risk note above.
func extractTextInProcessGuarded(ctx context.Context, format string, content []byte, limit int, timeout time.Duration) (string, int, error) {
	type result struct {
		text string
		err  error
	}
	fn := extractTextFn
	ch := make(chan result, 1) // buffered: a late finisher must not block
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("%s parse failed: %v", format, r)}
			}
		}()
		text, err := fn(format, content, limit)
		ch <- result{text: text, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", 0, r.err
		}
		return r.text, utf8.RuneCountInString(r.text), nil
	case <-timer.C:
		return "", 0, fmt.Errorf("text extraction gave up after %s (the document may be malformed or hostile)", timeout)
	case <-ctx.Done():
		return "", 0, ctx.Err()
	}
}

// cappedBuffer collects at most max bytes. Past that it either fails
// the write (so exec stops copying and the child dies on a broken
// pipe) or, with truncate, silently drops the rest.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	truncate bool
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.overflow = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		if c.truncate {
			return len(p), nil
		}
		return 0, errors.New("output limit exceeded")
	}
	return c.buf.Write(p)
}

// extractTextSubprocess runs the extraction child and parses its
// "<total runes>\n<text>" reply.
func extractTextSubprocess(ctx context.Context, format string, content []byte, limit int) (string, int, error) {
	exe, err := extractExecutable()
	if err != nil {
		return "", 0, fmt.Errorf("text extraction unavailable: locate executable: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, extractSandboxTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, ExtractTextSubcommand, format, strconv.Itoa(limit))
	cmd.Env = extractChildEnv
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(content)
	stdout := &cappedBuffer{max: extractOutputBudget(limit) + 32}
	stderr := &cappedBuffer{max: extractChildStderrMax, truncate: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "", 0, fmt.Errorf("text extraction was stopped after %s (the document may be malformed or hostile)", extractSandboxTimeout)
	case stdout.overflow:
		return "", 0, errors.New("text extraction produced more output than allowed; refusing")
	case runErr != nil:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			msg := strings.TrimSpace(cleanPlainText(stderr.buf.Bytes()))
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return "", 0, fmt.Errorf("text extraction was stopped (%s): the document exceeded the extractor's CPU or memory limits", ws.Signal())
			}
			if ee.ExitCode() == 2 && msg != "" {
				return "", 0, errors.New(clipRunes(msg, 500))
			}
			switch ee.ExitCode() {
			case 3:
				return "", 0, errors.New("text extraction was stopped: the document exceeded the extractor's memory limit")
			case 4:
				return "", 0, errors.New("text extraction was stopped: the document exceeded the extractor's CPU limit")
			}
		}
		return "", 0, fmt.Errorf("text extraction failed: %v", runErr)
	}
	out := stdout.buf.String()
	head, text, ok := strings.Cut(out, "\n")
	total, perr := strconv.Atoi(head)
	if !ok || perr != nil || total < 0 {
		return "", 0, errors.New("text extraction returned a malformed reply")
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "�")
	}
	return text, total, nil
}

// runExtractTextChild is the child side: args are <format> <max_chars>.
// Exit 0 → "<total runes>\n<text cut to max_chars>" on stdout; exit 2 →
// an extraction error on stderr; exit 3 → memory watchdog; exit 4 →
// CPU limit.
func runExtractTextChild(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 || !sandboxedFormat(args[0]) {
		fmt.Fprintf(stderr, "usage: %s <pdf|docx|xlsx> <max_chars>", ExtractTextSubcommand)
		return 2
	}
	limit, err := strconv.Atoi(args[1])
	if err != nil || limit < 0 || limit > maxReadMaxChars {
		fmt.Fprintf(stderr, "invalid max_chars %q", args[1])
		return 2
	}
	applyExtractChildLimits(stderr)
	startExtractMemoryWatchdog(extractChildMaxMemory, stderr)

	content, err := io.ReadAll(io.LimitReader(stdin, extractChildMaxInput+1))
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v", err)
		return 2
	}
	if len(content) > extractChildMaxInput {
		fmt.Fprintf(stderr, "input larger than %d bytes; refusing", extractChildMaxInput)
		return 2
	}
	text, err := extractTextFn(args[0], content, limit)
	if err != nil {
		fmt.Fprint(stderr, err.Error())
		return 2
	}
	total := utf8.RuneCountInString(text)
	text, _ = truncateRunes(text, limit)
	if _, err := fmt.Fprintf(stdout, "%d\n%s", total, text); err != nil {
		return 2
	}
	return 0
}

// applyExtractChildLimits sets the child's rlimits. Best-effort: a
// limit the OS refuses is skipped (the parent timeout and the memory
// watchdog still apply).
func applyExtractChildLimits(stderr io.Writer) {
	set := func(res int, v uint64) {
		_ = unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	// The soft CPU limit raises SIGXCPU, which the Go runtime ignores
	// unless asked for it, and darwin doesn't SIGKILL at the hard
	// limit: catch it and exit.
	xcpu := make(chan os.Signal, 1)
	signal.Notify(xcpu, syscall.SIGXCPU)
	go func() {
		<-xcpu
		fmt.Fprintf(stderr, "CPU limit (%ds) exceeded", extractChildCPUSeconds)
		os.Exit(4)
	}()
	_ = unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: extractChildCPUSeconds, Max: extractChildCPUSeconds + 1})
	set(unix.RLIMIT_FSIZE, 0)
	set(unix.RLIMIT_CORE, 0)
	set(unix.RLIMIT_NOFILE, 16)
	if runtime.GOOS == "darwin" {
		// Accepted but not enforced by darwin; enforced elsewhere it
		// would also count the Go runtime's reservations, so only
		// set it where it is harmless.
		set(unix.RLIMIT_DATA, extractChildMaxMemory)
	}
	debug.SetMemoryLimit(extractChildGoMemLimit)
}

// startExtractMemoryWatchdog exits the child once the Go runtime has
// mapped more than limit bytes.
func startExtractMemoryWatchdog(limit uint64, stderr io.Writer) {
	sample := []metrics.Sample{{Name: "/memory/classes/total:bytes"}}
	go func() {
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			metrics.Read(sample)
			if sample[0].Value.Kind() == metrics.KindUint64 && sample[0].Value.Uint64() > limit {
				fmt.Fprintf(stderr, "memory limit (%d bytes) exceeded", limit)
				os.Exit(3)
			}
		}
	}()
}

// cellReplacer keeps a cell on one TSV field.
var cellReplacer = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")

// colIndex converts the column letters of a cell reference ("C7" → 2).
func colIndex(ref string) (int, bool) {
	n := 0
	i := 0
	for ; i < len(ref); i++ {
		c := ref[i]
		if c < 'A' || c > 'Z' {
			break
		}
		n = n*26 + int(c-'A'+1)
		if n > 1<<20 {
			return 0, false
		}
	}
	if i == 0 {
		return 0, false
	}
	return n - 1, true
}
