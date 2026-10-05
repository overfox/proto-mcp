package mcptools

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ledongthuc/pdf"

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
// expansion (zip bombs, pathological PDFs).
const (
	extractMaxZipEntryBytes = 64 << 20 // per decompressed XML part
	extractMaxZipEntries    = 10000
	extractPDFTimeBudget    = 20 * time.Second
	extractMaxSheets        = 200
)

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

// extractText dispatches on format. limit is a rune budget: extractors
// may stop once they have produced more than limit runes (the caller
// truncates precisely and reports truncated).
func extractText(format string, content []byte, limit int) (string, error) {
	switch format {
	case "pdf":
		return extractPDF(content, limit)
	case "docx":
		return extractDOCX(content)
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
	var b strings.Builder
	n := r.NumPage()
	for i := 1; i <= n; i++ {
		if time.Now().After(deadline) {
			b.WriteString(fmt.Sprintf("\n[extraction stopped after %d of %d pages: time budget]\n", i-1, n))
			break
		}
		text, perr := r.Page(i).GetPlainText(nil)
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
	zr, err := openZip(content)
	if err != nil {
		return "", err
	}
	doc, err := readZipPart(zr, "word/document.xml")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	d := newXMLDecoder(doc)
	inText := false
	for {
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
		b.WriteString("## Sheet: " + sh.name + "\n")
		if err := xlsxWriteSheet(&b, data, shared, limit); err != nil {
			b.WriteString(fmt.Sprintf("[parse error: %v]\n", err))
		}
		b.WriteString("\n")
		if limit > 0 && b.Len() > limit*4 && utf8.RuneCountInString(b.String()) > limit {
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
				out = append(out, cur.String())
			case "t":
				inT = false
			case "rPh":
				inRPh = false
			}
		case xml.CharData:
			if inSI && inT && !inRPh {
				cur.Write(t)
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
func xlsxWriteSheet(b *strings.Builder, data []byte, shared []string, limit int) error {
	d := newXMLDecoder(data)
	var (
		row      []string
		cellType string
		cellCol  int
		inV      bool
		inIsT    bool
		val      strings.Builder
		inCell   bool
	)
	flushRow := func() {
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
				// would otherwise allocate a 16k-wide row per cell).
				if cellCol > 1000 {
					cellCol = len(row)
				}
				for len(row) < cellCol {
					row = append(row, "")
				}
				text = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(text)
				if cellCol < len(row) {
					row[cellCol] = text
				} else {
					row = append(row, text)
				}
			case "row":
				flushRow()
				if limit > 0 && b.Len() > limit*4 {
					return nil
				}
			}
		case xml.CharData:
			if inCell && (inV || inIsT) {
				val.Write(t)
			}
		}
	}
	flushRow()
	return nil
}

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
