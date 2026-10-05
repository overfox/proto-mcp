package mcptools

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// buildPDF assembles a minimal single-font PDF with one page per
// entry in pages, computing real xref offsets.
func buildPDF(pages ...string) []byte {
	var objs []string
	kids := ""
	n := len(pages)
	// 1 catalog, 2 pages, 3 font, then (page, content) pairs.
	for i := range pages {
		kids += fmt.Sprintf("%d 0 R ", 4+2*i)
	}
	objs = append(objs,
		"<< /Type /Catalog /Pages 2 0 R >>",
		fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids, n),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
	)
	for i, text := range pages {
		stream := fmt.Sprintf("BT /F1 12 Tf 72 700 Td (%s) Tj ET", text)
		objs = append(objs,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 3 0 R >> >> >>", 5+2*i),
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
		)
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func buildDOCX(t *testing.T) []byte {
	return buildZip(t, map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types/>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>
<w:p><w:r><w:t>Share Purchase Agreement</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Clause 1: </w:t></w:r><w:r><w:t>Price</w:t></w:r><w:r><w:tab/><w:t>CHF 1,000,000</w:t></w:r></w:p>
<w:tbl><w:tr><w:tc><w:p><w:r><w:t>Party</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Role</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
</w:body></w:document>`,
	})
}

func buildXLSX(t *testing.T) []byte {
	return buildZip(t, map[string]string{
		"xl/workbook.xml": `<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Positions" sheetId="1" r:id="rId2"/><sheet name="Cash" sheetId="2" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="worksheet" Target="worksheets/sheet2.xml"/>
<Relationship Id="rId2" Type="worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
		"xl/sharedStrings.xml": `<?xml version="1.0"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>ISIN</t></si><si><t>Qty</t></si>
<si><r><t>Nestl</t></r><r><t>é SA</t></r></si></sst>`,
		"xl/worksheets/sheet1.xml": `<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="D1" t="inlineStr"><is><t>Note</t></is></c></row>
<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2"><v>150</v></c><c r="C2" t="b"><v>1</v></c></row>
</sheetData></worksheet>`,
		"xl/worksheets/sheet2.xml": `<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t>CHF</t></is></c><c r="B1"><v>2500.5</v></c></row>
</sheetData></worksheet>`,
	})
}

func TestExtractPDF(t *testing.T) {
	got, err := extractPDF(buildPDF("Portfolio statement Q3", "Total CHF 42"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Portfolio statement Q3", "Total CHF 42", "--- page 2 ---"} {
		if !strings.Contains(got, want) {
			t.Errorf("pdf text missing %q: %q", want, got)
		}
	}
	// Garbage and truncated PDFs error (or recover), never panic.
	for _, bad := range [][]byte{[]byte("%PDF-1.4\ngarbage"), buildPDF("x")[:60], {}} {
		if _, err := extractPDF(bad, 0); err == nil {
			t.Errorf("expected error for malformed pdf %q", bad)
		}
	}
}

func TestExtractDOCX(t *testing.T) {
	got, err := extractDOCX(buildDOCX(t))
	if err != nil {
		t.Fatal(err)
	}
	want := "Share Purchase Agreement\nClause 1: Price\tCHF 1,000,000\nParty\n\tRole"
	if !strings.Contains(got, "Share Purchase Agreement\nClause 1: Price\tCHF 1,000,000") ||
		!strings.Contains(got, "Party") || !strings.Contains(got, "Role") {
		t.Errorf("docx text = %q, want like %q", got, want)
	}
}

func TestExtractXLSX(t *testing.T) {
	got, err := extractXLSX(buildXLSX(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "## Sheet: Positions\nISIN\tQty\t\tNote\nNestlé SA\t150\tTRUE\n\n## Sheet: Cash\nCHF\t2500.5"
	if got != want {
		t.Errorf("xlsx text =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractZipBombRefused(t *testing.T) {
	big := strings.Repeat("A", extractMaxZipEntryBytes+10)
	z := buildZip(t, map[string]string{"word/document.xml": big})
	if _, err := extractDOCX(z); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("expected decompression bound refusal, got %v", err)
	}
}

func TestDetectFormat(t *testing.T) {
	docx := buildDOCX(t)
	cases := []struct {
		mime, name string
		content    []byte
		want       string
	}{
		{"application/octet-stream", "x.bin", buildPDF("a"), "pdf"},
		{"application/pdf", "s.pdf", []byte("not really"), "pdf"},
		{"application/octet-stream", "contract", docx, "docx"}, // sniffed from zip
		{"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "p.xlsx", buildXLSX(t), "xlsx"},
		{"text/html; charset=utf-8", "a.html", []byte("<p>x</p>"), "html"},
		{"text/csv", "a.csv", []byte("a,b"), "csv"},
		{"text/plain", "notes", []byte("hi"), "text"},
		{"application/octet-stream", "notes.md", []byte("hi"), "text"},
		{"image/png", "a.png", []byte("\x89PNG"), ""},
		{"application/zip", "a.zip", buildZip(t, map[string]string{"x": "y"}), ""},
	}
	for _, c := range cases {
		if got := detectFormat(c.mime, c.name, c.content); got != c.want {
			t.Errorf("detectFormat(%q,%q) = %q, want %q", c.mime, c.name, got, c.want)
		}
	}
}

func TestCleanPlainTextStripsControls(t *testing.T) {
	in := "\uFEFFline1\r\nline2\x1b[31m\u202Eevil\u200B\tend\xff"
	got := cleanPlainText([]byte(in))
	if got != "line1\nline2[31mevil\tend\uFFFD" {
		t.Errorf("cleanPlainText = %q", got)
	}
}

func TestMailAttachmentText_FakeServer(t *testing.T) {
	f := newFakeProton(t)
	docx := buildDOCX(t)
	id, atts := f.createMessageWithAttachments(t, "contract", "see attached",
		fakeAttachment{Name: "spa.docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Body: docx},
		fakeAttachment{Name: "logo.png", MIME: "image/png", Body: []byte("\x89PNG\r\n")},
	)
	tl := mailAttachmentText(f.deps())

	var out struct {
		Filename   string `json:"filename"`
		Format     string `json:"format"`
		Text       string `json:"text"`
		TotalChars int    `json:"total_chars"`
		Truncated  bool   `json:"truncated"`
	}
	res := callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"attachment_id":%q}`, id, atts[0]), &out)
	if res.IsError {
		t.Fatalf("error: %s", res.Content[0].Text)
	}
	if out.Format != "docx" || out.Filename != "spa.docx" || out.Truncated {
		t.Errorf("result = %+v", out)
	}
	if !strings.Contains(out.Text, "Share Purchase Agreement") || !strings.HasPrefix(out.Text, untrustedBodyBegin) {
		t.Errorf("text not extracted / not fenced: %q", out.Text)
	}

	// Cached now; max_chars truncation reports total.
	res = callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"attachment_id":%q,"max_chars":5}`, id, atts[0]), &out)
	if res.IsError || !out.Truncated || out.TotalChars <= 5 || !strings.Contains(out.Text, "Share\n"+untrustedBodyEnd) {
		t.Errorf("truncation: %+v", out)
	}
	if _, err := f.st.GetCachedAttachment(context.Background(), id, atts[0]); err != nil {
		t.Errorf("attachment should be cached: %v", err)
	}

	// Unsupported type → tool error, not a crash.
	res = callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"attachment_id":%q}`, id, atts[1]), nil)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "not a supported type") {
		t.Errorf("png should be unsupported: %+v", res)
	}
}

func TestMailAttachmentText_CacheHitNoSession(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.UpsertMessage(ctx, store.Message{ID: "m", ThreadID: "m"}); err != nil {
		t.Fatal(err)
	}
	pdfBytes := buildPDF("Margin call notice")
	if err := st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
		MessageID: "m", AttachmentID: "a", Filename: "notice.pdf", MIMEType: "application/pdf",
		SizeBytes: int64(len(pdfBytes)), Content: pdfBytes,
	}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Format string `json:"format"`
		Text   string `json:"text"`
	}
	res := callTool(t, mailAttachmentText(Deps{Store: st}), `{"message_id":"m","attachment_id":"a"}`, &out)
	if res.IsError || out.Format != "pdf" || !strings.Contains(out.Text, "Margin call notice") {
		t.Errorf("cached pdf: %+v %v", out, res.Content[0].Text)
	}
}
