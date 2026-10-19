package mcptools

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// SECURITY H5 regression tests: hostile documents can't hang or
// balloon mail_attachment_text.

// loopPDF is the assessment PoC: the page tree's /Kids points at
// itself, which made the library's Page(1) descend forever.
func loopPDF() []byte {
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [2 0 R] /Count 5 >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	var offs []int
	for i, o := range objs {
		offs = append(offs, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

// within runs f and fails the test if it hasn't returned in d.
func returnsWithin(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("still running after %s", d)
	}
}

// In-process guard: the bounded page-tree walk rejects the cycle.
func TestSec_PDFPageLoop_InProcess(t *testing.T) {
	returnsWithin(t, 5*time.Second, func() {
		_, err := extractPDF(loopPDF(), 30000)
		if err == nil || !strings.Contains(err.Error(), "page tree") {
			t.Errorf("err = %v, want page-tree refusal", err)
		}
	})
	// The real multi-page path still works.
	got, err := extractPDF(buildPDF("one", "two", "three"), 0)
	if err != nil || !strings.Contains(got, "three") || !strings.Contains(got, "--- page 3 ---") {
		t.Fatalf("multi-page: %q, %v", got, err)
	}
}

// Subprocess path: same PoC through the sandboxed child.
func TestSec_PDFPageLoop_Subprocess(t *testing.T) {
	if !extractSandboxEnabled.Load() {
		t.Fatal("TestMain should have enabled the extraction child")
	}
	returnsWithin(t, extractSandboxTimeout+5*time.Second, func() {
		_, _, err := extractTextIsolated(context.Background(), "pdf", loopPDF(), 30000)
		if err == nil || !strings.Contains(err.Error(), "page tree") {
			t.Errorf("err = %v, want page-tree refusal from the child", err)
		}
	})
	text, total, err := extractTextIsolated(context.Background(), "pdf", buildPDF("Portfolio statement Q3"), 10)
	if err != nil || text != "Portfolio " || total != len("Portfolio statement Q3") {
		t.Fatalf("child round trip: text=%q total=%d err=%v", text, total, err)
	}
}

// A parser that never returns: the parent kills the child on time.
func TestSec_ExtractChildKilledOnHang(t *testing.T) {
	prevEnv, prevTimeout := extractChildEnv, extractSandboxTimeout
	extractChildEnv = append([]string{testChildHangEnv}, prevEnv...)
	extractSandboxTimeout = 2 * time.Second
	t.Cleanup(func() { extractChildEnv, extractSandboxTimeout = prevEnv, prevTimeout })

	start := time.Now()
	_, _, err := extractTextIsolated(context.Background(), "pdf", buildPDF("x"), 100)
	if err == nil || !strings.Contains(err.Error(), "stopped after") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %s", el)
	}
}

// A spinning parser hits the child's RLIMIT_CPU (1 s here) before the
// wall-clock timeout.
func TestSec_ExtractChildCPULimit(t *testing.T) {
	prev := extractChildEnv
	extractChildEnv = append([]string{testChildHangEnv, testChildCPU1Env}, prev...)
	t.Cleanup(func() { extractChildEnv = prev })
	start := time.Now()
	_, _, err := extractTextIsolated(context.Background(), "pdf", buildPDF("x"), 100)
	if err == nil || !strings.Contains(err.Error(), "CPU limit") {
		t.Fatalf("err = %v, want CPU-limit stop", err)
	}
	if el := time.Since(start); el > 15*time.Second {
		t.Fatalf("took %s", el)
	}
}

// A parser that eats memory: the child's watchdog stops it.
func TestSec_ExtractChildMemoryCap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~1 GiB in a child process")
	}
	prev := extractChildEnv
	extractChildEnv = append([]string{testChildHogEnv}, prev...)
	t.Cleanup(func() { extractChildEnv = prev })
	_, _, err := extractTextIsolated(context.Background(), "xlsx", []byte("PK"), 100)
	if err == nil || !strings.Contains(err.Error(), "memory") {
		t.Fatalf("err = %v, want memory-limit stop", err)
	}
}

// In-process fallback (binaries without the hidden subcommand): a hang
// returns an error on time.
func TestSec_ExtractInProcessGuardTimeout(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	prev := extractTextFn
	extractTextFn = func(string, []byte, int) (string, error) { <-block; return "", nil }
	t.Cleanup(func() { extractTextFn = prev })

	_, _, err := extractTextInProcessGuarded(context.Background(), "pdf", nil, 10, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "gave up") {
		t.Fatalf("err = %v, want timeout", err)
	}
	// And a panic inside the parser is an error, not a crash.
	extractTextFn = func(string, []byte, int) (string, error) { panic("boom") }
	if _, _, err := extractTextInProcessGuarded(context.Background(), "pdf", nil, 10, time.Second); err == nil {
		t.Fatal("panic not converted to an error")
	}
}

func xlsxBomb(t *testing.T, cells int) []byte {
	t.Helper()
	big := strings.Repeat("A", 8<<20) // one 8 MiB shared string
	var sheet bytes.Buffer
	sheet.WriteString(`<worksheet><sheetData><row>`)
	for i := 0; i < cells; i++ {
		sheet.WriteString(`<c t="s"><v>0</v></c>`)
	}
	sheet.WriteString(`</row></sheetData></worksheet>`)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{
		"xl/sharedStrings.xml":     []byte(`<sst><si><t>` + big + `</t></si></sst>`),
		"xl/worksheets/sheet1.xml": sheet.Bytes(),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The PoC: an ~8 KB xlsx whose one 8 MiB shared string is referenced
// from 60 cells allocated 1.48 GiB. Output and allocation are bounded.
func TestSec_XLSXAmplificationBounded(t *testing.T) {
	z := xlsxBomb(t, 60)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	out, err := extractXLSX(z, 30000)
	runtime.ReadMemStats(&m1)
	if err != nil {
		t.Fatal(err)
	}
	if max := extractOutputBudget(30000); len(out) > max {
		t.Errorf("output %d bytes, want <= %d", len(out), max)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 160<<20 {
		t.Errorf("allocated %d MiB, want bounded (was ~1500 MiB)", alloc>>20)
	}
	// Through the child, the tool sees the capped window.
	text, total, err := extractTextIsolated(context.Background(), "xlsx", z, 30000)
	if err != nil || len([]rune(text)) != 30000 || total < 30000 {
		t.Fatalf("child: len=%d total=%d err=%v", len([]rune(text)), total, err)
	}
}

// Rows without r= attributes are capped too.
func TestSec_XLSXCellsPerRowCapped(t *testing.T) {
	var sheet bytes.Buffer
	sheet.WriteString(`<worksheet><sheetData><row>`)
	for i := 0; i < 5000; i++ {
		sheet.WriteString(`<c t="inlineStr"><is><t>x</t></is></c>`)
	}
	sheet.WriteString(`</row></sheetData></worksheet>`)
	var b strings.Builder
	if err := xlsxWriteSheet(&b, sheet.Bytes(), nil, 1<<20); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(b.String(), "x"); n != extractMaxCellsPerRow {
		t.Errorf("cells kept = %d, want %d", n, extractMaxCellsPerRow)
	}
}
