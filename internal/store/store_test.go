package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"hybrid-net-lens/internal/diagnostic"
)

func TestPersistenceRetentionAndConcurrentAccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	storage, err := New(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for index := 0; index < 12; index++ {
		workers.Go(func() {
			report := diagnostic.Report{ID: fmt.Sprintf("%032x", index), SchemaVersion: "1", Status: "healthy", StartedAt: time.Now().UTC()}
			if err := storage.Save(report); err != nil {
				t.Error(err)
			}
			if _, err := storage.List(3); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	reopened, err := New(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	list, err := reopened.List(100)
	if err != nil || len(list) != 3 {
		t.Fatalf("%+v, %v", list, err)
	}
	for _, summary := range list {
		report, err := reopened.Get(summary.ID)
		if err != nil || report.ID != summary.ID {
			t.Fatalf("%+v, %v", report, err)
		}
		info, err := os.Stat(filepath.Join(dir, report.ID+".json"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("report permissions are not 0600")
		}
	}
	if _, err := reopened.Get("../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestRejectInsecureDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, 3); err == nil {
		t.Fatal("accepted public directory")
	}
}

func TestRejectCorruptAndSymlinkReports(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	storage, err := New(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	identifier := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(dir, identifier+".json")
	if err := os.WriteFile(path, []byte(`{"id":"0123456789abcdef0123456789abcdef","schema_version":"1"} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Get(identifier); err == nil {
		t.Fatal("accepted trailing data")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hosts", path); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Get(identifier); err == nil {
		t.Fatal("accepted symlink")
	}
}
