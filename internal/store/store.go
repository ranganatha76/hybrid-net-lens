package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"hybrid-net-lens/internal/diagnostic"
)

var ErrNotFound = errors.New("report not found")
var reportID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Store struct {
	mu      sync.Mutex
	dir     string
	maximum int
}

type Summary struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
}

// New opens a single-process report store with a positive retention limit.
// It creates the directory with owner-only permissions when it does not exist.
// An existing path must be a real directory with no group or other permission bits.
// A readiness write verifies the directory can create, write, sync, and close a file.
// Initialization returns the first filesystem or validation error without loading reports.
func New(dir string, maximum int) (*Store, error) {
	if maximum < 1 {
		return nil, errors.New("maximum reports must be positive")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("data directory must be a real directory accessible only to its owner (0700)")
	}
	storage := &Store{dir: dir, maximum: maximum}
	if err := storage.Ready(); err != nil {
		return nil, err
	}
	return storage, nil
}

// Ready checks whether the report directory supports the store's basic write path.
// It holds the store mutex to avoid racing other operations in this process.
// A temporary file is created, written with a small marker, and synchronized.
// The file is closed and scheduled for removal before the readiness check returns.
// Sync and close failures are combined so either can make the service unready.
func (storage *Store) Ready() error {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	file, err := os.CreateTemp(storage.dir, ".ready-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write([]byte("ready")); err != nil {
		file.Close()
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	return errors.Join(err, closeErr)
}

// Save persists one report while serializing access through the store mutex.
// It requires a safe hexadecimal report ID and JSON no larger than 1 MiB.
// Data is written to an owner-only temporary file and synced before atomic rename.
// Retention pruning removes older reports after the new report becomes visible.
// The directory is synced last; any failed step returns an error to the caller.
func (storage *Store) Save(report diagnostic.Report) error {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	if !reportID.MatchString(report.ID) {
		return errors.New("invalid report ID")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("report exceeds 1 MiB")
	}
	file, err := os.CreateTemp(storage.dir, ".report-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(storage.dir, report.ID+".json")); err != nil {
		return err
	}
	if err := storage.prune(); err != nil {
		return err
	}
	directory, err := os.Open(storage.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Get loads one persisted report under the store's process-local mutex.
// It serializes the read against saves and retention pruning in the same store.
// Identifier and file-content validation are delegated to the private get helper.
// Missing or unsafe identifiers return ErrNotFound rather than accessing arbitrary paths.
// Other read errors and the decoded report are passed back without additional mutation.
func (storage *Store) Get(identifier string) (diagnostic.Report, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.get(identifier)
}

// get reads and validates a report while its caller holds the store mutex.
// It rejects unsafe IDs, nonregular files, and files exceeding the 1 MiB bound.
// Missing paths map to ErrNotFound, while other filesystem failures remain errors.
// Bounded JSON decoding requires one document with no trailing data.
// The embedded report ID and schema version must match the requested supported report.
func (storage *Store) get(identifier string) (diagnostic.Report, error) {
	var report diagnostic.Report
	if !reportID.MatchString(identifier) {
		return report, ErrNotFound
	}
	path := filepath.Join(storage.dir, identifier+".json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return report, ErrNotFound
	}
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return report, errors.New("report must be a regular file no larger than 1 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, (1<<20)+1))
	if err := decoder.Decode(&report); err != nil {
		return report, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return report, errors.New("report contains trailing data")
	}
	if report.ID != identifier || report.SchemaVersion != "1" {
		return report, errors.New("invalid stored report")
	}
	return report, nil
}

// List returns up to the requested number of recent persisted report summaries.
// The limit must be between one and 100, and the store mutex covers the entire read.
// Candidate files are ordered newest-first by modification time through files.
// Each selected report is fully validated before its compact summary is appended.
// A corrupt selected report fails the listing instead of being silently skipped.
func (storage *Store) List(limit int) ([]Summary, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	if limit < 1 || limit > 100 {
		return nil, errors.New("limit must be 1..100")
	}
	files, err := storage.files()
	if err != nil {
		return nil, err
	}
	summaries := []Summary{}
	for _, file := range files[:min(limit, len(files))] {
		report, err := storage.get(file.name[:32])
		if err != nil {
			return nil, fmt.Errorf("read report: %w", err)
		}
		summaries = append(summaries, Summary{ID: report.ID, TargetID: report.Target.ID, Status: report.Status, StartedAt: report.StartedAt})
	}
	return summaries, nil
}

type reportFile struct {
	name     string
	modified time.Time
}

// files discovers report-shaped entries in the storage directory for a locked caller.
// Only filenames with a valid 32-character report ID and .json suffix are considered.
// Matching entries must be regular files; filesystem metadata failures abort discovery.
// Modification times determine newest-first ordering for listing and retention.
// Equal timestamps use ascending filenames as a stable deterministic tie-breaker.
func (storage *Store) files() ([]reportFile, error) {
	entries, err := os.ReadDir(storage.dir)
	if err != nil {
		return nil, err
	}
	files := []reportFile{}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 37 || filepath.Ext(name) != ".json" || !reportID.MatchString(name[:32]) {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, errors.New("report path must be a regular file")
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		files = append(files, reportFile{name: name, modified: info.ModTime()})
	}
	slices.SortFunc(files, func(first, second reportFile) int {
		if order := second.modified.Compare(first.modified); order != 0 {
			return order
		}
		if first.name < second.name {
			return -1
		}
		if first.name > second.name {
			return 1
		}
		return 0
	})
	return files, nil
}

// prune enforces count-based report retention while the caller holds the mutex.
// It obtains the same newest-first file ordering used by report listing.
// The newest configured maximum number of reports are retained.
// Each remaining older report is removed from the storage directory.
// Discovery or removal failures stop pruning and propagate to the save operation.
func (storage *Store) prune() error {
	files, err := storage.files()
	if err != nil {
		return err
	}
	for _, file := range files[min(storage.maximum, len(files)):] {
		if err := os.Remove(filepath.Join(storage.dir, file.name)); err != nil {
			return err
		}
	}
	return nil
}
