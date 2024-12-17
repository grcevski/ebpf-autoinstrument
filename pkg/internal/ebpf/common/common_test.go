package ebpfcommon

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const privilegedEnv = "PRIVILEGED_TESTS"

func setIntegrity(t *testing.T, path, text string) {
	err := os.WriteFile(path, []byte(text), 0644)
	assert.NoError(t, err)
}

func setNotReadable(t *testing.T, path string) {
	err := os.Chmod(path, 000)
	assert.NoError(t, err)
}

func TestLockdownParsing(t *testing.T) {
	noFile, err := os.CreateTemp("", "not_existent_fake_lockdown")
	assert.NoError(t, err)
	notPath, err := filepath.Abs(noFile.Name())
	assert.NoError(t, err)
	noFile.Close()
	os.Remove(noFile.Name())

	// Setup for testing file that doesn't exist
	lockdownPath = notPath
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	tempFile, err := os.CreateTemp("", "fake_lockdown")
	assert.NoError(t, err)
	path, err := filepath.Abs(tempFile.Name())
	assert.NoError(t, err)
	tempFile.Close()

	defer os.Remove(tempFile.Name())
	// Setup for testing
	lockdownPath = path

	setIntegrity(t, path, "none [integrity] confidentiality\n")
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())

	setIntegrity(t, path, "[none] integrity confidentiality\n")
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	setIntegrity(t, path, "none integrity [confidentiality]\n")
	assert.Equal(t, KernelLockdownConfidentiality, KernelLockdownMode())

	setIntegrity(t, path, "whatever\n")
	assert.Equal(t, KernelLockdownOther, KernelLockdownMode())

	setIntegrity(t, path, "")
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())

	if os.Getenv(privilegedEnv) != "" {
		// This test doesn't pass when run as sudo
		t.Skipf("Skipping this test because %v is set", privilegedEnv)
	}

	setIntegrity(t, path, "[none] integrity confidentiality\n")
	setNotReadable(t, path)
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())
}

type dummyCloser struct {
	closed bool
}

func (d *dummyCloser) Close() error {
	d.closed = true
	return nil
}

func TestInstrumetedLibsT(t *testing.T) {
	libs := make(InstrumentedLibsT)

	const id = uint64(10)

	assert.Nil(t, libs.Find(id))

	module := libs.At(id)

	assert.NotNil(t, module)

	closer := &dummyCloser{closed: false}
	module.AddClosers([]io.Closer{closer})

	removeRef := func(id uint64) *LibModule {
		m, _ := libs.RemoveRef(id)
		return m
	}

	assert.NotNil(t, libs.Find(id))

	assert.Equal(t, uint64(0), module.references)

	assert.Equal(t, module, libs.AddRef(id))
	assert.Equal(t, uint64(1), module.references)

	assert.Equal(t, module, libs.AddRef(id))
	assert.Equal(t, uint64(2), module.references)

	assert.Equal(t, module, libs.Find(id))

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(1), module.references)
	assert.False(t, closer.closed)

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(0), module.references)
	assert.True(t, closer.closed)

	assert.Nil(t, libs.Find(id))
}
