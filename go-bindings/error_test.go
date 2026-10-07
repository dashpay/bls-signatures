package blschia

import (
	"runtime"
	"testing"
)

func TestErrorMessageThreadOwnership(t *testing.T) {
	firstWritten := make(chan struct{})
	secondWritten := make(chan struct{})
	firstResult := make(chan [2]error, 1)
	secondResult := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, before := G1ElementFromBytes([]byte{0})
		close(firstWritten)
		<-secondWritten
		firstResult <- [2]error{before, errFromC()}
	}()
	go func() {
		<-firstWritten
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, err := G2ElementFromBytes([]byte{0})
		secondResult <- err
		close(secondWritten)
	}()

	for i, err := range <-firstResult {
		if err == nil || err.Error() != "G1Element::FromBytes: Invalid size" {
			t.Errorf("first thread error %d = %v", i, err)
		}
	}
	if err := <-secondResult; err == nil || err.Error() != "G2Element::FromBytes: Invalid size" {
		t.Errorf("second thread error = %v", err)
	}
}
