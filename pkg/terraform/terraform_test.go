package terraform

import (
	"testing"
)

func TestTfCollcetion(t *testing.T) {

	collection := NewCollection()

	if collection == nil {
		t.Error("Empty collection")
	}

}
