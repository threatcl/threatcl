package terraform

import (
	"testing"
)

func TestTfCollcetion(t *testing.T) {

	tfCollectionJson := ""

	collection := NewCollection(&tfCollectionJson)

	if collection == nil {
		t.Error("Empty collection")
	}

}
