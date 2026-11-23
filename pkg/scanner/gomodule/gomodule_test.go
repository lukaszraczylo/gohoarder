package gomodule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPath(t *testing.T) {
	assert.Equal(t, "golang.org/x/text", Path("golang.org/x/text/@v/v0.3.5.zip"))
	assert.Equal(t, "github.com/Azure/go-x", Path("github.com/!azure/go-x/@v/v1.2.3.zip"))
	assert.Equal(t, "github.com/a/b/v2", Path("github.com/a/b/v2"))
}
