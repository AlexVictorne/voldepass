package main

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestNewLogger_ValidLevel(t *testing.T) {
	log := newLogger("debug")
	assert.Equal(t, zerolog.DebugLevel, log.GetLevel())
}

func TestNewLogger_InvalidLevel_DefaultsToInfo(t *testing.T) {
	log := newLogger("not-a-level")
	assert.Equal(t, zerolog.InfoLevel, log.GetLevel())
}
