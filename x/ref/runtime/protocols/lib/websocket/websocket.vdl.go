// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file was auto-generated by the vanadium vdl tool.
// Package: websocket

//nolint:golint
package websocket

import (
	"v.io/v23/context"
	"v.io/v23/i18n"
	"v.io/v23/verror"
)

var _ = initializeVDL() // Must be first; see initializeVDL comments for details.

//////////////////////////////////////////////////
// Error definitions

var (
	ErrListenerClosed     = verror.Register("v.io/x/ref/runtime/protocols/lib/websocket.ListenerClosed", verror.NoRetry, "{1:}{2:} listener is already closed.")
	ErrListenCalledInNaCl = verror.Register("v.io/x/ref/runtime/protocols/lib/websocket.ListenCalledInNaCl", verror.NoRetry, "{1:}{2:} Listen cannot be called in NaCl code.")
)

// NewErrListenerClosed returns an error with the ErrListenerClosed ID.
func NewErrListenerClosed(ctx *context.T) error {
	return verror.New(ErrListenerClosed, ctx)
}

// NewErrListenCalledInNaCl returns an error with the ErrListenCalledInNaCl ID.
func NewErrListenCalledInNaCl(ctx *context.T) error {
	return verror.New(ErrListenCalledInNaCl, ctx)
}

var initializeVDLCalled bool

// initializeVDL performs vdl initialization.  It is safe to call multiple times.
// If you have an init ordering issue, just insert the following line verbatim
// into your source files in this package, right after the "package foo" clause:
//
//    var _ = initializeVDL()
//
// The purpose of this function is to ensure that vdl initialization occurs in
// the right order, and very early in the init sequence.  In particular, vdl
// registration and package variable initialization needs to occur before
// functions like vdl.TypeOf will work properly.
//
// This function returns a dummy value, so that it can be used to initialize the
// first var in the file, to take advantage of Go's defined init order.
func initializeVDL() struct{} {
	if initializeVDLCalled {
		return struct{}{}
	}
	initializeVDLCalled = true

	// Set error format strings.
	i18n.Cat().SetWithBase(i18n.LangID("en"), i18n.MsgID(ErrListenerClosed.ID), "{1:}{2:} listener is already closed.")
	i18n.Cat().SetWithBase(i18n.LangID("en"), i18n.MsgID(ErrListenCalledInNaCl.ID), "{1:}{2:} Listen cannot be called in NaCl code.")

	return struct{}{}
}
