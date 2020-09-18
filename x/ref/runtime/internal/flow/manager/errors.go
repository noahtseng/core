package manager

import "v.io/v23/verror"

var (
	// These were defined in errors.vdl using the ID values
	// below rather than the more conventional Err<Name>.
	errUnknownProtocol           = verror.NewID("UnknownProtocol")
	errManagerClosed             = verror.NewID("ManagerClosed")
	errAcceptFailed              = verror.NewID("AcceptFailed")
	errCacheClosed               = verror.NewID("CacheClosed")
	errConnKilledToFreeResources = verror.NewID("ConnKilledToFreeResources")
	errInvalidProxyResponse      = verror.NewID("InvalidProxyResponse")
	errManagerDialingSelf        = verror.NewID("ManagerDialingSelf")
	errListeningWithNullRid      = verror.NewID("ListeningWithNullRid")
	errProxyResponse             = verror.NewID("ProxyResponse")
	errNoBlessingsForPeer        = verror.NewID("NoBlessingsForPeer")
	errConnNotInCache            = verror.NewID("ConnNotInCache")
)