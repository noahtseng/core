package context

import (
	"context"
	"testing"
)

func hasKeys(ctx *T, t *testing.T, keys ...interface{}) {
	for _, key := range keys {
		if ctx.Value(key) == nil {
			t.Errorf("key %T %v missing", key, key)
		}
	}
}

func TestCopy(t *testing.T) {
	root, cancel := RootContext()
	defer cancel()
	hasKeys(root, t, rootKey, loggerKey)

	gctx := FromGoContextWithValues(context.Background(), root)
	hasKeys(gctx, t, rootKey, loggerKey)

	type ts int
	root = WithValue(root, ts(0), ts(-1))
	hasKeys(root, t, rootKey, loggerKey, ts(0))
	gctx = FromGoContextWithValues(context.Background(), root)
	hasKeys(gctx, t, rootKey, loggerKey, ts(0))

	rc, cancel := WithRootCancel(root)
	defer cancel()
	hasKeys(rc, t, rootKey, loggerKey, ts(0))
	if got, want := rc.Value(ts(0)).(ts), ts(-1); got != want {
		t.Errorf("got %v, want %v", got, want)
	}

}
