//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Behaviour tests for the node drop-in importer (patchset/feat-local-nodes-import.patch).
 * They are NOT part of the patch -- they are a maintenance fixture for
 * verifying the patch against a wing revision bump:
 *
 *	# from a checkout of the wing revision pinned in daed/Makefile:
 *	git clone https://github.com/daeuniverse/dae-wing wing && cd wing
 *	git checkout <WING_HASH>
 *	<run the same RetargetWingAtCore rewrites as daed/Makefile>
 *	patch --forward -p1 < ../patchset/build_fixes.patch || true
 *	patch --forward -p1 < ../patchset/feat-local-nodes-import.patch
 *	cp ../patchset/tests/wing-local-nodes_test.go graphql/service/subscription/
 *	GOOS=linux GOARCH=amd64 go test -tags dae_stub_ebpf ./graphql/service/subscription/
 *
 * (GOOS=linux is required: the wing tree only builds for Linux. On a non-Linux
 * host, build the test binary with `go test -c` and run it inside a container.)
 */

package subscription

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae-config-dist/db"
)

const cfMacFixture = `{
  "activeNodeId": "a",
  "nodes": [
    {"id":"a","name":"台湾-联通-1","wssAddr":"edge.example.workers.dev:443/?ip=1.1.1.1:443","prefIp":"203.0.113.7","echDns":"dns.example/dns-query","echDomain":"cloudflare-ech.com","token":"tok1"},
    {"id":"b","name":"日本-联通-2","wssAddr":"edge.example.workers.dev:443/","prefIp":"198.51.100.9","token":"tok2"}
  ]
}`

// setup points the importer at a temp dir and an empty database.
func setup(t *testing.T) (ctx context.Context, dir string) {
	t.Helper()
	root := t.TempDir()
	if err := db.InitDatabase(root); err != nil {
		t.Fatalf("init db: %v", err)
	}
	LocalNodesDir = filepath.Join(root, "nodes.d")
	SyncReportPath = filepath.Join(root, "report.json")
	if err := os.MkdirAll(LocalNodesDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return context.Background(), root
}

func writeFixture(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(LocalNodesDir, name), []byte(content), 0600); err != nil {
		t.Fatalf("write %v: %v", name, err)
	}
}

func readReport(t *testing.T) syncReport {
	t.Helper()
	b, err := os.ReadFile(SyncReportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r syncReport
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return r
}

func entryFor(t *testing.T, r syncReport, tag string) syncReportEntry {
	t.Helper()
	for _, e := range r.Entries {
		if e.Tag == tag {
			return e
		}
	}
	t.Fatalf("no report entry for tag %v (entries: %+v)", tag, r.Entries)
	return syncReportEntry{}
}

func nodeNames(t *testing.T, ctx context.Context, subID uint) []string {
	t.Helper()
	var nodes []db.Node
	if err := db.DB(ctx).Where("subscription_id = ?", subID).Find(&nodes).Error; err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	return names
}

func subByTag(t *testing.T, ctx context.Context, tag string) db.Subscription {
	t.Helper()
	var sub db.Subscription
	if err := db.DB(ctx).Where("tag = ?", tag).First(&sub).Error; err != nil {
		t.Fatalf("subscription %v: %v", tag, err)
	}
	return sub
}

// TestSyncLocalImportsCfMacNodes covers the happy path: the file becomes a
// subscription, the node names come from the "name" field, a group named after
// the tag is created and bound, and the import report says so.
func TestSyncLocalImportsCfMacNodes(t *testing.T) {
	ctx, _ := setup(t)
	writeFixture(t, "ech_nodes.json", cfMacFixture)

	SyncLocalSubscriptions(ctx)

	sub := subByTag(t, ctx, "ech_nodes")
	names := nodeNames(t, ctx, sub.ID)
	if len(names) != 2 {
		t.Fatalf("expected 2 nodes, got %v (%v)", len(names), names)
	}
	found := false
	for _, n := range names {
		if n == "台湾-联通-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("node name from the name field missing: %v", names)
	}

	entry := entryFor(t, readReport(t), "ech_nodes")
	if entry.Status != "imported" || entry.Nodes != 2 {
		t.Fatalf("unexpected report entry: %+v", entry)
	}

	var group db.Group
	if err := db.DB(ctx).Where("name = ?", "ech_nodes").First(&group).Error; err != nil {
		t.Fatalf("group not created: %v", err)
	}
	var bindings int64
	if err := db.DB(ctx).Model(&db.GroupSubscription{}).
		Where("group_id = ? and subscription_id = ?", group.ID, sub.ID).
		Count(&bindings).Error; err != nil || bindings != 1 {
		t.Fatalf("group binding missing (count=%v err=%v)", bindings, err)
	}
}

// TestSyncLocalPlaintextList covers the documented .txt support.
func TestSyncLocalPlaintextList(t *testing.T) {
	ctx, _ := setup(t)
	writeFixture(t, "plain.txt", "# comment\n\nsocks5://127.0.0.1:1080#local\nsocks5://127.0.0.1:1081#local2\n")

	SyncLocalSubscriptions(ctx)

	sub := subByTag(t, ctx, "plain")
	names := nodeNames(t, ctx, sub.ID)
	if len(names) != 2 {
		t.Fatalf("plaintext list not imported: %v", names)
	}
	entry := entryFor(t, readReport(t), "plain")
	if entry.Status != "imported" || entry.Nodes != 2 {
		t.Fatalf("unexpected report entry: %+v", entry)
	}
}

// TestSyncLocalTagConflictIsReported covers the silently-skipped case: a tag
// already owned by a user-managed subscription must be surfaced, not hidden.
func TestSyncLocalTagConflictIsReported(t *testing.T) {
	ctx, _ := setup(t)
	taken := "taken"
	if err := db.DB(ctx).Create(&db.Subscription{
		UpdatedAt: time.Now(), Tag: &taken, Link: "https://example.com/sub", Status: "", Info: "",
	}).Error; err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	writeFixture(t, "taken.json", cfMacFixture)

	SyncLocalSubscriptions(ctx)

	entry := entryFor(t, readReport(t), "taken")
	if entry.Status != "skipped" {
		t.Fatalf("expected skipped, got %+v", entry)
	}
	if entry.Error == "" {
		t.Fatalf("skip reason not reported: %+v", entry)
	}

	sub := subByTag(t, ctx, "taken")
	if names := nodeNames(t, ctx, sub.ID); len(names) != 0 {
		t.Fatalf("conflicting subscription must not be hijacked: %v", names)
	}
}

// TestSyncLocalReportsRetainedNodes covers stale nodes that survive because
// they are pinned to a group.
func TestSyncLocalReportsRetainedNodes(t *testing.T) {
	ctx, _ := setup(t)
	writeFixture(t, "ech_nodes.json", cfMacFixture)
	SyncLocalSubscriptions(ctx)

	sub := subByTag(t, ctx, "ech_nodes")
	var group db.Group
	if err := db.DB(ctx).Where("name = ?", "ech_nodes").First(&group).Error; err != nil {
		t.Fatalf("group: %v", err)
	}
	var pinned db.Node
	if err := db.DB(ctx).Where("subscription_id = ? and name = ?", sub.ID, "台湾-联通-1").First(&pinned).Error; err != nil {
		t.Fatalf("node: %v", err)
	}
	if err := db.DB(ctx).Model(&group).Association("Node").Append(&pinned); err != nil {
		t.Fatalf("pin node: %v", err)
	}

	writeFixture(t, "ech_nodes.json", `{"nodes":[{"id":"b","name":"日本-联通-2","wssAddr":"edge.example.workers.dev:443/","token":"tok2"}]}`)
	SyncLocalSubscriptions(ctx)

	entry := entryFor(t, readReport(t), "ech_nodes")
	if entry.Status != "imported" {
		t.Fatalf("unexpected status: %+v", entry)
	}
	if entry.Retained != 1 {
		t.Fatalf("expected 1 retained (pinned) node, got %+v", entry)
	}
	if names := nodeNames(t, ctx, sub.ID); len(names) != 2 {
		t.Fatalf("pinned node should still exist alongside the fresh one: %v", names)
	}
}

// TestSyncLocalPrunesRemovedDropins keeps the "no zombie subscriptions" rule.
func TestSyncLocalPrunesRemovedDropins(t *testing.T) {
	ctx, _ := setup(t)
	writeFixture(t, "ech_nodes.json", cfMacFixture)
	SyncLocalSubscriptions(ctx)
	sub := subByTag(t, ctx, "ech_nodes")

	if err := os.Remove(filepath.Join(LocalNodesDir, "ech_nodes.json")); err != nil {
		t.Fatalf("remove drop-in: %v", err)
	}
	SyncLocalSubscriptions(ctx)

	var count int64
	if err := db.DB(ctx).Model(&db.Subscription{}).Where("id = ?", sub.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("subscription of a removed drop-in was not pruned")
	}
	// The report is regenerated for the current directory content, so the
	// pruned drop-in must not be listed as if it were still imported.
	for _, e := range readReport(t).Entries {
		if e.Tag == "ech_nodes" {
			t.Fatalf("stale report entry for a removed drop-in: %+v", e)
		}
	}
}
