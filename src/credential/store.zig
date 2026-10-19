//! Password store shared by the user (Command Center copy rows) and the AI
//! agent (`password_get` tool). One plain-text file, `<config-dir>/passwords`,
//! one `name = secret` per line, `#` comments. The user edits it in their
//! editor; the palette and the agent only ever read it.
//!
//! ponytail: plain text with 0600 perms, like ssh_hosts/ai_profiles. Upgrade
//! path is the OS keychain (Keychain / Credential Manager / Secret Service)
//! behind the same `lookup` API if the user wants secrets off disk.
const std = @import("std");
const builtin = @import("builtin");
const platform_dirs = @import("../platform/dirs.zig");
const platform_atomic_file = @import("../platform/atomic_file.zig");
const platform_editor = @import("../platform/editor.zig");

pub const MAX_BYTES: usize = 256 * 1024;
pub const BASENAME = "passwords";

pub const template =
    "# WispTerm password store. One entry per line:  name = secret\n" ++
    "# - Command Center (Ctrl+Shift+P): type a name, press Enter to copy its secret.\n" ++
    "# - AI agent: the password_get tool reads a secret here after you approve.\n" ++
    "# Lines starting with # are ignored. Keep this file private.\n" ++
    "#\n" ++
    "# root = s3cret\n" ++
    "# mysql = another-secret\n";

pub const Entry = struct {
    name: []const u8,
    secret: []const u8,
};

pub const Iterator = struct {
    lines: std.mem.SplitIterator(u8, .scalar),

    pub fn next(self: *Iterator) ?Entry {
        while (self.lines.next()) |line| {
            if (parseLine(line)) |entry| return entry;
        }
        return null;
    }
};

pub fn iterate(content: []const u8) Iterator {
    return .{ .lines = std.mem.splitScalar(u8, content, '\n') };
}

/// `name = secret` -> Entry; comments, blanks, and lines without a name are skipped.
/// The secret keeps everything after the first `=` (trimmed), so `=` inside it is fine.
pub fn parseLine(line_raw: []const u8) ?Entry {
    const line = std.mem.trim(u8, line_raw, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;
    const eq = std.mem.indexOfScalar(u8, line, '=') orelse return null;
    const name = std.mem.trim(u8, line[0..eq], " \t");
    const secret = std.mem.trim(u8, line[eq + 1 ..], " \t");
    if (name.len == 0 or secret.len == 0) return null;
    return .{ .name = name, .secret = secret };
}

pub fn lookup(content: []const u8, name: []const u8) ?[]const u8 {
    var it = iterate(content);
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.secret;
    }
    return null;
}

/// Entries as an indexable slice (slices into `content`). Caller frees the slice.
pub fn collect(allocator: std.mem.Allocator, content: []const u8) ![]Entry {
    var list: std.ArrayListUnmanaged(Entry) = .empty;
    errdefer list.deinit(allocator);
    var it = iterate(content);
    while (it.next()) |entry| try list.append(allocator, entry);
    return list.toOwnedSlice(allocator);
}

pub fn path(allocator: std.mem.Allocator) ![]const u8 {
    return platform_dirs.pathInConfigDir(allocator, BASENAME);
}

/// Read the store file. Missing file -> empty content. Caller frees.
pub fn load(allocator: std.mem.Allocator) ![]u8 {
    const p = try path(allocator);
    defer allocator.free(p);
    return std.fs.cwd().readFileAlloc(allocator, p, MAX_BYTES) catch |err| switch (err) {
        error.FileNotFound => try allocator.alloc(u8, 0),
        else => err,
    };
}

/// Create the file from the template when missing (owner-only on POSIX), then
/// open it in the user's text editor. Returns false when the editor could not start.
pub fn openInEditor(allocator: std.mem.Allocator) bool {
    const p = path(allocator) catch return false;
    defer allocator.free(p);
    if (std.fs.path.dirname(p)) |dir| std.fs.cwd().makePath(dir) catch return false;
    std.fs.cwd().access(p, .{}) catch |err| switch (err) {
        error.FileNotFound => platform_atomic_file.writeFileReplaceSafeWithOptions(p, template, .{
            .mode = if (builtin.os.tag == .windows) std.fs.File.default_mode else 0o600,
        }) catch return false,
        else => return false,
    };
    return platform_editor.openTextFile(allocator, .{ .path = p });
}

// ---------------------------------------------------------------------------
// Palette cache: feature-owned UI state (threadlocal = per window thread, like
// recipe/ui_state.zig) so renderer/overlays.zig gains no new g_* field.
// ---------------------------------------------------------------------------

threadlocal var g_palette_content: []u8 = &.{};
threadlocal var g_palette_entries: []Entry = &.{};
threadlocal var g_palette_loaded: bool = false;

pub fn paletteItems() []const Entry {
    return g_palette_entries;
}

pub fn ensurePaletteList(allocator: std.mem.Allocator) void {
    if (g_palette_loaded) return;
    g_palette_loaded = true;
    g_palette_content = load(allocator) catch return;
    g_palette_entries = collect(allocator, g_palette_content) catch &.{};
}

pub fn invalidatePaletteList(allocator: std.mem.Allocator) void {
    if (g_palette_entries.len > 0) allocator.free(g_palette_entries);
    if (g_palette_content.len > 0) allocator.free(g_palette_content);
    g_palette_entries = &.{};
    g_palette_content = &.{};
    g_palette_loaded = false;
}

test "password store parses name = secret lines and skips comments" {
    const content = "# header\n\nroot = s3cret\nmysql=pa=ss word \n  # mysql = commented\nbroken line\n= nosecret\nempty =\n";
    const entries = try collect(std.testing.allocator, content);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("root", entries[0].name);
    try std.testing.expectEqualStrings("s3cret", entries[0].secret);
    try std.testing.expectEqualStrings("mysql", entries[1].name);
    try std.testing.expectEqualStrings("pa=ss word", entries[1].secret);
}

test "password store lookup is case-insensitive on the name and null when missing" {
    const content = "root = a\nMySQL = b\n";
    try std.testing.expectEqualStrings("b", lookup(content, "mysql").?);
    try std.testing.expectEqualStrings("a", lookup(content, "ROOT").?);
    try std.testing.expect(lookup(content, "postgres") == null);
    try std.testing.expect(lookup("", "root") == null);
}

test "password store template has no live entries" {
    const entries = try collect(std.testing.allocator, template);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}
