//! `password_get` tool: hand the agent a secret from the user's encrypted
//! password store (Password Store page) for privileged work such as sudo or a
//! DB login. Every reveal asks the user first, at any permission level — the
//! secret enters the model context, which is a stronger act than running a
//! command — and the secret is decrypted only after that approval. Entries the
//! user marked "agent off" are refused without asking.
const std = @import("std");
const types = @import("../assistant/conversation/types.zig");
const tool_args = @import("args.zig");
const store = @import("../credential/store.zig");

const ToolContext = types.ToolContext;

pub const TOOL_NAME = "password_get";

pub fn get(ctx: *ToolContext, root: std.json.Value) ![]u8 {
    var vault = try store.load(ctx.allocator);
    defer vault.deinit();
    return getFrom(ctx, vault.entries.items, tool_args.string(root, "name"));
}

fn getFrom(ctx: *ToolContext, entries: []const store.Entry, name_opt: ?[]const u8) ![]u8 {
    const name = name_opt orelse return listNames(ctx.allocator, entries, "Missing name.");
    const entry = store.lookup(entries, name) orelse {
        var prefix_buf: [160]u8 = undefined;
        const prefix = std.fmt.bufPrint(&prefix_buf, "No password named \"{s}\" in the store.", .{name}) catch "No such password in the store.";
        return listNames(ctx.allocator, entries, prefix);
    };
    if (!entry.agent) {
        return std.fmt.allocPrint(ctx.allocator, "The user does not let the agent read \"{s}\". Ask the user to enter it themselves.", .{entry.name});
    }
    if (entry.secret.len == 0) {
        return std.fmt.allocPrint(ctx.allocator, "\"{s}\" has no password set. Ask the user to add it in the Password Store page.", .{entry.name});
    }
    var reason_buf: [160]u8 = undefined;
    const reason = std.fmt.bufPrint(&reason_buf, "Reveal the stored password \"{s}\" to the agent", .{entry.name}) catch "Reveal a stored password to the agent";
    if (!ctx.requestApproval(TOOL_NAME, entry.name, reason)) {
        return std.fmt.allocPrint(ctx.allocator, "User declined to reveal the password \"{s}\". Do not retry without asking the user.", .{entry.name});
    }
    const secret = store.reveal(ctx.allocator, entry) catch |err| {
        return std.fmt.allocPrint(ctx.allocator, "Could not decrypt \"{s}\" ({s}). Ask the user to check the Password Store page.", .{ entry.name, @errorName(err) });
    };
    defer store.wipe(ctx.allocator, secret);
    const user_line = if (entry.username.len > 0)
        try std.fmt.allocPrint(ctx.allocator, "username[{s}]={s}\n", .{ entry.name, entry.username })
    else
        try ctx.allocator.dupe(u8, "");
    defer ctx.allocator.free(user_line);
    return std.fmt.allocPrint(ctx.allocator, "{s}password[{s}]={s}\nUse it directly; never echo it back to the user or write it to a file.", .{ user_line, entry.name, secret });
}

/// Names, usernames and notes are not secrets: list the entries the agent may
/// use so it can pick the right one.
fn listNames(allocator: std.mem.Allocator, entries: []const store.Entry, prefix: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, prefix);
    var count: usize = 0;
    for (entries) |entry| {
        if (!entry.agent) continue;
        try out.appendSlice(allocator, if (count == 0) " Available names: " else ", ");
        try out.appendSlice(allocator, entry.name);
        if (entry.username.len > 0 or entry.note.len > 0) {
            try out.appendSlice(allocator, " (");
            if (entry.username.len > 0) try out.print(allocator, "user {s}", .{entry.username});
            if (entry.username.len > 0 and entry.note.len > 0) try out.appendSlice(allocator, "; ");
            try out.appendSlice(allocator, entry.note);
            try out.append(allocator, ')');
        }
        count += 1;
    }
    if (count == 0) try out.appendSlice(allocator, " No entry is available to the agent; ask the user to add one in Command Center > Password Store.");
    return out.toOwnedSlice(allocator);
}

const TestApproval = struct {
    var allow: bool = true;
    var asked: bool = false;
    var asked_command: [64]u8 = undefined;
    var asked_len: usize = 0;
    fn approve(_: *anyopaque, _: []const u8, command: []const u8, _: []const u8) bool {
        asked = true;
        asked_len = @min(command.len, asked_command.len);
        @memcpy(asked_command[0..asked_len], command[0..asked_len]);
        return allow;
    }
    fn cancelled(_: *anyopaque) bool {
        return false;
    }
};

fn testCtx(permission: types.AgentPermission) ToolContext {
    var dummy: u8 = 0;
    TestApproval.asked = false;
    return .{
        .allocator = std.testing.allocator,
        .ctx = &dummy,
        .tool_host = null,
        .tool_snapshot = null,
        .settings = .{ .permission = permission },
        .approve = TestApproval.approve,
        .cancelled = TestApproval.cancelled,
    };
}

fn testVault() !store.Vault {
    var vault = store.Vault.init(std.testing.allocator);
    errdefer vault.deinit();
    try vault.append(.{ .name = "root", .username = "admin", .secret = try vault.seal("s3cret"), .note = "lab sudo" });
    try vault.append(.{ .name = "mysql", .secret = try vault.seal("m") });
    try vault.append(.{ .name = "bank", .secret = try vault.seal("never"), .agent = false });
    return vault;
}

test "password_get asks even under full permission, then decrypts" {
    var vault = try testVault();
    defer vault.deinit();
    var ctx = testCtx(.full);
    TestApproval.allow = true;
    const out = try getFrom(&ctx, vault.entries.items, "ROOT");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "username[root]=admin\npassword[root]=s3cret"));
    try std.testing.expectEqualStrings("root", TestApproval.asked_command[0..TestApproval.asked_len]);
}

test "password_get denial never leaks the secret" {
    var vault = try testVault();
    defer vault.deinit();
    var ctx = testCtx(.confirm);
    TestApproval.allow = false;
    const out = try getFrom(&ctx, vault.entries.items, "root");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "s3cret") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "declined") != null);
}

test "password_get refuses agent-off entries without asking" {
    var vault = try testVault();
    defer vault.deinit();
    var ctx = testCtx(.full);
    TestApproval.allow = true;
    const out = try getFrom(&ctx, vault.entries.items, "bank");
    defer std.testing.allocator.free(out);
    try std.testing.expect(!TestApproval.asked);
    try std.testing.expect(std.mem.indexOf(u8, out, "never") == null);
}

test "password_get unknown or missing name lists agent entries without secrets" {
    var vault = try testVault();
    defer vault.deinit();
    var ctx = testCtx(.confirm);
    const out = try getFrom(&ctx, vault.entries.items, "pg");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "Available names: root (user admin; lab sudo), mysql") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "bank") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "s3cret") == null);
    const empty = try getFrom(&ctx, &.{}, null);
    defer std.testing.allocator.free(empty);
    try std.testing.expect(std.mem.indexOf(u8, empty, "No entry is available") != null);
}
