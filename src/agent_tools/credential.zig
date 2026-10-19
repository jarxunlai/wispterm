//! `password_get` tool: hand the agent a secret from the user's password store
//! (<config-dir>/passwords) for privileged work such as sudo or a DB login.
//! Every reveal asks the user first, at any permission level — the secret
//! enters the model context, which is a stronger act than running a command.
const std = @import("std");
const types = @import("../assistant/conversation/types.zig");
const tool_args = @import("args.zig");
const store = @import("../credential/store.zig");

const ToolContext = types.ToolContext;

pub const TOOL_NAME = "password_get";

pub fn get(ctx: *ToolContext, root: std.json.Value) ![]u8 {
    const content = try store.load(ctx.allocator);
    defer ctx.allocator.free(content);
    return getFromContent(ctx, content, tool_args.string(root, "name"));
}

fn getFromContent(ctx: *ToolContext, content: []const u8, name_opt: ?[]const u8) ![]u8 {
    const name = name_opt orelse return listNames(ctx.allocator, content, "Missing name.");
    const secret = store.lookup(content, name) orelse {
        var prefix_buf: [160]u8 = undefined;
        const prefix = std.fmt.bufPrint(&prefix_buf, "No password named \"{s}\" in the store.", .{name}) catch "No such password in the store.";
        return listNames(ctx.allocator, content, prefix);
    };
    var reason_buf: [160]u8 = undefined;
    const reason = std.fmt.bufPrint(&reason_buf, "Reveal the stored password \"{s}\" to the agent", .{name}) catch "Reveal a stored password to the agent";
    if (!ctx.requestApproval(TOOL_NAME, name, reason)) {
        return std.fmt.allocPrint(ctx.allocator, "User declined to reveal the password \"{s}\". Do not retry without asking the user.", .{name});
    }
    return std.fmt.allocPrint(ctx.allocator, "password[{s}]={s}\nUse it directly; never echo it back to the user or write it to a file.", .{ name, secret });
}

/// Names are not secrets: list them so the agent can pick the right one.
fn listNames(allocator: std.mem.Allocator, content: []const u8, prefix: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, prefix);
    var it = store.iterate(content);
    var count: usize = 0;
    while (it.next()) |entry| : (count += 1) {
        try out.appendSlice(allocator, if (count == 0) " Available names: " else ", ");
        try out.appendSlice(allocator, entry.name);
    }
    if (count == 0) try out.appendSlice(allocator, " The store is empty; ask the user to add entries via Command Center > Password Store.");
    return out.toOwnedSlice(allocator);
}

const TestApproval = struct {
    var allow: bool = true;
    var asked_command: [64]u8 = undefined;
    var asked_len: usize = 0;
    fn approve(_: *anyopaque, _: []const u8, command: []const u8, _: []const u8) bool {
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

test "password_get asks even under full permission and shows only the name" {
    var ctx = testCtx(.full);
    TestApproval.allow = true;
    TestApproval.asked_len = 0;
    const out = try getFromContent(&ctx, "root = s3cret\n", "root");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "password[root]=s3cret"));
    try std.testing.expectEqualStrings("root", TestApproval.asked_command[0..TestApproval.asked_len]);
}

test "password_get denial never leaks the secret" {
    var ctx = testCtx(.confirm);
    TestApproval.allow = false;
    const out = try getFromContent(&ctx, "root = s3cret\n", "root");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "s3cret") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "declined") != null);
}

test "password_get unknown or missing name lists names without secrets" {
    var ctx = testCtx(.confirm);
    const out = try getFromContent(&ctx, "root = s3cret\nmysql = m\n", "pg");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "Available names: root, mysql") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "s3cret") == null);
    const empty = try getFromContent(&ctx, "", null);
    defer std.testing.allocator.free(empty);
    try std.testing.expect(std.mem.indexOf(u8, empty, "store is empty") != null);
}
