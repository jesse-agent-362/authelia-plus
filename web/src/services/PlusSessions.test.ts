// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";

import { getPlusSessions, revokeOtherPlusSessions, revokePlusSession } from "@services/PlusSessions";

vi.mock("axios");
vi.mock("@services/Api", () => ({
    PlusSessionsPath: "/api/plus/sessions",
}));

const session = {
    created_at: "2026-10-20T08:00:00Z",
    current: true,
    expires_at: "2026-10-21T08:00:00Z",
    id: "0199f6c4-58a1-7d2e-9b1a-3c4d5e6f7a8b",
    last_active: "2026-10-20T09:30:00Z",
    reported_ip: "192.0.2.10",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
};

beforeEach(() => {
    vi.mocked(axios).mockReset();
});

it("gets the sessions and parses their dates", async () => {
    (axios as any).mockResolvedValue({ data: { data: [session], status: "OK" }, status: 200 });

    const result = await getPlusSessions();

    expect(axios).toHaveBeenCalledWith(expect.objectContaining({ method: "GET", url: "/api/plus/sessions" }));
    expect(result).toEqual({
        secondFactor: false,
        sessions: [
            {
                ...session,
                created_at: new Date("2026-10-20T08:00:00Z"),
                expires_at: new Date("2026-10-21T08:00:00Z"),
                last_active: new Date("2026-10-20T09:30:00Z"),
            },
        ],
    });
});

it("reports that the sessions need a second factor", async () => {
    (axios as any).mockResolvedValue({ data: { data: { second_factor: true }, status: "KO" }, status: 403 });

    await expect(getPlusSessions()).resolves.toEqual({ secondFactor: true });
});

it("throws on a forbidden response without the second factor flag", async () => {
    (axios as any).mockResolvedValue({ data: { message: "Operation failed", status: "KO" }, status: 403 });

    await expect(getPlusSessions()).rejects.toThrow("Failed GET to /api/plus/sessions. Code: 403.");
});

it("throws when getting the sessions fails", async () => {
    (axios as any).mockResolvedValue({ data: { message: "Operation failed", status: "KO" }, status: 500 });

    await expect(getPlusSessions()).rejects.toThrow("Failed GET to /api/plus/sessions. Code: 500.");
});

it("accepts only the statuses the endpoints answer with", async () => {
    (axios as any).mockResolvedValue({ data: { data: [], status: "OK" }, status: 200 });

    await getPlusSessions();

    const { validateStatus } = vi.mocked(axios).mock.calls[0][0] as any;

    expect([200, 403, 404].map(validateStatus)).toEqual([true, true, true]);
    expect([302, 401, 500].map(validateStatus)).toEqual([false, false, false]);
});

it("revokes a session", async () => {
    (axios as any).mockResolvedValue({ data: { status: "OK" }, status: 200 });

    await expect(revokePlusSession(session.id)).resolves.toBe("ok");
    expect(axios).toHaveBeenCalledWith(
        expect.objectContaining({ method: "DELETE", url: `/api/plus/sessions/${session.id}` }),
    );
});

it("encodes the session ID in the revoke path", async () => {
    (axios as any).mockResolvedValue({ data: { status: "OK" }, status: 200 });

    await revokePlusSession("../logout");

    expect(axios).toHaveBeenCalledWith(expect.objectContaining({ url: "/api/plus/sessions/..%2Flogout" }));
});

it("reports a session which has already ended", async () => {
    (axios as any).mockResolvedValue({ data: { message: "Operation failed", status: "KO" }, status: 404 });

    await expect(revokePlusSession(session.id)).resolves.toBe("not_found");
});

it("reports that revoking needs a second factor", async () => {
    (axios as any).mockResolvedValue({ data: { data: { second_factor: true }, status: "KO" }, status: 403 });

    await expect(revokePlusSession(session.id)).resolves.toBe("second_factor");
});

it("reports that revoking needs the session elevated", async () => {
    (axios as any).mockResolvedValue({
        data: { data: { elevation: true, first_factor: false, second_factor: false }, status: "KO" },
        status: 403,
    });

    await expect(revokePlusSession(session.id)).resolves.toBe("elevation");
});

it("throws when revoking fails", async () => {
    (axios as any).mockResolvedValue({ data: { message: "Operation failed", status: "KO" }, status: 500 });

    await expect(revokePlusSession(session.id)).rejects.toThrow(
        `Failed DELETE to /api/plus/sessions/${session.id}. Code: 500.`,
    );
});

it("revokes the other sessions", async () => {
    (axios as any).mockResolvedValue({ data: { data: { count: 2 }, status: "OK" }, status: 200 });

    await expect(revokeOtherPlusSessions()).resolves.toBe("ok");
    expect(axios).toHaveBeenCalledWith(expect.objectContaining({ method: "DELETE", url: "/api/plus/sessions" }));
    expect((vi.mocked(axios).mock.calls[0][0] as any).data).toBeUndefined();
});

it("reports that revoking the other sessions needs a second factor", async () => {
    (axios as any).mockResolvedValue({ data: { data: { second_factor: true }, status: "KO" }, status: 403 });

    await expect(revokeOtherPlusSessions()).resolves.toBe("second_factor");
});

it("reports that revoking the other sessions needs the session elevated", async () => {
    (axios as any).mockResolvedValue({
        data: { data: { elevation: true, first_factor: false, second_factor: false }, status: "KO" },
        status: 403,
    });

    await expect(revokeOtherPlusSessions()).resolves.toBe("elevation");
});

it("throws when revoking the other sessions fails", async () => {
    (axios as any).mockResolvedValue({ data: { message: "Operation failed", status: "KO" }, status: 404 });

    await expect(revokeOtherPlusSessions()).rejects.toThrow("Failed DELETE to /api/plus/sessions. Code: 404.");
});
