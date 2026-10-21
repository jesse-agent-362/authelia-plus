// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { fireEvent, render, screen } from "@testing-library/react";

import { PlusSession } from "@services/PlusSessions";
import SessionRevokeDialog from "@views/Settings/Sessions/SessionRevokeDialog";

vi.mock("react-i18next", () => ({
    useTranslation: () => ({ t: (key: string) => key }),
}));

const session: PlusSession = {
    created_at: new Date("2026-10-20T08:00:00Z"),
    current: false,
    expires_at: new Date("2026-10-21T08:00:00Z"),
    id: "abc",
    last_active: new Date("2026-10-20T09:30:00Z"),
    reported_ip: "192.0.2.10",
    user_agent: "Firefox/144.0",
};

it("is closed without a session", () => {
    render(<SessionRevokeDialog onConfirm={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.queryByText("Revoke Session")).not.toBeInTheDocument();
});

it("asks to confirm revoking another session", () => {
    const onConfirm = vi.fn();
    render(<SessionRevokeDialog session={session} onConfirm={onConfirm} onCancel={vi.fn()} />);

    expect(screen.getByText("Reported IP: 192.0.2.10")).toBeInTheDocument();
    expect(screen.getByText("Firefox")).toBeInTheDocument();

    expect(
        screen.getByText("Are you sure you want to revoke this session, the device will be signed out"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByText("Revoke"));

    expect(onConfirm).toHaveBeenCalledOnce();
});

it("renders the session's user agent and IP as text in the dialog", () => {
    const userAgent = '<img src="x" onerror="alert(1)">';
    render(
        <SessionRevokeDialog
            session={{ ...session, reported_ip: "<b>ip</b>", user_agent: userAgent }}
            onConfirm={vi.fn()}
            onCancel={vi.fn()}
        />,
    );

    const details = document.getElementById("dialog-revoke-session")!;
    expect(details.querySelector("img")).toBeNull();
    expect(details.querySelector("b")).toBeNull();
    expect(screen.getByText("Unknown device")).toBeInTheDocument();
    expect(screen.getByText("Reported IP: <b>ip</b>")).toBeInTheDocument();
});

it("warns that revoking the current session signs the user out", () => {
    const onConfirm = vi.fn();
    render(<SessionRevokeDialog session={{ ...session, current: true }} onConfirm={onConfirm} onCancel={vi.fn()} />);

    expect(
        screen.getByText("This is the session you are using now, revoking it will sign you out of this device"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByText("Revoke and Sign Out"));

    expect(onConfirm).toHaveBeenCalledOnce();
});

it("calls onCancel when cancel is clicked", () => {
    const onCancel = vi.fn();
    render(<SessionRevokeDialog session={session} onConfirm={vi.fn()} onCancel={onCancel} />);

    fireEvent.click(screen.getByText("Cancel"));

    expect(onCancel).toHaveBeenCalledOnce();
});
