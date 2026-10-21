// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

import { fireEvent, render, screen } from "@testing-library/react";

import SessionRevokeOthersDialog from "@views/Settings/Sessions/SessionRevokeOthersDialog";

vi.mock("react-i18next", () => ({
    useTranslation: () => ({
        t: (key: string, options?: Record<string, number>) =>
            options ? key.replaceAll(/{{(\w+)}}/g, (_, name: string) => String(options[name])) : key,
    }),
}));

it("is closed without a count", () => {
    render(<SessionRevokeOthersDialog onConfirm={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.queryByText("Sign out all other sessions")).not.toBeInTheDocument();
});

it("asks to confirm with the number of other sessions", () => {
    const onConfirm = vi.fn();
    render(<SessionRevokeOthersDialog count={3} onConfirm={onConfirm} onCancel={vi.fn()} />);

    expect(screen.getByText("Sign out all other sessions")).toBeInTheDocument();
    expect(screen.getByText("Other sessions: 3")).toBeInTheDocument();
    expect(
        screen.getByText(
            "Are you sure you want to sign out all other sessions, every other device will be signed out and this one stays signed in",
        ),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByText("Sign Out Others"));

    expect(onConfirm).toHaveBeenCalledOnce();
});

it("calls onCancel when cancel is clicked", () => {
    const onCancel = vi.fn();
    render(<SessionRevokeOthersDialog count={1} onConfirm={vi.fn()} onCancel={onCancel} />);

    fireEvent.click(screen.getByText("Cancel"));

    expect(onCancel).toHaveBeenCalledOnce();
});
