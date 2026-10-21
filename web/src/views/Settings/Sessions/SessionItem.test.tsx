// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

import { fireEvent, render, screen } from "@testing-library/react";

import { PlusSession } from "@services/PlusSessions";
import SessionItem from "@views/Settings/Sessions/SessionItem";

vi.mock("react-i18next", () => ({
    useTranslation: () => ({
        t: (key: string, options?: Record<string, string>) =>
            options ? key.replaceAll(/{{(\w+)}}/g, (_, name: string) => options[name]) : key,
    }),
}));

vi.mock("@hooks/RelativeTimeString", () => ({
    useRelativeTime: () => "2 hours ago",
}));

const session: PlusSession = {
    created_at: new Date("2026-10-20T08:00:00Z"),
    current: false,
    expires_at: new Date("2026-10-21T08:00:00Z"),
    id: "abc",
    last_active: new Date("2026-10-20T09:30:00Z"),
    reported_ip: "192.0.2.10",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
};

it("renders the label, the raw user agent and the reported IP", () => {
    render(<SessionItem session={session} handleRevoke={vi.fn()} />);

    expect(screen.getByText("Firefox on Linux")).toBeInTheDocument();
    expect(screen.getByText(session.user_agent)).toBeInTheDocument();
    expect(screen.getByText("Reported IP: 192.0.2.10")).toBeInTheDocument();
    expect(screen.getByText("Last Active 2 hours ago")).toBeInTheDocument();
    expect(screen.getByText("Signed In 2 hours ago")).toBeInTheDocument();
    expect(screen.queryByText("This session")).not.toBeInTheDocument();
});

it("marks the current session", () => {
    render(<SessionItem session={{ ...session, current: true }} handleRevoke={vi.fn()} />);

    expect(screen.getByText("This session")).toBeInTheDocument();
});

it("renders the user agent and IP as text, never as markup", () => {
    const userAgent = '<img src="x" onerror="alert(1)"><b>bold</b>';
    const reportedIP = "<script>alert(2)</script>";

    const { container } = render(
        <SessionItem session={{ ...session, reported_ip: reportedIP, user_agent: userAgent }} handleRevoke={vi.fn()} />,
    );

    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText(userAgent)).toBeInTheDocument();
    expect(screen.getByText(`Reported IP: ${reportedIP}`)).toBeInTheDocument();
});

it("falls back when the user agent isn't recognized or is empty", () => {
    const { rerender } = render(
        <SessionItem session={{ ...session, user_agent: "curl/8.16.0" }} handleRevoke={vi.fn()} />,
    );

    expect(screen.getByText("Unknown device")).toBeInTheDocument();
    expect(screen.getByText("curl/8.16.0")).toBeInTheDocument();

    rerender(<SessionItem session={{ ...session, reported_ip: "", user_agent: "" }} handleRevoke={vi.fn()} />);

    expect(screen.getByText("Unknown device")).toBeInTheDocument();
    expect(screen.getByText("Reported IP: unknown")).toBeInTheDocument();
});

it("calls handleRevoke when revoke is clicked", () => {
    const handleRevoke = vi.fn();
    render(<SessionItem session={session} handleRevoke={handleRevoke} />);

    fireEvent.click(screen.getByText("Revoke"));

    expect(handleRevoke).toHaveBeenCalledOnce();
});

it.each([
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) Version/26.0 Mobile/15E148 Safari/604.1", "iOS"],
    ["Mozilla/5.0 (Linux; Android 16; Pixel 9) Chrome/141.0.0.0 Mobile Safari/537.36", "Android"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0.0.0 Safari/537.36", "Windows"],
    ["curl/8.16.0", "unknown"],
])("shows the platform logo for %s", (userAgent, system) => {
    const { container } = render(
        <SessionItem session={{ ...session, user_agent: userAgent }} handleRevoke={vi.fn()} />,
    );

    const logo = container.querySelector(`#session-${session.id}-logo`);

    expect(logo?.tagName.toLowerCase()).toBe("svg");
    expect(logo).toHaveAttribute("data-system", system);
});
