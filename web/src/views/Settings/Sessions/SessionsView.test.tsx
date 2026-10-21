// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

import { PlusSession, getPlusSessions, revokeOtherPlusSessions, revokePlusSession } from "@services/PlusSessions";
import { getUserSessionElevation } from "@services/UserSessionElevation";
import SessionsView from "@views/Settings/Sessions/SessionsView";

// Stable across renders, as the real hooks are, so the view's effects run once.
const mockTranslate = (key: string, options?: Record<string, number | string>) =>
    options ? key.replaceAll(/{{(\w+)}}/g, (_, name: string) => String(options[name] ?? `{{${name}}}`)) : key;

vi.mock("react-i18next", () => ({
    useTranslation: () => ({ t: mockTranslate }),
}));

const mockCreateError = vi.fn();
const mockCreateInfo = vi.fn();
const mockCreateSuccess = vi.fn();

vi.mock("@contexts/NotificationsContext", () => ({
    useNotifications: () => ({
        createErrorNotification: mockCreateError,
        createInfoNotification: mockCreateInfo,
        createSuccessNotification: mockCreateSuccess,
    }),
}));

const mockSignOut = vi.fn();

vi.mock("@hooks/SignOut", () => ({
    useSignOut: () => mockSignOut,
}));

const mockUserInfo = { display_name: "John", has_totp: true };
const mockFetchUserInfo = vi.fn();

vi.mock("@hooks/UserInfo", () => ({
    useUserInfoGET: () => [mockUserInfo, mockFetchUserInfo, false, undefined],
}));

vi.mock("@hooks/RelativeTimeString", () => ({
    useRelativeTime: () => "2 hours ago",
}));

vi.mock("@services/PlusSessions", () => ({
    getPlusSessions: vi.fn(),
    revokeOtherPlusSessions: vi.fn(),
    revokePlusSession: vi.fn(),
}));

vi.mock("@services/UserSessionElevation", () => ({
    getUserSessionElevation: vi.fn(),
}));

vi.mock("@views/Settings/Common/SecondFactorDialog", () => ({
    default: (props: any) => (
        <div
            data-testid="second-factor-dialog"
            data-opening={String(props.opening)}
            data-elevation={JSON.stringify(props.elevation ?? null)}
        >
            <button data-testid="sf-closed-ok-changed" onClick={() => props.handleClosed(true, true)} />
            <button data-testid="sf-closed-cancel" onClick={() => props.handleClosed(false, false)} />
        </div>
    ),
}));

vi.mock("@views/Settings/Common/IdentityVerificationDialog", () => ({
    default: (props: any) => (
        <div
            data-testid="identity-verification-dialog"
            data-opening={String(props.opening)}
            data-elevation={JSON.stringify(props.elevation ?? null)}
        >
            <button data-testid="iv-closed-ok" onClick={() => props.handleClosed(true)} />
            <button data-testid="iv-closed-cancel" onClick={() => props.handleClosed(false)} />
        </div>
    ),
}));

const current: PlusSession = {
    created_at: new Date("2026-10-20T08:00:00Z"),
    current: true,
    expires_at: new Date("2026-10-21T08:00:00Z"),
    id: "current-id",
    last_active: new Date("2026-10-20T09:30:00Z"),
    reported_ip: "192.0.2.10",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
};

const other: PlusSession = {
    ...current,
    current: false,
    id: "other-id",
    reported_ip: "198.51.100.7",
    user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) Version/26.0 Mobile/15E148 Safari/604.1",
};

const elevation = {
    can_skip_second_factor: true,
    elevated: false,
    expires: 0,
    factor_knowledge: true,
    require_second_factor: false,
    skip_second_factor: false,
};

beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    mockCreateError.mockReset();
    mockCreateInfo.mockReset();
    mockCreateSuccess.mockReset();
    mockSignOut.mockReset();
    vi.mocked(getPlusSessions).mockReset();
    vi.mocked(revokePlusSession).mockReset();
    vi.mocked(revokeOtherPlusSessions).mockReset();
    vi.mocked(getUserSessionElevation).mockReset();
});

const renderView = async () => {
    await act(async () => {
        render(<SessionsView />);
    });
};

const confirmRevoke = async (id: string) => {
    await act(async () => {
        fireEvent.click(document.getElementById(`session-${id}-revoke`)!);
    });
    await act(async () => {
        fireEvent.click(document.getElementById("dialog-revoke")!);
    });
};

const confirmRevokeOthers = async () => {
    await act(async () => {
        fireEvent.click(document.getElementById("sessions-revoke-others")!);
    });
    await act(async () => {
        fireEvent.click(document.getElementById("dialog-revoke-others")!);
    });
};

const third: PlusSession = {
    ...current,
    current: false,
    id: "third-id",
    reported_ip: "203.0.113.25",
    user_agent: "Mozilla/5.0 (Linux; Android 16; Pixel 9) Chrome/141.0.0.0 Mobile Safari/537.36",
};

it("lists the sessions", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });

    await renderView();

    expect(screen.getByText("Sessions")).toBeInTheDocument();
    expect(screen.getByText("Firefox on Linux")).toBeInTheDocument();
    expect(screen.getByText("Safari on iOS")).toBeInTheDocument();
    expect(screen.getByText("This session")).toBeInTheDocument();
    expect(document.getElementById("sessions-panel")).toHaveAttribute("data-loading", "false");
});

it("shows a message when there are no sessions", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [] });

    await renderView();

    expect(screen.getByText("There are no active sessions")).toBeInTheDocument();
});

it("notifies when the sessions can't be retrieved", async () => {
    vi.mocked(getPlusSessions).mockRejectedValue(new Error("failed"));

    await renderView();

    expect(mockCreateError).toHaveBeenCalledWith("There was an issue retrieving the sessions");
});

it("revokes another session after confirming and refreshes the list", async () => {
    vi.mocked(getPlusSessions)
        .mockResolvedValueOnce({ secondFactor: false, sessions: [current, other] })
        .mockResolvedValueOnce({ secondFactor: false, sessions: [current] });
    vi.mocked(revokePlusSession).mockResolvedValue("ok");

    await renderView();
    await confirmRevoke(other.id);

    expect(revokePlusSession).toHaveBeenCalledWith(other.id);
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
    expect(mockSignOut).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByText("Safari on iOS")).not.toBeInTheDocument());
});

it("does nothing when the revoke is cancelled", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });

    await renderView();

    await act(async () => {
        fireEvent.click(document.getElementById(`session-${other.id}-revoke`)!);
    });
    await act(async () => {
        fireEvent.click(screen.getByText("Cancel"));
    });

    expect(revokePlusSession).not.toHaveBeenCalled();
});

it("signs the user out after revoking the current session", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValue("ok");

    await renderView();

    await act(async () => {
        fireEvent.click(document.getElementById(`session-${current.id}-revoke`)!);
    });

    expect(
        screen.getByText("This is the session you are using now, revoking it will sign you out of this device"),
    ).toBeInTheDocument();

    await act(async () => {
        fireEvent.click(document.getElementById("dialog-revoke")!);
    });

    expect(revokePlusSession).toHaveBeenCalledWith(current.id);
    expect(mockSignOut).toHaveBeenCalledWith(false);
    expect(getPlusSessions).toHaveBeenCalledOnce();
});

it("tells the user a session already ended and refreshes the list", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValue("not_found");

    await renderView();
    await confirmRevoke(other.id);

    expect(mockCreateInfo).toHaveBeenCalledWith("This session has already ended");
    expect(getPlusSessions).toHaveBeenCalledTimes(2);
});

it("notifies when revoking fails", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockRejectedValue(new Error("failed"));

    await renderView();
    await confirmRevoke(other.id);

    expect(mockCreateError).toHaveBeenCalledWith("There was a problem revoking the session");
});

it("asks for the second factor before listing, holding the dialog to a second factor", async () => {
    vi.mocked(getPlusSessions)
        .mockResolvedValueOnce({ secondFactor: true })
        .mockResolvedValueOnce({ secondFactor: false, sessions: [current] });
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();

    expect(screen.getByText("You must authenticate with your second factor to view your sessions")).toBeInTheDocument();

    await act(async () => {
        fireEvent.click(screen.getByText("Authenticate"));
    });

    const dialog = screen.getByTestId("second-factor-dialog");
    expect(dialog).toHaveAttribute("data-opening", "true");
    expect(JSON.parse(dialog.getAttribute("data-elevation")!)).toEqual({
        ...elevation,
        can_skip_second_factor: false,
        require_second_factor: true,
        skip_second_factor: false,
    });

    await act(async () => {
        fireEvent.click(screen.getByTestId("sf-closed-ok-changed"));
    });

    expect(getPlusSessions).toHaveBeenCalledTimes(2);
    expect(screen.getByText("Firefox on Linux")).toBeInTheDocument();
});

it("retries the revoke once the second factor succeeds", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValueOnce("second_factor").mockResolvedValueOnce("ok");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevoke(other.id);

    expect(screen.getByTestId("second-factor-dialog")).toHaveAttribute("data-opening", "true");

    await act(async () => {
        fireEvent.click(screen.getByTestId("sf-closed-ok-changed"));
    });

    expect(revokePlusSession).toHaveBeenCalledTimes(2);
    expect(revokePlusSession).toHaveBeenLastCalledWith(other.id);
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
});

it("drops the revoke when the second factor is cancelled", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValue("second_factor");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevoke(other.id);

    await act(async () => {
        fireEvent.click(screen.getByTestId("sf-closed-cancel"));
    });

    expect(revokePlusSession).toHaveBeenCalledOnce();
    expect(screen.getByTestId("second-factor-dialog")).toHaveAttribute("data-elevation", "null");
});

it("notifies when the elevation status can't be retrieved", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: true });
    vi.mocked(getUserSessionElevation).mockRejectedValue(new Error("failed"));

    await renderView();

    await act(async () => {
        fireEvent.click(screen.getByText("Authenticate"));
    });

    expect(mockCreateError).toHaveBeenCalledWith("Failed to get session elevation status");
});

it("allows one revoke at a time", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockReturnValue(new Promise(() => {}));

    await renderView();
    await confirmRevoke(other.id);

    expect(document.getElementById(`session-${current.id}-revoke`)).toBeDisabled();
    expect(document.getElementById(`session-${other.id}-revoke`)).toBeDisabled();
    expect(revokePlusSession).toHaveBeenCalledOnce();
});

it("drops the waiting revoke when the elevation status can't be retrieved", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValue("second_factor");
    vi.mocked(getUserSessionElevation).mockRejectedValue(new Error("failed"));

    await renderView();
    await confirmRevoke(other.id);

    expect(mockCreateError).toHaveBeenCalledWith("Failed to get session elevation status");
    expect(document.getElementById(`session-${other.id}-revoke`)).not.toBeDisabled();

    // A later second factor success must not replay the dropped revoke.
    await act(async () => {
        fireEvent.click(screen.getByTestId("sf-closed-ok-changed"));
    });

    expect(revokePlusSession).toHaveBeenCalledOnce();
});

it("hides sign out all other sessions when the current session is the only one", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current] });

    await renderView();

    expect(document.getElementById("sessions-revoke-others")).toBeNull();
});

it("signs out the other sessions after confirming with their count and refreshes the list", async () => {
    vi.mocked(getPlusSessions)
        .mockResolvedValueOnce({ secondFactor: false, sessions: [current, other, third] })
        .mockResolvedValueOnce({ secondFactor: false, sessions: [current] });
    vi.mocked(revokeOtherPlusSessions).mockResolvedValue("ok");

    await renderView();

    await act(async () => {
        fireEvent.click(document.getElementById("sessions-revoke-others")!);
    });

    expect(document.getElementById("dialog-revoke-others-count")).toHaveTextContent("Other sessions: 2");

    await act(async () => {
        fireEvent.click(document.getElementById("dialog-revoke-others")!);
    });

    expect(revokeOtherPlusSessions).toHaveBeenCalledOnce();
    expect(revokePlusSession).not.toHaveBeenCalled();
    expect(mockSignOut).not.toHaveBeenCalled();
    expect(mockCreateSuccess).toHaveBeenCalledWith("Successfully signed out the other sessions");
    await waitFor(() => expect(document.getElementById("sessions-revoke-others")).toBeNull());
    expect(screen.getByText("Firefox on Linux")).toBeInTheDocument();
});

it("does nothing when signing out the other sessions is cancelled", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });

    await renderView();

    await act(async () => {
        fireEvent.click(document.getElementById("sessions-revoke-others")!);
    });
    await act(async () => {
        fireEvent.click(document.getElementById("dialog-cancel")!);
    });

    expect(revokeOtherPlusSessions).not.toHaveBeenCalled();
});

it("retries signing out the other sessions once the second factor succeeds", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokeOtherPlusSessions).mockResolvedValueOnce("second_factor").mockResolvedValueOnce("ok");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevokeOthers();

    expect(screen.getByTestId("second-factor-dialog")).toHaveAttribute("data-opening", "true");
    expect(document.getElementById("sessions-revoke-others")).toBeDisabled();

    await act(async () => {
        fireEvent.click(screen.getByTestId("sf-closed-ok-changed"));
    });

    expect(revokeOtherPlusSessions).toHaveBeenCalledTimes(2);
    expect(revokePlusSession).not.toHaveBeenCalled();
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
});

it("notifies when signing out the other sessions fails", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokeOtherPlusSessions).mockRejectedValue(new Error("failed"));

    await renderView();
    await confirmRevokeOthers();

    expect(mockCreateError).toHaveBeenCalledWith("There was a problem signing out the other sessions");
    expect(document.getElementById("sessions-revoke-others")).not.toBeDisabled();
});

it("disables sign out all other sessions while a single revoke runs", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockReturnValue(new Promise(() => {}));

    await renderView();
    await confirmRevoke(other.id);

    expect(document.getElementById("sessions-revoke-others")).toBeDisabled();
});

it("retries the revoke once the session is elevated with a one-time code", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValueOnce("elevation").mockResolvedValueOnce("ok");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevoke(other.id);

    const dialog = screen.getByTestId("identity-verification-dialog");
    expect(dialog).toHaveAttribute("data-opening", "true");
    expect(dialog).toHaveAttribute("data-elevation", JSON.stringify(elevation));
    expect(screen.getByTestId("second-factor-dialog")).toHaveAttribute("data-opening", "false");
    expect(document.getElementById(`session-${current.id}-revoke`)).toBeDisabled();

    await act(async () => {
        fireEvent.click(screen.getByTestId("iv-closed-ok"));
    });

    expect(revokePlusSession).toHaveBeenCalledTimes(2);
    expect(revokePlusSession).toHaveBeenLastCalledWith(other.id);
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-opening", "false");
});

it("drops the revoke when the one-time code is cancelled", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValue("elevation");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevoke(other.id);

    await act(async () => {
        fireEvent.click(screen.getByTestId("iv-closed-cancel"));
    });

    expect(revokePlusSession).toHaveBeenCalledOnce();
    expect(mockCreateSuccess).not.toHaveBeenCalled();
    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-opening", "false");
    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-elevation", "null");
    expect(document.getElementById(`session-${other.id}-revoke`)).not.toBeDisabled();
});

it("asks for the second factor and then the one-time code when the server wants both", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession)
        .mockResolvedValueOnce("second_factor")
        .mockResolvedValueOnce("elevation")
        .mockResolvedValueOnce("ok");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevoke(other.id);

    expect(screen.getByTestId("second-factor-dialog")).toHaveAttribute("data-opening", "true");
    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-opening", "false");

    await act(async () => {
        fireEvent.click(screen.getByTestId("sf-closed-ok-changed"));
    });

    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-opening", "true");

    await act(async () => {
        fireEvent.click(screen.getByTestId("iv-closed-ok"));
    });

    expect(revokePlusSession).toHaveBeenCalledTimes(3);
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
});

it("retries signing out the other sessions once the session is elevated with a one-time code", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other, third] });
    vi.mocked(revokeOtherPlusSessions).mockResolvedValueOnce("elevation").mockResolvedValueOnce("ok");
    vi.mocked(getUserSessionElevation).mockResolvedValue(elevation);

    await renderView();
    await confirmRevokeOthers();

    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-opening", "true");
    expect(document.getElementById("sessions-revoke-others")).toBeDisabled();

    await act(async () => {
        fireEvent.click(screen.getByTestId("iv-closed-ok"));
    });

    expect(revokeOtherPlusSessions).toHaveBeenCalledTimes(2);
    expect(revokePlusSession).not.toHaveBeenCalled();
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
});

it("drops the revoke waiting on a one-time code when the elevation status can't be retrieved", async () => {
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(revokePlusSession).mockResolvedValue("elevation");
    vi.mocked(getUserSessionElevation).mockRejectedValue(new Error("failed"));

    await renderView();
    await confirmRevoke(other.id);

    expect(mockCreateError).toHaveBeenCalledWith("Failed to get session elevation status");
    expect(screen.getByTestId("identity-verification-dialog")).toHaveAttribute("data-opening", "false");
    expect(document.getElementById(`session-${other.id}-revoke`)).not.toBeDisabled();
});
