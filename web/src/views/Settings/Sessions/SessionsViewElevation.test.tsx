// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

import { PlusSession, getPlusSessions, revokePlusSession } from "@services/PlusSessions";
import {
    generateUserSessionElevation,
    getUserSessionElevation,
    verifyUserSessionElevation,
} from "@services/UserSessionElevation";
import SessionsView from "@views/Settings/Sessions/SessionsView";

// The view with the real one-time code dialog, which only shows while its opening prop stays set.

const mockTranslate = (key: string) => key;

vi.mock("react-i18next", () => ({
    useTranslation: () => ({ t: mockTranslate }),
}));

const mockCreateError = vi.fn();
const mockCreateSuccess = vi.fn();

vi.mock("@contexts/NotificationsContext", () => ({
    useNotifications: () => ({
        createErrorNotification: mockCreateError,
        createInfoNotification: vi.fn(),
        createSuccessNotification: mockCreateSuccess,
    }),
}));

vi.mock("@hooks/SignOut", () => ({
    useSignOut: () => vi.fn(),
}));

const mockFetchUserInfo = vi.fn();

vi.mock("@hooks/UserInfo", () => ({
    useUserInfoGET: () => [{ display_name: "John" }, mockFetchUserInfo, false, undefined],
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
    deleteUserSessionElevation: vi.fn(),
    generateUserSessionElevation: vi.fn(),
    getUserSessionElevation: vi.fn(),
    verifyUserSessionElevation: vi.fn(),
}));

vi.mock("@components/OneTimeCodeTextField", () => ({
    default: (props: any) => <input data-testid="one-time-code" value={props.value} onChange={props.onChange} />,
}));

vi.mock("@views/Settings/Common/SecondFactorDialog", () => ({
    default: () => null,
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

const other: PlusSession = { ...current, current: false, id: "other-id", reported_ip: "198.51.100.7" };

beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(getPlusSessions).mockResolvedValue({ secondFactor: false, sessions: [current, other] });
    vi.mocked(getUserSessionElevation).mockResolvedValue({
        can_skip_second_factor: false,
        elevated: false,
        expires: 0,
        factor_knowledge: true,
        require_second_factor: false,
        skip_second_factor: false,
    });
    vi.mocked(generateUserSessionElevation).mockResolvedValue({ delete_id: "delete-id" });
    vi.mocked(verifyUserSessionElevation).mockResolvedValue(true);
});

it("keeps the one-time code dialog open until the code is verified, then retries the revoke", async () => {
    vi.mocked(revokePlusSession).mockResolvedValueOnce("elevation").mockResolvedValueOnce("ok");

    await act(async () => {
        render(<SessionsView />);
    });
    await act(async () => {
        fireEvent.click(document.getElementById(`session-${other.id}-revoke`)!);
    });
    await act(async () => {
        fireEvent.click(document.getElementById("dialog-revoke")!);
    });

    await waitFor(() => expect(screen.getByText("Identity Verification")).toBeInTheDocument());
    expect(generateUserSessionElevation).toHaveBeenCalledOnce();

    fireEvent.change(screen.getByTestId("one-time-code"), { target: { value: "ABCDEFGH" } });

    await act(async () => {
        fireEvent.click(document.getElementById("dialog-verify")!);
    });

    expect(verifyUserSessionElevation).toHaveBeenCalledWith("ABCDEFGH");
    await waitFor(() => expect(revokePlusSession).toHaveBeenCalledTimes(2));
    expect(revokePlusSession).toHaveBeenLastCalledWith(other.id);
    expect(mockCreateSuccess).toHaveBeenCalledOnce();
});
