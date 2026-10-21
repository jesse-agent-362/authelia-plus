// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// authelia-plus: the user's own sessions, listed and revoked from the settings.

import axios from "axios";

import { OKResponse, PlusSessionsPath, Response } from "@services/Api";

export interface PlusSession {
    id: string;
    created_at: Date;
    last_active: Date;
    expires_at: Date;
    reported_ip: string;
    user_agent: string;
    current: boolean;
}

interface PlusSessionJSON {
    id: string;
    created_at: string;
    last_active: string;
    expires_at: string;
    reported_ip: string;
    user_agent: string;
    current: boolean;
}

// The 403 the endpoints answer when the user has a second factor enrolled but only did the first, or when revoking
// another session needs the session elevated with a one-time code first.
interface PlusSessionsForbiddenResponse {
    status: "KO";
    data?: { elevation?: boolean; second_factor?: boolean };
}

export type PlusSessionsResult = { secondFactor: true } | { sessions: PlusSession[]; secondFactor: false };

export type PlusSessionRevokeResult = "elevation" | "not_found" | "ok" | "second_factor";

function validateStatusPlusSessions(status: number) {
    return (status >= 200 && status < 300) || status === 403 || status === 404;
}

function isSecondFactorRequired(status: number, data: OKResponse | PlusSessionsForbiddenResponse) {
    return status === 403 && data.status === "KO" && data.data?.second_factor === true;
}

function isElevationRequired(status: number, data: OKResponse | PlusSessionsForbiddenResponse) {
    return status === 403 && data.status === "KO" && data.data?.elevation === true;
}

function toPlusSession(session: PlusSessionJSON): PlusSession {
    return {
        ...session,
        created_at: new Date(session.created_at),
        expires_at: new Date(session.expires_at),
        last_active: new Date(session.last_active),
    };
}

export async function getPlusSessions(): Promise<PlusSessionsResult> {
    const res = await axios<PlusSessionsForbiddenResponse | Response<PlusSessionJSON[]>>({
        method: "GET",
        url: PlusSessionsPath,
        validateStatus: validateStatusPlusSessions,
    });

    if (isSecondFactorRequired(res.status, res.data)) {
        return { secondFactor: true };
    }

    if (res.status !== 200 || res.data.status !== "OK") {
        throw new Error(`Failed GET to ${PlusSessionsPath}. Code: ${res.status}.`);
    }

    return { secondFactor: false, sessions: res.data.data.map(toPlusSession) };
}

export async function revokePlusSession(id: string): Promise<PlusSessionRevokeResult> {
    const url = `${PlusSessionsPath}/${encodeURIComponent(id)}`;

    const res = await axios<OKResponse | PlusSessionsForbiddenResponse>({
        method: "DELETE",
        url: url,
        validateStatus: validateStatusPlusSessions,
    });

    if (isSecondFactorRequired(res.status, res.data)) {
        return "second_factor";
    }

    if (isElevationRequired(res.status, res.data)) {
        return "elevation";
    }

    if (res.status === 404) {
        return "not_found";
    }

    if (res.status !== 200 || res.data.status !== "OK") {
        throw new Error(`Failed DELETE to ${url}. Code: ${res.status}.`);
    }

    return "ok";
}

// Revokes every session of the user's except the current one.
export async function revokeOtherPlusSessions(): Promise<Exclude<PlusSessionRevokeResult, "not_found">> {
    const res = await axios<OKResponse | PlusSessionsForbiddenResponse>({
        method: "DELETE",
        url: PlusSessionsPath,
        validateStatus: validateStatusPlusSessions,
    });

    if (isSecondFactorRequired(res.status, res.data)) {
        return "second_factor";
    }

    if (isElevationRequired(res.status, res.data)) {
        return "elevation";
    }

    if (res.status !== 200 || res.data.status !== "OK") {
        throw new Error(`Failed DELETE to ${PlusSessionsPath}. Code: ${res.status}.`);
    }

    return "ok";
}
