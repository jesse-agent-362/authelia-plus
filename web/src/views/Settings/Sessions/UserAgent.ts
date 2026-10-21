// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

// authelia-plus: a short "browser on system" label for a session's reported user agent. The label only ever holds
// names from these lists, never text from the user agent itself.

// Ordered so a more specific product wins: Edge and Opera also send Chrome, and Chrome also sends Safari.
const browsers: [RegExp, string][] = [
    [/\bEdg(?:e|A|iOS)?\//, "Edge"],
    [/\bOPR\/|\bOpera\b/, "Opera"],
    [/\bFirefox\/|\bFxiOS\//, "Firefox"],
    [/\bChrome\/|\bCriOS\//, "Chrome"],
    [/\bSafari\//, "Safari"],
];

// Ordered so iPadOS (which sends Mac OS X) and Android and ChromeOS (which send Linux) are found first.
const systems: [RegExp, string][] = [
    [/\biPhone\b|\biPad\b|\biPod\b/, "iOS"],
    [/\bAndroid\b/, "Android"],
    [/\bCrOS\b/, "ChromeOS"],
    [/\bWindows\b/, "Windows"],
    [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
    [/\bLinux\b/, "Linux"],
];

export interface UserAgentLabel {
    browser?: string;
    system?: string;
}

function match(userAgent: string, candidates: [RegExp, string][]) {
    return candidates.find(([pattern]) => pattern.test(userAgent))?.[1];
}

export function getUserAgentLabel(userAgent: string): UserAgentLabel {
    return { browser: match(userAgent, browsers), system: match(userAgent, systems) };
}

// The label shown for a session: "browser on system", whichever of the two is known, or "Unknown device".
export function getUserAgentDisplayLabel(
    userAgent: string,
    translate: (_key: string, _options?: Record<string, string>) => string,
): string {
    const { browser, system } = getUserAgentLabel(userAgent);

    if (browser && system) {
        return translate("{{browser}} on {{system}}", { browser, system });
    }

    return browser || system || translate("Unknown device");
}
