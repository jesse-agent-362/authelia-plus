// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

import { getUserAgentDisplayLabel, getUserAgentLabel } from "@views/Settings/Sessions/UserAgent";

it.each([
    ["Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0", "Firefox", "Linux"],
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Chrome",
        "Windows",
    ],
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
        "Edge",
        "Windows",
    ],
    [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/123.0.0.0",
        "Opera",
        "macOS",
    ],
    [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
        "Safari",
        "macOS",
    ],
    [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1",
        "Chrome",
        "iOS",
    ],
    [
        "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
        "Chrome",
        "Android",
    ],
    [
        "Mozilla/5.0 (X11; CrOS x86_64 16328.55.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Chrome",
        "ChromeOS",
    ],
])("labels %s", (userAgent, browser, system) => {
    expect(getUserAgentLabel(userAgent)).toEqual({ browser, system });
});

it("leaves out what it doesn't recognize", () => {
    expect(getUserAgentLabel("curl/8.16.0")).toEqual({ browser: undefined, system: undefined });
    expect(getUserAgentLabel("")).toEqual({ browser: undefined, system: undefined });
});

it("never puts text from the user agent in the label", () => {
    expect(getUserAgentLabel("<b>Firefox/1.0</b> (Linux)")).toEqual({ browser: "Firefox", system: "Linux" });
});

it("builds the display label from what it recognizes", () => {
    const translate = (key: string, options?: Record<string, string>) =>
        options ? key.replaceAll(/{{(\w+)}}/g, (_, name: string) => options[name]) : key;

    expect(getUserAgentDisplayLabel("Firefox/144.0 (X11; Linux x86_64)", translate)).toBe("Firefox on Linux");
    expect(getUserAgentDisplayLabel("Firefox/144.0", translate)).toBe("Firefox");
    expect(getUserAgentDisplayLabel("(Windows NT 10.0)", translate)).toBe("Windows");
    expect(getUserAgentDisplayLabel("curl/8.16.0", translate)).toBe("Unknown device");
});
