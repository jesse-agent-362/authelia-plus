// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { ComponentType, SVGProps } from "react";

import { LaptopMinimal, LogOut } from "lucide-react";
import { useTranslation } from "react-i18next";

import AndroidLogo from "@assets/images/platforms/android.svg?react";
import AppleLogo from "@assets/images/platforms/apple.svg?react";
import ChromeLogo from "@assets/images/platforms/chrome.svg?react";
import LinuxLogo from "@assets/images/platforms/linux.svg?react";
import WindowsLogo from "@assets/images/platforms/windows.svg?react";
import { Button } from "@components/UI/Button";
import { Card } from "@components/UI/Card";
import { useRelativeTime } from "@hooks/RelativeTimeString";
import { PlusSession } from "@services/PlusSessions";
import { cn } from "@utils/Styles";
import { getUserAgentDisplayLabel, getUserAgentLabel } from "@views/Settings/Sessions/UserAgent";

// Keyed by the system names from getUserAgentLabel. A system without a logo gets a generic device.
const systemLogos: Record<string, ComponentType<SVGProps<SVGSVGElement>>> = {
    Android: AndroidLogo,
    ChromeOS: ChromeLogo,
    iOS: AppleLogo,
    Linux: LinuxLogo,
    macOS: AppleLogo,
    Windows: WindowsLogo,
};

interface Props {
    session: PlusSession;
    disabled?: boolean;
    handleRevoke: () => void;
}

// The user agent and the IP are what the client reported, so both are rendered as text and never as markup.
const SessionItem = function (props: Props) {
    const { t: translate } = useTranslation("settings");
    const timeSinceActive = useRelativeTime(props.session.last_active);
    const timeSinceCreated = useRelativeTime(props.session.created_at);

    const id = `session-${props.session.id}`;
    const { system } = getUserAgentLabel(props.session.user_agent);

    const Logo = (system && systemLogos[system]) || LaptopMinimal;

    const label = getUserAgentDisplayLabel(props.session.user_agent, translate);

    return (
        <Card id={id} className="p-0">
            <div className="p-6">
                <div className="flex items-center h-full w-full">
                    <div className="shrink-0 mr-2 md:mr-4 xl:mr-6">
                        <Logo
                            id={`${id}-logo`}
                            data-system={system ?? "unknown"}
                            className={cn("size-8", props.session.current && "text-primary")}
                            aria-hidden={true}
                        />
                    </div>
                    <div className="flex-1 min-w-0">
                        <div className="flex flex-col">
                            <div className="flex flex-row flex-wrap items-center gap-x-2">
                                <span id={`${id}-label`} className="font-bold inline">
                                    {label}
                                </span>
                                {props.session.current ? (
                                    <span
                                        id={`${id}-current`}
                                        className="rounded border border-primary px-2 text-xs text-primary whitespace-nowrap"
                                    >
                                        {translate("This session")}
                                    </span>
                                ) : null}
                            </div>
                            {props.session.user_agent === "" ? null : (
                                <span
                                    id={`${id}-user-agent`}
                                    className="hidden sm:block text-xs text-muted-foreground break-all"
                                >
                                    {props.session.user_agent}
                                </span>
                            )}
                            <span id={`${id}-reported-ip`} className="text-xs text-muted-foreground">
                                {`${translate("Reported IP")}: ${props.session.reported_ip || translate("unknown")}`}
                            </span>
                            <span className="hidden sm:block text-xs text-muted-foreground">
                                {`${translate("Last Active")} ${timeSinceActive}`}
                            </span>
                            <span className="hidden sm:block text-xs text-muted-foreground">
                                {`${translate("Signed In")} ${timeSinceCreated}`}
                            </span>
                        </div>
                    </div>
                    <div className="flex items-center justify-end ml-2">
                        <Button
                            id={`${id}-revoke`}
                            variant={"outline"}
                            color={"destructive"}
                            onClick={props.handleRevoke}
                            disabled={props.disabled}
                            aria-label={translate("Revoke")}
                        >
                            <LogOut />
                            <span className="hidden sm:inline">{translate("Revoke")}</span>
                        </Button>
                    </div>
                </div>
            </div>
        </Card>
    );
};

export default SessionItem;
