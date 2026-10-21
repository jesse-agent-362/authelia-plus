// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { LogOut } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@components/UI/Button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@components/UI/Dialog";
import { PlusSession } from "@services/PlusSessions";
import { getUserAgentDisplayLabel } from "@views/Settings/Sessions/UserAgent";

interface Props {
    session?: PlusSession;
    onConfirm: () => void;
    onCancel: () => void;
}

const SessionRevokeDialog = function (props: Props) {
    const { t: translate } = useTranslation("settings");

    return (
        <Dialog
            open={props.session !== undefined}
            onOpenChange={(open) => {
                if (!open) props.onCancel();
            }}
        >
            <DialogContent showCloseButton={false}>
                <DialogHeader>
                    <DialogTitle>{translate("Revoke Session")}</DialogTitle>
                    <DialogDescription className="my-4">
                        {props.session?.current
                            ? translate(
                                  "This is the session you are using now, revoking it will sign you out of this device",
                              )
                            : translate("Are you sure you want to revoke this session, the device will be signed out")}
                    </DialogDescription>
                </DialogHeader>
                {props.session ? (
                    <div id={"dialog-revoke-session"} className="rounded border p-3 text-sm">
                        <p className="font-bold">{getUserAgentDisplayLabel(props.session.user_agent, translate)}</p>
                        <p className="text-muted-foreground">
                            {`${translate("Reported IP")}: ${props.session.reported_ip || translate("unknown")}`}
                        </p>
                    </div>
                ) : null}
                <DialogFooter>
                    <Button id={"dialog-cancel"} variant={"ghost"} color={"primary"} onClick={props.onCancel}>
                        {translate("Cancel")}
                    </Button>
                    <Button id={"dialog-revoke"} variant={"ghost"} color={"destructive"} onClick={props.onConfirm}>
                        <LogOut className="size-4" />
                        {props.session?.current ? translate("Revoke and Sign Out") : translate("Revoke")}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};

export default SessionRevokeDialog;
