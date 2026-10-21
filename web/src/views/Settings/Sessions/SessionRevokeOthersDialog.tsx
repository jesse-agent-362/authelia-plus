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

interface Props {
    // The number of other sessions in the list; the dialog is open while it's set.
    count?: number;
    onConfirm: () => void;
    onCancel: () => void;
}

const SessionRevokeOthersDialog = function (props: Props) {
    const { t: translate } = useTranslation("settings");

    return (
        <Dialog
            open={props.count !== undefined}
            onOpenChange={(open) => {
                if (!open) props.onCancel();
            }}
        >
            <DialogContent showCloseButton={false}>
                <DialogHeader>
                    <DialogTitle>{translate("Sign out all other sessions")}</DialogTitle>
                    <DialogDescription className="my-4">
                        {translate(
                            "Are you sure you want to sign out all other sessions, every other device will be signed out and this one stays signed in",
                        )}
                    </DialogDescription>
                </DialogHeader>
                <div id={"dialog-revoke-others-count"} className="rounded border p-3 text-sm font-bold">
                    {translate("Other sessions: {{count}}", { count: props.count ?? 0 })}
                </div>
                <DialogFooter>
                    <Button id={"dialog-cancel"} variant={"ghost"} color={"primary"} onClick={props.onCancel}>
                        {translate("Cancel")}
                    </Button>
                    <Button
                        id={"dialog-revoke-others"}
                        variant={"ghost"}
                        color={"destructive"}
                        onClick={props.onConfirm}
                    >
                        <LogOut className="size-4" />
                        {translate("Sign Out Others")}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};

export default SessionRevokeOthersDialog;
