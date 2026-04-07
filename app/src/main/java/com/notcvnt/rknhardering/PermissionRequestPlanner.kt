package com.notcvnt.rknhardering

internal object PermissionRequestPlanner {

    enum class Action {
        NONE,
        SHOW_RATIONALE,
        REQUEST,
        OPEN_SETTINGS,
    }

    data class PermissionState(
        val permission: String,
        val shouldShowRationale: Boolean,
        val wasRequestedBefore: Boolean,
    )

    fun decideAction(missingPermissions: List<PermissionState>): Action {
        if (missingPermissions.isEmpty()) {
            return Action.NONE
        }
        if (missingPermissions.any { it.shouldShowRationale }) {
            return Action.SHOW_RATIONALE
        }
        if (missingPermissions.any { !it.wasRequestedBefore }) {
            return Action.REQUEST
        }
        return Action.OPEN_SETTINGS
    }
}
