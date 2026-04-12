package com.notcvnt.rknhardering

import android.content.Context
import android.util.AttributeSet
import android.view.MotionEvent
import android.widget.ScrollView

class TouchAwareScrollView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : ScrollView(context, attrs, defStyleAttr) {

    var onUserTouchChanged: ((Boolean) -> Unit)? = null

    private var isUserTouchActive = false

    override fun onInterceptTouchEvent(ev: MotionEvent): Boolean {
        updateTouchState(ev)
        return super.onInterceptTouchEvent(ev)
    }

    override fun onTouchEvent(ev: MotionEvent): Boolean {
        updateTouchState(ev)
        if (ev.actionMasked == MotionEvent.ACTION_UP) {
            performClick()
        }
        return super.onTouchEvent(ev)
    }

    override fun performClick(): Boolean {
        return super.performClick()
    }

    private fun updateTouchState(event: MotionEvent) {
        val nextState = when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> true
            MotionEvent.ACTION_UP,
            MotionEvent.ACTION_CANCEL,
            -> false
            else -> isUserTouchActive
        }
        if (nextState == isUserTouchActive) return
        isUserTouchActive = nextState
        onUserTouchChanged?.invoke(nextState)
    }
}
