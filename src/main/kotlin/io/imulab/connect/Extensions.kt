package io.imulab.connect

inline fun <reified T> Collection<T>.containsExactly(element: T): Boolean =
    this.size == 1 && this.contains(element)