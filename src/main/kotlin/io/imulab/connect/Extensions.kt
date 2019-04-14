package io.imulab.connect

inline fun <reified T> Collection<T>.containsExactly(vararg elements: T): Boolean =
    this.size == elements.size && this.containsAll(elements.toSet())