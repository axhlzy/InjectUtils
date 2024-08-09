#pragma once

#include "main.h"

class Timer;
#define TIME_FUNCTION Timer timer(__FUNCTION__)
class ScopedLock;
class Trace;
#define TRACE_FUNCTION Trace trace(__PRETTY_FUNCTION__);
class Semaphore;
class SemaphoreGuard;