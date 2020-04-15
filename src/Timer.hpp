#ifndef TIMER_LIBRARY_H
#define TIMER_LIBRARY_H

#include <cstdlib>

typedef enum {
    TIMER_SINGLE_SHOT = 0,
    TIMER_PERIODIC
} t_timer;

typedef enum {
    SEC = 0,
    MILI_SEC
} t_unit;

typedef void (*time_handler)(size_t timer_id, void * user_data);

class Timer {
public:

    static int     initialize();
    static size_t  start_timer(unsigned int interval, t_unit unit, time_handler handler, t_timer type, void * user_data);
    static void    stop_timer(size_t timer_id);
    static void    finalize();
};

#endif