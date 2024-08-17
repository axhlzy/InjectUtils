
#ifndef REPLXX_EXPORT_H
#define REPLXX_EXPORT_H

#ifdef REPLXX_STATIC_DEFINE
#  define REPLXX_EXPORT
#  define REPLXX_NO_EXPORT
#else
#  ifndef REPLXX_EXPORT
#    ifdef replxx_EXPORTS
        /* We are building this library */
#      define REPLXX_EXPORT 
#    else
        /* We are using this library */
#      define REPLXX_EXPORT 
#    endif
#  endif

#  ifndef REPLXX_NO_EXPORT
#    define REPLXX_NO_EXPORT 
#  endif
#endif

#ifndef REPLXX_DEPRECATED
#  define REPLXX_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef REPLXX_DEPRECATED_EXPORT
#  define REPLXX_DEPRECATED_EXPORT REPLXX_EXPORT REPLXX_DEPRECATED
#endif

#ifndef REPLXX_DEPRECATED_NO_EXPORT
#  define REPLXX_DEPRECATED_NO_EXPORT REPLXX_NO_EXPORT REPLXX_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef REPLXX_NO_DEPRECATED
#    define REPLXX_NO_DEPRECATED
#  endif
#endif

#endif /* REPLXX_EXPORT_H */
