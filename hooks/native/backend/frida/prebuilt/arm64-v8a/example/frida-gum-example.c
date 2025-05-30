#include "frida-gum.h"

#include <fcntl.h>
#include <unistd.h>


#define G_IMPLEMENT_INTERFACE(TYPE_IFACE, iface_init)       { \
  const GInterfaceInfo g_implement_interface_info = { \
    (GInterfaceInitFunc)(void (*)(void)) iface_init, NULL, NULL \
  }; \
  g_type_add_interface_static (g_define_type_id, TYPE_IFACE, &g_implement_interface_info); \
}


typedef struct _ExampleListener ExampleListener;
typedef enum ExampleHookId	ExampleHookId;

struct _ExampleListener
{
    GObject parent;

    guint num_calls;
};

enum ExampleHookId
{
    EXAMPLE_HOOK_OPEN,
    EXAMPLE_HOOK_CLOSE
};

static void test_listener_iface_init( gpointer g_iface, gpointer iface_data );


#define EXAMPLE_TYPE_LISTENER (example_listener_get_type() )


G_DECLARE_FINAL_TYPE( ExampleListener, example_listener, EXAMPLE, LISTENER, GObject )

G_DEFINE_TYPE_EXTENDED( ExampleListener, example_listener, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE( GUM_TYPE_INVOCATION_LISTENER, test_listener_iface_init ) )

int gum_main( int argc, char * argv[])
{
    GumInterceptor		* interceptor;
    GumInvocationListener	* listener;

    gum_init_embedded();

    interceptor	= gum_interceptor_obtain();
    listener	= g_object_new( EXAMPLE_TYPE_LISTENER, NULL );

    gum_interceptor_begin_transaction( interceptor );
    gum_interceptor_attach( interceptor,
                            GSIZE_TO_POINTER( gum_module_find_export_by_name( NULL, "open" ) ),
                            listener,
                            GSIZE_TO_POINTER( EXAMPLE_HOOK_OPEN ) );
    gum_interceptor_attach( interceptor,
                            GSIZE_TO_POINTER( gum_module_find_export_by_name( NULL, "close" ) ),
                            listener,
                            GSIZE_TO_POINTER( EXAMPLE_HOOK_CLOSE ) );
    gum_interceptor_end_transaction( interceptor );

    close( open( "/etc/hosts", O_RDONLY ) );
    close( open( "/etc/fstab", O_RDONLY ) );

    g_print( "[*] listener got %u calls\n", EXAMPLE_LISTENER( listener )->num_calls );

    gum_interceptor_detach( interceptor, listener );

    close( open( "/etc/hosts", O_RDONLY ) );
    close( open( "/etc/fstab", O_RDONLY ) );

    g_print( "[*] listener still has %u calls\n", EXAMPLE_LISTENER( listener )->num_calls );

    g_object_unref( listener );
    g_object_unref( interceptor );

    gum_deinit_embedded();

    return(0);
}


static void
example_listener_on_enter( GumInvocationListener * listener,
                           GumInvocationContext * ic )
{
    ExampleListener * self	= EXAMPLE_LISTENER( listener );
    ExampleHookId	hook_id = GUM_IC_GET_FUNC_DATA( ic, ExampleHookId );

    gum_cpu_context_get_nth_argument( ic->cpu_context, 1 );

    switch ( hook_id )
    {
        case EXAMPLE_HOOK_OPEN:
            g_print( "[*] open(\"%s\")\n", (const gchar *) gum_invocation_context_get_nth_argument( ic, 0 ) );
            break;
        case EXAMPLE_HOOK_CLOSE:
            g_print( "[*] close(%d)\n", GPOINTER_TO_INT( gum_invocation_context_get_nth_argument( ic, 0 ) ) );
            break;
    }

    self->num_calls++;
}


static void
example_listener_on_leave( GumInvocationListener * listener,
                           GumInvocationContext * ic )
{
}


static void
example_listener_class_init( ExampleListenerClass * klass )
{
    (void) EXAMPLE_IS_LISTENER;
    (void) glib_autoptr_cleanup_ExampleListener;
}


static void
test_listener_iface_init( gpointer g_iface,
                             gpointer iface_data )
{
    GumInvocationListenerInterface * iface = g_iface;

    iface->on_enter = example_listener_on_enter;
    iface->on_leave = example_listener_on_leave;
}


static void
example_listener_init( ExampleListener * self )
{
}


