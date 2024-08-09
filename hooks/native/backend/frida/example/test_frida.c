#include "test_frida.h"

typedef struct _HookerListener HookerListener;

struct _HookerListener
{
    GObject parent;

    guint num_calls;
};

typedef enum  HookerHookId
{
    HOOKER_HOOK_OPEN,
    HOOKER_HOOK_CLOSE
} HookerHookId;

static void hooker_listener_iface_init( gpointer g_iface, gpointer iface_data );

#define HOOKER_TYPE_LISTENER ( Hooker_listener_get_type() )

G_DECLARE_FINAL_TYPE( HookerListener, Hooker_listener, HOOKER, LISTENER, GObject)

G_DEFINE_TYPE_EXTENDED( HookerListener, Hooker_listener, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE( GUM_TYPE_INVOCATION_LISTENER, hooker_listener_iface_init))

// typedef void (* GumEventSinkCallback) (const GumEvent * event, GumCpuContext * cpu_context, gpointer user_data);
void event_sink(const GumEvent* event, GumCpuContext const* cpu_context, gpointer user_data) {
    LOGD__("called event_sink %d", event->type);
}

void test_frida_hook(){

    GumInterceptor		* interceptor;
    GumInvocationListener	* listener;
    gum_init_embedded();

    interceptor	= gum_interceptor_obtain();

    listener = g_object_new(HOOKER_TYPE_LISTENER, NULL);

    gum_interceptor_begin_transaction( interceptor );
    gum_interceptor_attach( interceptor,
                            GSIZE_TO_POINTER( gum_module_find_export_by_name( NULL, "open" ) ),
                            listener,
                            GSIZE_TO_POINTER( HOOKER_HOOK_OPEN ) );
    gum_interceptor_attach( interceptor,
                            GSIZE_TO_POINTER( gum_module_find_export_by_name( NULL, "close" ) ),
                            listener,
                            GSIZE_TO_POINTER( HOOKER_HOOK_CLOSE ) );
    gum_interceptor_end_transaction( interceptor );

    close( open( "/etc/hosts", O_RDONLY ) );
    close( open( "/etc/fstab", O_RDONLY ) );

    close( open( "/etc/hosts", O_RDONLY ) );
    close( open( "/etc/fstab", O_RDONLY ) );

    LOGD__( "[*] listener got %u calls\n", HOOKER_LISTENER( listener )->num_calls );

    gum_interceptor_detach( interceptor, listener );

    close( open( "/etc/hosts", O_RDONLY ) );
    close( open( "/etc/fstab", O_RDONLY ) );

    LOGD__( "[*] listener still has %u calls\n", HOOKER_LISTENER( listener )->num_calls );

    g_object_unref( listener );
    g_object_unref( interceptor );

    gum_deinit_embedded();
}

static void
hooker_listener_on_enter(GumInvocationListener * listener, GumInvocationContext * ic ){
//    HookerListener * self	= HOOKER_LISTENER( listener );
//    HookerHookId	hook_id = GUM_IC_GET_FUNC_DATA( ic, HookerHookId );
//
//    gum_cpu_context_get_nth_argument( ic->cpu_context, 1 );
//
//    switch ( hook_id )
//    {
//        case HOOKER_HOOK_OPEN:
//            LOGD__( "[*] open(\"%s\")\n", (const gchar *) gum_invocation_context_get_nth_argument( ic, 0 ) );
//            break;
//        case HOOKER_HOOK_CLOSE:
//            LOGD__( "[*] close(%d)\n", GPOINTER_TO_INT( gum_invocation_context_get_nth_argument( ic, 0 ) ) );
//            break;
//    }
//
//    self->num_calls++;
}


static void
hooker_listener_on_leave(GumInvocationListener * listener, GumInvocationContext * ic ){
//    HookerListener * self	= HOOKER_LISTENER( listener );
//    gum_cpu_context_get_nth_argument( ic->cpu_context, 1 );
//    HookerHookId	hook_id = GUM_IC_GET_FUNC_DATA( ic, HookerHookId );
//
//    switch ( hook_id )
//    {
//        case HOOKER_HOOK_OPEN:
//            LOGD__( "[*] HOOKER_HOOK_OPEN %s called from %p\n", __FUNCTION__, (void*)ic->cpu_context->lr );
//            break;
//        case HOOKER_HOOK_CLOSE:
//            LOGD__( "[*] HOOKER_HOOK_CLOSE %s called from %p\n", __FUNCTION__, (void*)ic->cpu_context->lr );
//            break;
//    }
//
//    LOGD__( "[*] %s called from %p", __FUNCTION__, (void*)ic->cpu_context->lr );
}

static void
Hooker_listener_class_init( HookerListenerClass * klass ) {
    (void) HOOKER_IS_LISTENER;
    (void) glib_autoptr_cleanup_HookerListener;
}

static void
Hooker_listener_init( HookerListener * self ) {

}

static void
hooker_listener_iface_init( gpointer g_iface, gpointer iface_data ){
    GumInvocationListenerInterface * iface = g_iface;
    iface->on_enter = hooker_listener_on_enter;
    iface->on_leave = hooker_listener_on_leave;
}