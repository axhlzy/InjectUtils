//
// Created by lzy on 2023/7/4.
//

#include <future>
#include "test_frida_pp.h"
#include "test_frida.h"

#include "gumpp.hpp"
#include "frida-gum.h"


void FRIDA::test_interceptor() {
//    test_frida_hook();

    gum_init_embedded();
    GumAddress soAddress = gum_module_find_base_address("libil2cpp.so");
    LOGD_("libil2cpp.so base :%p", (void*)soAddress);

    // 0x5c2d90       |  UIJoyStick        (0x7be1e54e10,0x7aec32f390)  ===>  public Void SwithcOff()
    void* address = reinterpret_cast<void *>(soAddress + 0x5c2d90);

    Gum::Interceptor_obtain()->attach(address,
                                      [](Gum::InvocationContext * context){
                                          LOGD_("on_enter %u %p", context->get_thread_id(), context->get_nth_argument<gpointer>(0));
                                          Gum::ReturnAddressArray ra;
                                          auto bk = Gum::Backtracer_make_accurate();
                                          bk->generate(context->get_cpu_context(), ra);
                                          for (int i=0 ; i<ra.len ; i++) {
                                              LOGD_("ra %d %p", i, ra.items[i]);
                                          }
                                      },
                                      [](Gum::InvocationContext * context){
                                          LOGD_("on_leave %p", context->get_return_value_ptr());
                                      });

}

void target_function() {
    LOGD_("called target_function");
}

// typedef void (* GumStalkerTransformerCallback) (GumStalkerIterator * iterator, GumStalkerOutput * output, gpointer user_data);
void transform_function(GumStalkerIterator * iterator, GumStalkerWriter * output, gpointer user_data) {
    gum_stalker_iterator_keep(iterator);
}

// typedef void (* GumEventSinkCallback) (const GumEvent * event, GumCpuContext * cpu_context, gpointer user_data);
void event_sink(const GumEvent* event, GumCpuContext const* cpu_context, gpointer user_data) {
    LOGD_("called event_sink %d", event->type);
}

void FRIDA::test_stalker() {

    static auto td = thread([](){
        gum_init_embedded();
        GumStalker *stalker = gum_stalker_new();

//        GumStalkerTransformer * transformer = gum_stalker_transformer_make_from_callback((GumStalkerTransformerCallback)transform_function, NULL, NULL);

        GumStalkerTransformer * transformer = gum_stalker_transformer_make_default();

        GumEventSink *sink = gum_event_sink_make_from_callback(GUM_COMPILE | GUM_CALL, (GumEventSinkCallback)event_sink, NULL, NULL);

        gum_stalker_follow_me(stalker, transformer, sink);

        target_function();

        gum_stalker_unfollow_me(stalker);

        g_object_unref(sink);
        g_object_unref(transformer);
        g_object_unref(stalker);

        gum_deinit_embedded();
    });

    td.detach();
}

