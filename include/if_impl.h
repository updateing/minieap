/*
 * MiniEAP Network Interface Implementation
 *
 * The implementations provide unified functions to access network.
 *
 * Every implementation must implement ALL of the following functions,
 * as well as a `new()` function which constructs its _if_impl structure (produce a new instance).
 * The `new()` function must be registered by IF_IMPL_INIT() macro.
 *
 * Each member function takes the pointer to the structure/instance as first parameter.
 *
 * Take a look at if_impl/sockraw/if_impl_sockraw.c for example.
 */
#ifndef _MINIEAP_IF_IMPL_H
#define _MINIEAP_IF_IMPL_H

#include <stdint.h>
#include "minieap_common.h"
#include "eth_frame.h"
#include "linkedlist.h"
#include "module_init.h"

#define FRAME_BUF_SIZE 1512

#ifdef __linux__
#define IF_IMPL_INIT(func) __define_in_section(func, ".ifimplinit")
#else
#define IF_IMPL_INIT(func) __define_in_section(func, "__DATA,__ifimplinit")
#endif

/*
 * Representing an interface driver plugin.
 * Main program should exit after any FAILURE returning value
 */
typedef struct _if_impl {
    /*
     * Set the interface which we should operate on.
     *
     * Note: we are NOT ready for capturing nor sending frames now.
     * Do not recv() or send() now, just store the name or get a handle.
     *
     * Return: if the initialization succeeds
     */
    RESULT (*set_ifname)(struct _if_impl* this, const char* ifname);

    /*
     * Copy specified interface name into given buffer.
     * Better check buffer length before writing to the buffer.
     *
     * Return: if the operation succeeds
     */
    RESULT (*get_ifname)(struct _if_impl* this, char* buf, int buflen);


    /*
     * Close the interface, free `this` and `this->priv` pointer, and
     * everything allocated dynamically.
     */
    void (*destroy)(struct _if_impl* this);

     /*
      * Set up packet filter and promiscuous mode (0 = disable, other=enable).
      *
      * Note: protocol number should be in host byte order.
      *
      * Return: if the setup was successful
      */
    RESULT (*setup_capture_params)(struct _if_impl* this, unsigned short eth_protocol, int promisc);

    /*
     * Prepare the interface, using all the parameters given before (name, proto, promisc etc).
     *
     * Can be used to actually initialize the interface.
     * If you have done this in `set_ifname` and `setup_capture_params`, you can leave this empty.
     */
    RESULT (*prepare_interface)(struct _if_impl* this);

    /*
     * Can be used to launch/terminate the actual capturing loop.
     * Note: `start_capture` should be blocking.
     *
     * Return: if capturing started/stopped successfully (no use in start_capture since it's blocking)
     */
    RESULT (*start_capture)(struct _if_impl* this);
    RESULT (*stop_capture)(struct _if_impl* this);

    /*
     * Send a frame on request.
     * Should send bytes starting at `frame->content` with `frame->content_len` bytes long.
     *
     * Return: if the frame was successfully sent
     */
    RESULT (*send_frame)(struct _if_impl* this, ETH_EAP_FRAME* frame);

    /*
     * Set the frame handler.
     * A frame handler is a function called on arrival of new frames.
     *
     * Note: the `frame` pointer does not guarantee to be valid after this
     * handler returns. If you want to use it afterwards, make a copy yourselves.
     */
    void (*set_frame_handler)(struct _if_impl* this, void (*handler)(ETH_EAP_FRAME* frame));

    /*
     * Implementation name, to be shown and selected by user
     */
    char* name;

    /*
     * Description, shown to user
     */
    char* description;

    /*
     * For plugin private use, a plugin can malloc and save data (such as interface handle) here.
     * Other parts of the program should not access this field.
     */
    void* priv;
} IF_IMPL;

/*
 * Initialize the network interface implementation list.
 *
 * Return: number of plugins loaded
 */
int init_if_impl_list();

/*
 * Prints names and description of all interface implementations
 * Called when `--help` presents
 */
void print_if_impl_list();

/*
 * Select one implementation with given name for usage.
 * If name is NULL, return the first implementation.
 *
 * Return: if the specific implementation was found.
 */
RESULT select_if_impl(const char* name);
/*
 * Get the instance of selected implementation
 */
IF_IMPL* get_if_impl();
/*
 * Free everything!
 */
void free_if_impl();
#endif
