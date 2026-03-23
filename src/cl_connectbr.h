/*
Copyright (C) 2024 unezQuake team
cl_connectbr.h - Smart route selection for connectbr/connectnext commands
*/

#ifndef __CL_CONNECTBR_H__
#define __CL_CONNECTBR_H__

// CVars (extern declarations for use in other modules)
extern cvar_t cl_connectbr_test_packets;
extern cvar_t cl_connectbr_timeout_ms;
extern cvar_t cl_connectbr_packet_delay;
extern cvar_t cl_connectbr_ping_green;
extern cvar_t cl_connectbr_ping_orange;
extern cvar_t cl_connectbr_weight_ping;
extern cvar_t cl_connectbr_weight_loss;
extern cvar_t cl_connectbr_verbose;
extern cvar_t cl_connectbr_debug;

// Public functions
void CL_ConnectBR_Init(void);          // register cvars — call from CL_InitLocal
void CL_Connect_BestRoute_f(void);     // connectbr command
void CL_Connect_Next_f(void);          // connectnext command

#endif // __CL_CONNECTBR_H__
