/*
Copyright (C) 2024 unezQuake team

cl_connectbr.h - Smart route selection for connectbr/connectnext commands
*/

#ifndef __CL_CONNECTBR_H__
#define __CL_CONNECTBR_H__

/*
 * connectbr <address>
 *   Tests up to 5 routes measuring ping, jitter and packet loss.
 *   Connects via the best route and shows full ranking in console.
 *   Requires: sb_findroutes 1 + server browser refreshed.
 */
void CL_Connect_BestRoute_f(void);

/*
 * connectnext
 *   Disconnects and reconnects via the next ranked route.
 *   Only works after a connectbr session.
 */
void CL_Connect_Next_f(void);

#endif /* __CL_CONNECTBR_H__ */
