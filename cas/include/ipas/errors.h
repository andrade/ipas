#ifndef IPAS_ERROR_H
#define IPAS_ERROR_H

// TODO indexar com array para reverse search

typedef enum {
	IPAS_SUCCESS                =  0,
	IPAS_FAILURE                =  1,   // Oh, too bad!

	IPAS_INVALID                =  3,  // FIXME same as bad argument?
	IPAS_BAD_SID                =  4,
	IPAS_BAD_TAG                =  5,
	IPAS_BAD_SIG                =  6,
	IPAS_PEER_VETO              =  7,
	// IPAS_LARGER              =  8,
	// IPAS_SMALLER              =  8,
	IPAS_CAPACITY               =  8,
	// IPAS_COUNT              =  8,
	// IPAS_SIZE              =  8,
	IPAS_NO_KEY                 =  9,

	// IPAS_MA_SUCCESS             = 0,
	// IPAS_MA_FAILURE             = 1,
	// IPAS_MA_INVALID             = 2,
	// IPAS_MA_PEER_FAILURE        = 3,
} ipas_status;

#endif
