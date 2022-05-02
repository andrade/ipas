#pragma once




// WIP
// Faz MA entre dois enclaves (que se assumem iguais: MRENCLAVE; hard-req?).
// Como identificar os 2 enclaves, initiator/responder? É preciso?
// Porque razão devolve duas chaves? Porque original RA faz o mesmo.
//
// Devolve 0 sucesso, outro número caso haja erro durante protocolo.
// Preciso intervalos de erros, e enum, para erros de protocolo, e erros devolvidos pela MA como enclaves diferentes ou que estejam desactualizados, etc.
int ipas_ma(uint8_t mk[static 16], uint8_t sk[static 16]);

/**
** Gets shared keys that are the result of MA.
**
** The id is id=1 for MK and id=2 for SK.
**
** Returns the key on success, NULL otherwise.
**/
void *ipas_ma_get_key(uint32_t sid, int key_id);




// #include <stdarg.h>
// #include <stdint.h>

// int ipas_attest_initiator(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t));
//
// int ipas_attest_responder(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t));
