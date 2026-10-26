"""Compile the actual patched AFC functions with a fault-injecting transport."""
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
def function(name):
    start = source.index(name + '(')
    start = source.rfind('\n', 0, start) + 1
    opened = source.index('{', start)
    depth = 1; end = opened + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

harness = r'''
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
typedef int afc_error_t;
typedef int service_error_t;
typedef struct { uint64_t magic, entire_length, this_length, packet_num, operation; char data[8]; } AFCPacket;
typedef struct { void *parent; AFCPacket *afc_packet; } *afc_client_t;
#define AFC_E_SUCCESS 0
#define AFC_E_INVALID_ARG 7
#define AFC_E_MUX_ERROR 30
#define SERVICE_E_SUCCESS 0
#define AFC_OP_FILE_WRITE 16
#define LIBIMOBILEDEVICE_API
#define AFC_PACKET_DATA_PTR client->afc_packet->data
#define debug_info(...)
#define debug_buffer(...)
#define AFCPacket_to_LE(p)
#define AFCPacket_from_LE(p)
static int fault, calls, received, locks;
static void afc_lock(afc_client_t c) { ++locks; }
static void afc_unlock(afc_client_t c) { --locks; }
static int service_send(void *p, const void *data, uint32_t len, uint32_t *sent) {
    ++calls; *sent = len;
    if ((fault == 1 && calls == 1) || (fault == 2 && calls == 2)) { *sent = len-1; return 0; }
    if ((fault == 3 && calls == 1) || (fault == 4 && calls == 2)) { *sent = 0; return -1; }
    return 0;
}
static int afc_receive_data(afc_client_t c, char **data, uint32_t *count) {
    ++received; *count = 0; return fault == 5 ? 12 : 0;
}
'''
harness += function('afc_dispatch_packet') + '\n' + function('afc_file_write')
harness += r'''
int main(void) {
    AFCPacket packet = {0};
    struct { void *parent; AFCPacket *afc_packet; } object = {&packet, &packet};
    afc_client_t client = (afc_client_t)&object;
    for (fault = 0; fault <= 5; ++fault) {
        calls = received = locks = 0;
        uint32_t written = 999;
        int result = afc_file_write(client, 1, "test", 4, &written);
        assert(locks == 0);
        if (fault == 0) { assert(result == 0 && written == 4 && received == 1); }
        else { assert(result != 0 && written == 0); }
        if (fault >= 1 && fault <= 4) assert(received == 0);
    }
    puts("PASS: actual AFC writes reject short sends, transport errors and failed acknowledgements");
}
'''
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder); (root/'check.c').write_text(harness)
    subprocess.run(['cc','-std=c99','-Wall','-Werror',str(root/'check.c'),'-o',str(root/'check')],check=True)
    subprocess.run([str(root/'check')],check=True)
