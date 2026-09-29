/* Local, bounded regression: a stalled writer must relinquish its caller buffer.
 * The negative control exits before calling any function with unsafe state.
 * No network access or external target is involved. */
#include "gzguts.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    int channel[2];
    assert(pipe(channel) == 0);
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(channel[i], F_GETFL);
        assert(flags >= 0);
        assert(fcntl(channel[i], F_SETFL, flags | O_NONBLOCK) == 0);
    }
    const unsigned length = 1024 * 1024;
    unsigned char *payload = calloc(length, 1);
    assert(payload != NULL);
    gzFile writer = gzdopen(channel[1], "wb0");
    assert(writer != NULL);
    assert(gzbuffer(writer, 8192) == 0);
    int accepted = gzwrite(writer, payload, length);
    assert(accepted >= 0 && (unsigned)accepted < length);
    gz_statep state = (gz_statep)writer;
    if (state->strm.avail_in != 0 || state->strm.next_in != state->in)
        return 86; /* vulnerable original: borrowed buffer retained after return */
    unsigned char discarded[4096];
    while (read(channel[0], discarded, sizeof discarded) > 0) {}
    gzclearerr(writer);
    (void)gzprintf(writer, "%s", "bounded regression marker");
    (void)gzclose(writer);
    close(channel[0]);
    free(payload);
    return 0;
}
