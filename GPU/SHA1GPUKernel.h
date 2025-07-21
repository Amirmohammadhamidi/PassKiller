#pragma once
#ifdef __cplusplus
extern "C"
{
#endif

    void runSHA1BruteForceKernel(const char *targetHash, char *foundCandidate, bool *found, int numCandidates);

#ifdef __cplusplus
}
#endif